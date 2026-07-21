"""Sanitized, content-addressed reviewer feedback for the next planner cycle.

This module is deliberately a lossy boundary.  Provider prose, required-change
text, provider response bodies, program material, and crash/seed data are never
written.  Only strict enums, evidence identifiers, and hashes copied from
already-validated local objects cross from the reviewer to future telemetry.
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, ValidationError, model_validator

from .models import (
    Digest,
    EvidenceRef,
    FindingCategory,
    FindingSeverity,
    Identifier,
    OutcomeKind,
    PlannerProposal,
    PriorProposalOutcome,
    ResidualRisk,
    ReviewerVerdict,
    StrictModel,
    TargetHashes,
    TelemetryPacket,
    Timestamp,
    VerdictKind,
)
from .quarantine import QuarantineError, QuarantineStore, canonical_json
from .validator import ValidationReport


_STRUCTURAL_REVIEW_CHECKS = frozenset(
    {"review.binding", "review.evidence", "review.finding-targets"}
)
_NON_STRUCTURAL_REVIEW_CHECKS = frozenset({"review.acceptance"})
_MAX_FEEDBACK_BYTES = 64 * 1024


class FeedbackError(RuntimeError):
    """A persisted feedback object is unsafe, corrupt, or unverifiable."""


class SanitizedFinding(StrictModel):
    """The non-prose, non-executable projection of one reviewer finding."""

    category: FindingCategory
    severity: FindingSeverity
    evidence_refs: Annotated[list[EvidenceRef], Field(max_length=12)]

    @model_validator(mode="after")
    def require_canonical_refs(self) -> "SanitizedFinding":
        if self.evidence_refs != sorted(set(self.evidence_refs)):
            raise ValueError("finding evidence_refs must be unique and sorted")
        return self


def _finding_key(finding: SanitizedFinding) -> tuple[str, str, tuple[str, ...]]:
    return (
        finding.category.value,
        finding.severity.value,
        tuple(finding.evidence_refs),
    )


def _record_summary(
    verdict: VerdictKind,
    residual_risk: ResidualRisk,
    findings: list[SanitizedFinding],
    evidence_refs: list[str],
) -> str:
    """Return deterministic local text; no provider-authored text is accepted."""

    pairs = sorted({f"{item.category.value}/{item.severity.value}" for item in findings})
    finding_text = ",".join(pairs) if pairs else "none"
    return (
        f"Independent review verdict={verdict.value}; "
        f"residual_risk={residual_risk.value}; finding_kinds={finding_text}; "
        f"evidence_ref_count={len(evidence_refs)}."
    )


class ReviewFeedbackRecord(StrictModel):
    """Immutable lossy projection of a structurally verified reviewer verdict."""

    schema_version: Literal["review-feedback.v1"]
    trust: Literal["untrusted_model_review_sanitized"]
    created_at: Timestamp
    proposal_id: Identifier
    packet_id: Identifier
    proposal_hash: Digest
    packet_hash: Digest
    reviewer_verdict_hash: Digest
    target_hashes: TargetHashes
    verdict: VerdictKind
    residual_risk: ResidualRisk
    safe_for_quarantine: bool
    findings: Annotated[list[SanitizedFinding], Field(max_length=32)]
    checked_evidence_refs: Annotated[list[EvidenceRef], Field(max_length=24)]
    validation_basis: Literal[
        "review.binding+review.evidence+review.finding-targets"
    ]
    local_summary: Annotated[str, Field(min_length=1, max_length=1600)]

    @model_validator(mode="after")
    def require_canonical_projection(self) -> "ReviewFeedbackRecord":
        finding_keys = [_finding_key(item) for item in self.findings]
        if finding_keys != sorted(set(finding_keys)):
            raise ValueError("sanitized findings must be unique and in canonical order")
        if self.checked_evidence_refs != sorted(set(self.checked_evidence_refs)):
            raise ValueError("checked_evidence_refs must be unique and sorted")
        finding_refs = {
            ref for finding in self.findings for ref in finding.evidence_refs
        }
        if not finding_refs.issubset(set(self.checked_evidence_refs)):
            raise ValueError("finding evidence was not included in checked evidence")
        severe = {FindingSeverity.CRITICAL, FindingSeverity.HIGH}
        if self.verdict is VerdictKind.ACCEPT:
            if not self.safe_for_quarantine:
                raise ValueError("accepted feedback must be safe for quarantine")
            if any(item.severity in severe for item in self.findings):
                raise ValueError("accepted feedback cannot retain severe findings")
        elif self.safe_for_quarantine:
            raise ValueError("non-accepted feedback cannot be safe for quarantine")
        expected = _record_summary(
            self.verdict,
            self.residual_risk,
            self.findings,
            self.checked_evidence_refs,
        )
        if self.local_summary != expected:
            raise ValueError("local_summary was not generated by the local projector")
        return self


def _model_digest(model: StrictModel) -> str:
    return "sha256:" + hashlib.sha256(
        canonical_json(model.model_dump(mode="json"))
    ).hexdigest()


def build_review_feedback(
    telemetry: TelemetryPacket,
    proposal: PlannerProposal,
    verdict: ReviewerVerdict,
    report: ValidationReport,
    *,
    now: datetime | None = None,
) -> ReviewFeedbackRecord:
    """Project a verdict only after its binding/evidence checks passed locally.

    ``review.acceptance`` is intentionally not required: reject and escalate
    verdicts are valuable bounded feedback, but still fail the separate final
    acceptance gate in :mod:`iou_ai.pipeline`.
    """

    passed = set(report.passed_check_ids)
    failed = set(report.failed_check_ids)
    if not _STRUCTURAL_REVIEW_CHECKS.issubset(passed):
        raise FeedbackError("review feedback did not pass all structural checks")
    if failed - _NON_STRUCTURAL_REVIEW_CHECKS:
        raise FeedbackError("review feedback has a non-acceptance validation failure")
    if verdict.packet_id != telemetry.packet_id or verdict.proposal_id != proposal.proposal_id:
        raise FeedbackError("review feedback binding is inconsistent")
    if (
        proposal.packet_id != telemetry.packet_id
        or proposal.target_hashes != telemetry.target_hashes
    ):
        raise FeedbackError("proposal feedback binding is inconsistent")

    projected_findings = [
        SanitizedFinding(
            category=item.category,
            severity=item.severity,
            evidence_refs=sorted(set(item.evidence_refs)),
        )
        for item in verdict.findings
    ]
    findings_by_key = {_finding_key(item): item for item in projected_findings}
    findings = [findings_by_key[key] for key in sorted(findings_by_key)]
    evidence_refs = sorted(set(verdict.checked_evidence_refs))
    timestamp = now or datetime.now(timezone.utc)
    if timestamp.tzinfo is None or timestamp.utcoffset() is None:
        raise FeedbackError("feedback timestamp must include a timezone")
    timestamp = timestamp.astimezone(timezone.utc)
    local_summary = _record_summary(
        verdict.verdict,
        verdict.residual_risk,
        findings,
        evidence_refs,
    )
    return ReviewFeedbackRecord(
        schema_version="review-feedback.v1",
        trust="untrusted_model_review_sanitized",
        created_at=timestamp.isoformat().replace("+00:00", "Z"),
        proposal_id=proposal.proposal_id,
        packet_id=telemetry.packet_id,
        proposal_hash=_model_digest(proposal),
        packet_hash=telemetry.packet_hash,
        reviewer_verdict_hash=_model_digest(verdict),
        target_hashes=telemetry.target_hashes,
        verdict=verdict.verdict,
        residual_risk=verdict.residual_risk,
        safe_for_quarantine=verdict.safe_for_quarantine,
        findings=findings,
        checked_evidence_refs=evidence_refs,
        validation_basis="review.binding+review.evidence+review.finding-targets",
        local_summary=local_summary,
    )


class FeedbackStore:
    """Create-only content-addressed store with verified, strict reads."""

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)
        self._objects = QuarantineStore(self.root)

    def put(self, record: ReviewFeedbackRecord) -> tuple[str, Path]:
        return self._objects.put(record.model_dump(mode="json"))

    def iter_verified(self, *, max_items: int = 1024):
        try:
            for digest, value in self._objects.iter_verified(
                max_items=max_items,
                max_bytes=_MAX_FEEDBACK_BYTES,
            ):
                try:
                    record = ReviewFeedbackRecord.model_validate_json(
                        canonical_json(value)
                    )
                except ValidationError:
                    raise FeedbackError(
                        "feedback object failed strict validation"
                    ) from None
                yield digest, record
        except QuarantineError:
            raise FeedbackError("feedback object failed content verification") from None


def _bounded_tokens(tokens: list[str], *, character_limit: int) -> str:
    """Render whole enum/identifier tokens without ever slicing their content."""

    if not tokens:
        return "none"
    selected: list[str] = []
    for index, token in enumerate(tokens):
        omitted = len(tokens) - index - 1
        candidate_items = [*selected, token]
        candidate = ",".join(candidate_items)
        if omitted:
            candidate += f",+{omitted}_more"
        if len(candidate) > character_limit:
            break
        selected.append(token)
    omitted = len(tokens) - len(selected)
    if not selected:
        return f"+{omitted}_more"
    rendered = ",".join(selected)
    if omitted:
        rendered += f",+{omitted}_more"
    return rendered


def to_prior_proposal_outcome(record: ReviewFeedbackRecord) -> PriorProposalOutcome:
    """Create the sole bounded model-facing projection of a feedback record."""

    finding_tokens = sorted(
        {f"{item.category.value}/{item.severity.value}" for item in record.findings}
    )
    refs = sorted(
        set(record.checked_evidence_refs).union(
            ref for finding in record.findings for ref in finding.evidence_refs
        )
    )
    summary = (
        f"Claude review verdict={record.verdict.value}; "
        f"risk={record.residual_risk.value}; "
        f"findings={_bounded_tokens(finding_tokens, character_limit=72)}; "
        f"refs={_bounded_tokens(refs, character_limit=72)}."
    )
    # The fixed field allocations above should remain well under ShortText's
    # limit; retain an explicit invariant at this security boundary.
    if len(summary) > 240:
        raise FeedbackError("local feedback summary exceeded its fixed bound")
    outcome = (
        OutcomeKind.NOT_RUN
        if record.verdict is VerdictKind.ACCEPT
        else OutcomeKind.REJECTED
    )
    return PriorProposalOutcome(
        proposal_id=record.proposal_id,
        outcome=outcome,
        executions=0,
        paths_gained=0,
        novel_outcomes=0,
        summary=summary,
    )


def load_prior_proposal_outcomes(
    root: str | Path,
    *,
    target_hashes: TargetHashes,
    limit: int = 12,
) -> list[PriorProposalOutcome]:
    """Load newest verified, target-bound feedback records for planner telemetry."""

    if not 0 <= limit <= 12:
        raise FeedbackError("feedback outcome limit must be between 0 and 12")
    if limit == 0:
        return []
    records = [
        (digest, record)
        for digest, record in FeedbackStore(root).iter_verified()
        if record.target_hashes == target_hashes
    ]
    records.sort(
        key=lambda item: (
            datetime.fromisoformat(item[1].created_at.replace("Z", "+00:00")),
            item[0],
        ),
        reverse=True,
    )

    # Repeated manual one-shot runs must not crowd the next packet with the same
    # logical review.  Keep only the newest record per hash-bound proposal.
    selected: list[ReviewFeedbackRecord] = []
    seen: set[tuple[str, str, str]] = set()
    for _, record in records:
        key = (record.proposal_id, record.proposal_hash, record.packet_hash)
        if key in seen:
            continue
        seen.add(key)
        selected.append(record)
        if len(selected) == limit:
            break
    return [to_prior_proposal_outcome(record) for record in selected]


__all__ = [
    "FeedbackError",
    "FeedbackStore",
    "ReviewFeedbackRecord",
    "SanitizedFinding",
    "build_review_feedback",
    "load_prior_proposal_outcomes",
    "to_prior_proposal_outcome",
]
