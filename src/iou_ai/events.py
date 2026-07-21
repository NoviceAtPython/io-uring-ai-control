"""Redacted, inert notification events for the AFL/Nyx shadow pipeline.

This module deliberately stops at a content-addressed outbox.  It has no SMS,
network, compiler, corpus, or fleet-write capability.  Every rendered message
comes from a fixed template and every event contains identifiers, hashes, and
counters only--never model prose, programs, crash traces, paths, or PII.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import base64
import stat
from collections.abc import Callable, Iterable
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Annotated, Literal, TypeAlias

from pydantic import Field, TypeAdapter, field_validator, model_validator

from .budget import BudgetStatus
from .execution import ExecutionCandidate, PromotionScope
from .models import (
    Digest,
    Identifier,
    QuarantineEnvelope,
    StrictModel,
    TargetHashes,
    Timestamp,
)
from .quarantine import canonical_json


class EventProjectionError(RuntimeError):
    """Raised when an authority input or create-only outbox fails closed."""


Nonce256 = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
HumanCode = Annotated[str, Field(pattern=r"^[A-Z2-7]{8}$")]
Month = Annotated[str, Field(pattern=r"^\d{4}-(?:0[1-9]|1[0-2])$")]
NonNegativeInt = Annotated[int, Field(ge=0)]
PositiveInt = Annotated[int, Field(ge=1)]


class ApprovalChallenge(StrictModel):
    """One-time material bound only to offline-validation authority."""

    nonce: Nonce256
    human_code: HumanCode
    expires_at: Timestamp
    binding_digest: Digest
    allowed_actions: tuple[
        Literal["approve_for_offline_validation"], Literal["deny"]
    ] = ("approve_for_offline_validation", "deny")

    @field_validator("allowed_actions")
    @classmethod
    def actions_are_fixed(
        cls, value: tuple[str, str]
    ) -> tuple[str, str]:
        if value != ("approve_for_offline_validation", "deny"):
            raise ValueError("approval actions are fixed and ordered")
        return value


class ExecutionApprovalChallenge(StrictModel):
    """One-time material bound only to one exact live-execution candidate."""

    nonce: Nonce256
    human_code: HumanCode
    expires_at: Timestamp
    binding_digest: Digest
    allowed_actions: tuple[
        Literal["approve_for_live_execution"], Literal["deny"]
    ] = ("approve_for_live_execution", "deny")

    @field_validator("allowed_actions")
    @classmethod
    def actions_are_fixed(
        cls, value: tuple[str, str]
    ) -> tuple[str, str]:
        if value != ("approve_for_live_execution", "deny"):
            raise ValueError("execution approval actions are fixed and ordered")
        return value


class _EventBase(StrictModel):
    schema_version: Literal["redacted-event.v1"] = "redacted-event.v1"
    created_at: Timestamp


class ProposalQuarantinedEvent(_EventBase):
    event_kind: Literal["proposal_quarantined"] = "proposal_quarantined"
    severity: Literal["action_required"] = "action_required"
    envelope_digest: Digest
    proposal_hash: Digest
    target_hashes: TargetHashes
    approval: ApprovalChallenge

    @model_validator(mode="after")
    def challenge_binds_event(self) -> "ProposalQuarantinedEvent":
        expected = approval_binding_digest(
            envelope_digest=self.envelope_digest,
            target_hashes=self.target_hashes,
            nonce=self.approval.nonce,
            human_code=self.approval.human_code,
            expires_at=self.approval.expires_at,
        )
        if self.approval.binding_digest != expected:
            raise ValueError("approval challenge is not bound to this envelope and target")
        return self


class ExecutionReadyEvent(StrictModel):
    """Redacted final approval prompt for one canaried immutable artifact."""

    schema_version: Literal["redacted-event.v2"] = "redacted-event.v2"
    event_kind: Literal["execution_ready"] = "execution_ready"
    created_at: Timestamp
    severity: Literal["action_required"] = "action_required"
    candidate_digest: Digest
    envelope_digest: Digest
    artifact_manifest_digest: Digest
    artifact_digest: Digest
    artifact_size_bytes: Annotated[int, Field(ge=1, le=2048)]
    validation_report_digest: Digest
    canary_report_digest: Digest
    target_hashes: TargetHashes
    promotion_scope: PromotionScope
    approval: ExecutionApprovalChallenge

    @model_validator(mode="after")
    def challenge_binds_execution(self) -> "ExecutionReadyEvent":
        expected = execution_approval_binding_digest(
            candidate_digest=self.candidate_digest,
            envelope_digest=self.envelope_digest,
            artifact_manifest_digest=self.artifact_manifest_digest,
            artifact_digest=self.artifact_digest,
            artifact_size_bytes=self.artifact_size_bytes,
            validation_report_digest=self.validation_report_digest,
            canary_report_digest=self.canary_report_digest,
            target_hashes=self.target_hashes,
            promotion_scope=self.promotion_scope,
            nonce=self.approval.nonce,
            human_code=self.approval.human_code,
            expires_at=self.approval.expires_at,
        )
        if self.approval.binding_digest != expected:
            raise ValueError("execution challenge is not bound to this exact candidate")
        return self


class BudgetThresholdEvent(_EventBase):
    event_kind: Literal["budget_threshold"] = "budget_threshold"
    severity: Literal["warning", "critical"]
    month: Month
    threshold_microdollars: NonNegativeInt
    effective_spend_microdollars: NonNegativeInt
    hard_limit_microdollars: PositiveInt
    remaining_microdollars: NonNegativeInt

    @model_validator(mode="after")
    def amounts_are_consistent(self) -> "BudgetThresholdEvent":
        if self.threshold_microdollars >= self.hard_limit_microdollars:
            raise ValueError("warning threshold must be below the hard limit")
        if self.effective_spend_microdollars < self.threshold_microdollars:
            raise ValueError("budget threshold has not been crossed")
        expected_remaining = max(
            0, self.hard_limit_microdollars - self.effective_spend_microdollars
        )
        if self.remaining_microdollars != expected_remaining:
            raise ValueError("remaining budget is inconsistent with effective spend")
        return self


class _CounterIncreaseBase(_EventBase):
    severity: Literal["attention"] = "attention"
    campaign_id: Identifier
    telemetry_packet_digest: Digest
    target_hashes: TargetHashes
    previous_count: NonNegativeInt
    current_count: PositiveInt
    increase: PositiveInt

    @model_validator(mode="after")
    def delta_is_exact(self) -> "_CounterIncreaseBase":
        if self.current_count <= self.previous_count:
            raise ValueError("counter did not increase")
        if self.increase != self.current_count - self.previous_count:
            raise ValueError("counter increase is inconsistent")
        return self


class CrashCounterIncreaseEvent(_CounterIncreaseBase):
    event_kind: Literal["crash_counter_increase"] = "crash_counter_increase"


class HangCounterIncreaseEvent(_CounterIncreaseBase):
    event_kind: Literal["hang_counter_increase"] = "hang_counter_increase"


class CrashTriageEvent(_EventBase):
    """Sanitized output of a future root-local reproducer/classifier.

    This schema cannot be produced from AFL counters alone.  It accepts no
    trace, seed, address, symbol, path, or model-authored severity prose.
    """

    event_kind: Literal["crash_triage"] = "crash_triage"
    severity: Literal["attention", "urgent"]
    campaign_id: Identifier
    telemetry_packet_digest: Digest
    target_hashes: TargetHashes
    stack_signature: Digest
    bug_class: Literal[
        "kasan_use_after_free",
        "kasan_out_of_bounds",
        "kasan_double_free",
        "kernel_null_dereference",
        "kernel_general_protection_fault",
        "kernel_oops_other",
        "harness_exit",
        "timeout",
        "unknown",
    ]
    reproductions: Annotated[int, Field(ge=1, le=16)]
    kernel_context_confirmed: bool
    potential_high_value: bool

    @model_validator(mode="after")
    def high_value_requires_reproduced_kernel_memory_safety(self) -> "CrashTriageEvent":
        high_value_classes = {
            "kasan_use_after_free",
            "kasan_out_of_bounds",
            "kasan_double_free",
        }
        qualifies = (
            self.reproductions >= 2
            and self.kernel_context_confirmed
            and self.bug_class in high_value_classes
        )
        if self.potential_high_value != qualifies:
            raise ValueError("potential-high-value flag does not match local evidence")
        if (self.severity == "urgent") != self.potential_high_value:
            raise ValueError("urgent severity is reserved for high-value candidates")
        return self


RedactedEvent: TypeAlias = Annotated[
    ProposalQuarantinedEvent
    | ExecutionReadyEvent
    | BudgetThresholdEvent
    | CrashCounterIncreaseEvent
    | HangCounterIncreaseEvent
    | CrashTriageEvent,
    Field(discriminator="event_kind"),
]
_EVENT_ADAPTER = TypeAdapter(RedactedEvent)


class CounterSnapshot(StrictModel):
    """A sanitized caller-maintained baseline; first observation emits nothing."""

    campaign_id: Identifier
    telemetry_packet_digest: Digest
    target_hashes: TargetHashes
    crash_count: NonNegativeInt
    hang_count: NonNegativeInt


def _duplicates_fail(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise EventProjectionError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _require_canonical_json(payload: bytes, *, source: Path) -> None:
    try:
        decoded = json.loads(payload, object_pairs_hook=_duplicates_fail)
    except EventProjectionError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EventProjectionError(f"invalid JSON in {source.name}") from exc
    if canonical_json(decoded) != payload:
        raise EventProjectionError(f"non-canonical JSON in {source.name}")


def _read_content_addressed(path: Path) -> tuple[str, bytes]:
    match = re.fullmatch(r"([0-9a-f]{64})\.json", path.name)
    if match is None:
        raise EventProjectionError(f"invalid content-addressed filename: {path.name}")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise EventProjectionError(
            f"authority item is unavailable: {path.name}"
        ) from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 2 * 1024 * 1024:
            raise EventProjectionError(
                f"authority item is not a bounded regular file: {path.name}"
            )
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = -1
            payload = handle.read(2 * 1024 * 1024 + 1)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if len(payload) > 2 * 1024 * 1024:
        raise EventProjectionError(f"authority item is oversized: {path.name}")
    actual = hashlib.sha256(payload).hexdigest()
    if actual != match.group(1):
        raise EventProjectionError(f"content digest mismatch: {path.name}")
    _require_canonical_json(payload, source=path)
    return actual, payload


def _utc_datetime(value: datetime | None) -> datetime:
    current = value or datetime.now(timezone.utc)
    if current.tzinfo is None or current.utcoffset() is None:
        raise EventProjectionError("event time must be timezone-aware")
    return current.astimezone(timezone.utc)


def _timestamp(value: datetime | None) -> str:
    return _utc_datetime(value).isoformat(timespec="seconds").replace(
        "+00:00", "Z"
    )


def _human_code(*, envelope_digest: str, nonce: str) -> str:
    material = bytes.fromhex(nonce) + envelope_digest.encode("ascii")
    return base64.b32encode(hashlib.sha256(material).digest()[:5]).decode("ascii")


def approval_binding_digest(
    *,
    envelope_digest: str,
    target_hashes: TargetHashes,
    nonce: str,
    human_code: str,
    expires_at: str,
) -> str:
    material = {
        "envelope_digest": envelope_digest,
        "expires_at": expires_at,
        "human_code": human_code,
        "nonce": nonce,
        "target_hashes": target_hashes.model_dump(mode="json"),
    }
    return "sha256:" + hashlib.sha256(canonical_json(material)).hexdigest()


def execution_approval_binding_digest(
    *,
    candidate_digest: str,
    envelope_digest: str,
    artifact_manifest_digest: str,
    artifact_digest: str,
    artifact_size_bytes: int,
    validation_report_digest: str,
    canary_report_digest: str,
    target_hashes: TargetHashes,
    promotion_scope: PromotionScope,
    nonce: str,
    human_code: str,
    expires_at: str,
) -> str:
    """Domain-separated binding for one exact post-canary live action."""

    material = {
        "binding_version": "execution-approval-binding.v1",
        "event_kind": "execution_ready",
        "positive_action": "approve_for_live_execution",
        "candidate_digest": candidate_digest,
        "envelope_digest": envelope_digest,
        "artifact_manifest_digest": artifact_manifest_digest,
        "artifact_digest": artifact_digest,
        "artifact_size_bytes": artifact_size_bytes,
        "validation_report_digest": validation_report_digest,
        "canary_report_digest": canary_report_digest,
        "target_hashes": target_hashes.model_dump(mode="json"),
        "promotion_scope": promotion_scope.model_dump(mode="json"),
        "nonce": nonce,
        "human_code": human_code,
        "expires_at": expires_at,
    }
    return "sha256:" + hashlib.sha256(canonical_json(material)).hexdigest()


def _new_challenge(
    *,
    envelope_digest: str,
    target_hashes: TargetHashes,
    nonce_source: Callable[[int], bytes],
    expires_at: str,
) -> ApprovalChallenge:
    raw = nonce_source(32)
    if not isinstance(raw, bytes) or len(raw) != 32:
        raise EventProjectionError("nonce source must return exactly 32 random bytes")
    nonce = raw.hex()
    human_code = _human_code(envelope_digest=envelope_digest, nonce=nonce)
    return ApprovalChallenge(
        nonce=nonce,
        human_code=human_code,
        expires_at=expires_at,
        binding_digest=approval_binding_digest(
            envelope_digest=envelope_digest,
            target_hashes=target_hashes,
            nonce=nonce,
            human_code=human_code,
            expires_at=expires_at,
        ),
    )


def _new_execution_challenge(
    *,
    candidate: ExecutionCandidate,
    candidate_digest: str,
    nonce_source: Callable[[int], bytes],
    expires_at: str,
) -> ExecutionApprovalChallenge:
    raw = nonce_source(32)
    if not isinstance(raw, bytes) or len(raw) != 32:
        raise EventProjectionError("nonce source must return exactly 32 random bytes")
    nonce = raw.hex()
    human_code = _human_code(
        envelope_digest=candidate_digest,
        nonce=nonce,
    )
    return ExecutionApprovalChallenge(
        nonce=nonce,
        human_code=human_code,
        expires_at=expires_at,
        binding_digest=execution_approval_binding_digest(
            candidate_digest=candidate_digest,
            envelope_digest=candidate.envelope_digest,
            artifact_manifest_digest=candidate.artifact_manifest_digest,
            artifact_digest=candidate.artifact_digest,
            artifact_size_bytes=candidate.artifact_size_bytes,
            validation_report_digest=candidate.validation_report_digest,
            canary_report_digest=candidate.canary_report_digest,
            target_hashes=candidate.target_hashes,
            promotion_scope=candidate.promotion_scope,
            nonce=nonce,
            human_code=human_code,
            expires_at=expires_at,
        ),
    )


def parse_event(payload: bytes | str) -> RedactedEvent:
    """Strictly parse an outbox event using JSON wire semantics."""

    try:
        return _EVENT_ADAPTER.validate_json(payload, strict=True)
    except Exception as exc:
        raise EventProjectionError("invalid redacted event") from exc


class EventOutbox:
    """Content-addressed, create-only storage with no delivery capability."""

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)

    def put(self, event: RedactedEvent) -> tuple[str, Path]:
        # Revalidate the serialized wire representation before authority storage.
        payload = canonical_json(event.model_dump(mode="json"))
        parse_event(payload)
        digest = hashlib.sha256(payload).hexdigest()
        self.root.mkdir(parents=True, exist_ok=True)
        destination = self.root / f"{digest}.json"
        try:
            descriptor = os.open(
                destination,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o440,
            )
        except FileExistsError:
            _, existing = _read_content_addressed(destination)
            parse_event(existing)
            if existing != payload:
                raise EventProjectionError("digest collision or mutated outbox event")
            return digest, destination
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
        except BaseException:
            destination.unlink(missing_ok=True)
            raise
        return digest, destination

    def events(self) -> tuple[RedactedEvent, ...]:
        if self.root.is_symlink():
            raise EventProjectionError("event outbox is not a regular directory")
        try:
            names = os.listdir(self.root)
        except FileNotFoundError:
            return ()
        except OSError as exc:
            raise EventProjectionError("event outbox is unavailable") from exc
        result: list[RedactedEvent] = []
        for name in sorted(item for item in names if item.endswith(".json")):
            path = self.root / name
            _, payload = _read_content_addressed(path)
            result.append(parse_event(payload))
        return tuple(result)


def _projection_key(event: RedactedEvent) -> tuple[object, ...]:
    if isinstance(event, ProposalQuarantinedEvent):
        return (event.event_kind, event.envelope_digest)
    if isinstance(event, ExecutionReadyEvent):
        return (event.event_kind, event.candidate_digest)
    if isinstance(event, BudgetThresholdEvent):
        return (event.event_kind, event.month, event.threshold_microdollars)
    if isinstance(event, CrashTriageEvent):
        return (event.event_kind, event.stack_signature)
    return (event.event_kind, event.campaign_id, event.telemetry_packet_digest)


def _challenge_has_expired(
    event: ProposalQuarantinedEvent | ExecutionReadyEvent, *, current: datetime
) -> bool:
    try:
        expiry = datetime.fromisoformat(
            event.approval.expires_at.replace("Z", "+00:00")
        )
    except ValueError as exc:
        raise EventProjectionError("proposal approval expiration is invalid") from exc
    if expiry.tzinfo is None or expiry.utcoffset() is None:
        raise EventProjectionError("proposal approval expiration is not timezone-aware")
    return expiry.astimezone(timezone.utc) <= current


def project_quarantine(
    quarantine_root: str | Path,
    outbox: EventOutbox,
    *,
    created_at: datetime | None = None,
    nonce_source: Callable[[int], bytes] = secrets.token_bytes,
    decision_ttl: timedelta = timedelta(minutes=30),
) -> tuple[ProposalQuarantinedEvent, ...]:
    """Project verified envelopes and permit one bounded expiry recovery.

    A single missed approval window may be reissued once for the exact same
    immutable envelope.  Further automatic reissues are prohibited, so this
    path cannot create an unbounded notification loop.
    """

    root = Path(quarantine_root)
    if not root.exists():
        return ()
    if not timedelta(minutes=5) <= decision_ttl <= timedelta(hours=48):
        raise EventProjectionError("decision TTL must be between 5 minutes and 48 hours")
    current = _utc_datetime(created_at)
    created_timestamp = _timestamp(current)
    expires_timestamp = _timestamp(current + decision_ttl)
    existing_events = outbox.events()
    existing = {_projection_key(event) for event in existing_events}
    challenges_by_envelope: dict[str, list[ProposalQuarantinedEvent]] = {}
    for event in existing_events:
        if isinstance(event, ProposalQuarantinedEvent):
            challenges_by_envelope.setdefault(event.envelope_digest, []).append(event)
    projected: list[ProposalQuarantinedEvent] = []
    for path in sorted(root.glob("*.json")):
        raw_digest, payload = _read_content_addressed(path)
        try:
            envelope = QuarantineEnvelope.model_validate_json(payload, strict=True)
        except Exception as exc:
            raise EventProjectionError(
                f"invalid quarantine envelope: {path.name}"
            ) from exc
        # Compiled candidates continue automatically through deterministic
        # validation and the isolated canary.  Emitting the legacy v1 event
        # here would ask the operator twice and, more importantly, its action
        # can authorize only offline validation—not execution.
        if envelope.compiled_artifact_hashes:
            continue
        envelope_digest = "sha256:" + raw_digest
        key = ("proposal_quarantined", envelope_digest)
        prior_challenges = challenges_by_envelope.get(envelope_digest, [])
        if prior_challenges:
            if len(prior_challenges) != 1 or not _challenge_has_expired(
                prior_challenges[0], current=current
            ):
                continue
        event = ProposalQuarantinedEvent(
            created_at=created_timestamp,
            envelope_digest=envelope_digest,
            proposal_hash=envelope.proposal_hash,
            target_hashes=envelope.target_hashes,
            approval=_new_challenge(
                envelope_digest=envelope_digest,
                target_hashes=envelope.target_hashes,
                nonce_source=nonce_source,
                expires_at=expires_timestamp,
            ),
        )
        outbox.put(event)
        existing.add(key)
        challenges_by_envelope.setdefault(envelope_digest, []).append(event)
        projected.append(event)
    return tuple(projected)


def project_execution_ready(
    candidate_root: str | Path,
    outbox: EventOutbox,
    *,
    created_at: datetime | None = None,
    nonce_source: Callable[[int], bytes] = secrets.token_bytes,
    decision_ttl: timedelta = timedelta(minutes=30),
) -> tuple[ExecutionReadyEvent, ...]:
    """Project canary-passed candidates into one final execution approval."""

    root = Path(candidate_root)
    if not root.exists():
        return ()
    if not timedelta(minutes=5) <= decision_ttl <= timedelta(hours=48):
        raise EventProjectionError("decision TTL must be between 5 minutes and 48 hours")
    current = _utc_datetime(created_at)
    created_timestamp = _timestamp(current)
    expires_timestamp = _timestamp(current + decision_ttl)
    existing_events = outbox.events()
    challenges: dict[str, list[ExecutionReadyEvent]] = {}
    for event in existing_events:
        if isinstance(event, ExecutionReadyEvent):
            challenges.setdefault(event.candidate_digest, []).append(event)

    projected: list[ExecutionReadyEvent] = []
    for path in sorted(root.glob("*.json")):
        raw_digest, payload = _read_content_addressed(path)
        try:
            candidate = ExecutionCandidate.model_validate_json(payload, strict=True)
        except Exception as exc:
            raise EventProjectionError(
                f"invalid execution candidate: {path.name}"
            ) from exc
        candidate_digest = "sha256:" + raw_digest
        prior = challenges.get(candidate_digest, [])
        if prior:
            if len(prior) != 1 or not _challenge_has_expired(
                prior[0], current=current
            ):
                continue
        event = ExecutionReadyEvent(
            created_at=created_timestamp,
            candidate_digest=candidate_digest,
            envelope_digest=candidate.envelope_digest,
            artifact_manifest_digest=candidate.artifact_manifest_digest,
            artifact_digest=candidate.artifact_digest,
            artifact_size_bytes=candidate.artifact_size_bytes,
            validation_report_digest=candidate.validation_report_digest,
            canary_report_digest=candidate.canary_report_digest,
            target_hashes=candidate.target_hashes,
            promotion_scope=candidate.promotion_scope,
            approval=_new_execution_challenge(
                candidate=candidate,
                candidate_digest=candidate_digest,
                nonce_source=nonce_source,
                expires_at=expires_timestamp,
            ),
        )
        outbox.put(event)
        challenges.setdefault(candidate_digest, []).append(event)
        projected.append(event)
    return tuple(projected)


def project_budget_status(
    status: BudgetStatus,
    outbox: EventOutbox,
    *,
    created_at: datetime | None = None,
) -> tuple[BudgetThresholdEvent, ...]:
    """Emit each configured monthly threshold crossing at most once."""

    existing = {_projection_key(event) for event in outbox.events()}
    projected: list[BudgetThresholdEvent] = []
    for threshold in sorted(set(status.crossed_warning_thresholds_microdollars)):
        key = ("budget_threshold", status.month, threshold)
        if key in existing:
            continue
        event = BudgetThresholdEvent(
            created_at=_timestamp(created_at),
            severity="critical" if status.warning_level in {"critical", "exhausted"} else "warning",
            month=status.month,
            threshold_microdollars=threshold,
            effective_spend_microdollars=status.effective_spend_microdollars,
            hard_limit_microdollars=status.hard_limit_microdollars,
            remaining_microdollars=status.remaining_microdollars,
        )
        outbox.put(event)
        existing.add(key)
        projected.append(event)
    return tuple(projected)


def project_counter_snapshot(
    previous: CounterSnapshot | None,
    current: CounterSnapshot,
    outbox: EventOutbox,
    *,
    created_at: datetime | None = None,
) -> tuple[CrashCounterIncreaseEvent | HangCounterIncreaseEvent, ...]:
    """Project sanitized counter deltas; the first/reset observation is baseline-only.

    The caller owns persistence of the returned/current baseline.  A campaign or
    target change, or a counter decrease, is treated as a reset and never turned
    into a misleading increase alert.
    """

    if previous is None:
        return ()
    if (
        previous.campaign_id != current.campaign_id
        or previous.target_hashes != current.target_hashes
        or current.crash_count < previous.crash_count
        or current.hang_count < previous.hang_count
    ):
        return ()

    existing = {_projection_key(event) for event in outbox.events()}
    projected: list[CrashCounterIncreaseEvent | HangCounterIncreaseEvent] = []
    specifications: Iterable[
        tuple[
            str,
            int,
            int,
            type[CrashCounterIncreaseEvent] | type[HangCounterIncreaseEvent],
        ]
    ] = (
        (
            "crash_counter_increase",
            previous.crash_count,
            current.crash_count,
            CrashCounterIncreaseEvent,
        ),
        (
            "hang_counter_increase",
            previous.hang_count,
            current.hang_count,
            HangCounterIncreaseEvent,
        ),
    )
    for kind, old, new, event_type in specifications:
        if new <= old:
            continue
        key = (kind, current.campaign_id, current.telemetry_packet_digest)
        if key in existing:
            continue
        event = event_type(
            created_at=_timestamp(created_at),
            campaign_id=current.campaign_id,
            telemetry_packet_digest=current.telemetry_packet_digest,
            target_hashes=current.target_hashes,
            previous_count=old,
            current_count=new,
            increase=new - old,
        )
        outbox.put(event)
        existing.add(key)
        projected.append(event)
    return tuple(projected)


def render_fixed_message(event: RedactedEvent) -> str:
    """Render a redacted fixed template; no field can carry free-form prose."""

    if isinstance(event, ProposalQuarantinedEvent):
        return (
            "IOU-AI APPROVAL: GPT plan passed Claude and local checks. "
            f"Ref {event.envelope_digest.removeprefix('sha256:')[:12]}. "
            f"Reply APPROVE {event.approval.human_code} or "
            f"DENY {event.approval.human_code} by {event.approval.expires_at}. "
            "Offline validation only; AFL/Nyx fleet unchanged."
        )
    if isinstance(event, ExecutionReadyEvent):
        artifact = event.artifact_digest.removeprefix("sha256:")[:12]
        return (
            "IOU-AI LIVE EXECUTION APPROVAL: exact artifact "
            f"{artifact} ({event.artifact_size_bytes} bytes) passed GPT planning, "
            "Claude review, deterministic checks, byte round-trip, and isolated "
            f"Nyx canary. Scope={event.promotion_scope.destination_id}; one artifact. "
            f"Reply EXECUTE {event.approval.human_code} or "
            f"DENY {event.approval.human_code} by {event.approval.expires_at}."
        )
    if isinstance(event, BudgetThresholdEvent):
        return (
            "IOU-AI BUDGET: monthly spend crossed "
            f"${_format_usd(event.threshold_microdollars)}; "
            f"${_format_usd(event.remaining_microdollars)} remains of "
            f"${_format_usd(event.hard_limit_microdollars)}."
        )
    if isinstance(event, CrashCounterIncreaseEvent):
        return (
            "IOU-AI CRASH COUNTER ALERT: "
            f"campaign {event.campaign_id} increased by {event.increase} "
            f"({event.previous_count} to {event.current_count}). "
            "Untriaged; impact and bounty status are not yet established."
        )
    if isinstance(event, HangCounterIncreaseEvent):
        return (
            "IOU-AI HANG COUNTER ALERT: "
            f"campaign {event.campaign_id} increased by {event.increase} "
            f"({event.previous_count} to {event.current_count}). Untriaged."
        )
    if isinstance(event, CrashTriageEvent):
        signature = event.stack_signature.removeprefix("sha256:")[:12]
        if event.potential_high_value:
            return (
                "POTENTIAL HIGH-VALUE SECURITY IMPACT - PRESERVE/REPRODUCE NOW. "
                f"Class={event.bug_class}; reproductions={event.reproductions}; "
                f"signature={signature}. Not a confirmed bounty."
            )
        return (
            "IOU-AI SECURITY TRIAGE: "
            f"class={event.bug_class}; reproductions={event.reproductions}; "
            f"signature={signature}; high-value criteria not met."
        )
    raise EventProjectionError("unsupported event type")


def _format_usd(microdollars: int) -> str:
    """Format cents with integer half-up rounding in every runtime."""

    if type(microdollars) is not int or microdollars < 0:
        raise EventProjectionError("microdollar amount must be a non-negative integer")
    cents = (microdollars + 5_000) // 10_000
    return f"{cents // 100}.{cents % 100:02d}"


__all__ = [
    "ApprovalChallenge",
    "BudgetThresholdEvent",
    "CounterSnapshot",
    "CrashTriageEvent",
    "CrashCounterIncreaseEvent",
    "EventOutbox",
    "EventProjectionError",
    "ExecutionApprovalChallenge",
    "ExecutionReadyEvent",
    "HangCounterIncreaseEvent",
    "ProposalQuarantinedEvent",
    "RedactedEvent",
    "approval_binding_digest",
    "execution_approval_binding_digest",
    "parse_event",
    "project_budget_status",
    "project_counter_snapshot",
    "project_execution_ready",
    "project_quarantine",
    "render_fixed_message",
]
