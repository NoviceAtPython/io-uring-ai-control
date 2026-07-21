from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path

import pytest

from iou_ai.feedback import (
    FeedbackError,
    FeedbackStore,
    ReviewFeedbackRecord,
    build_review_feedback,
    load_prior_proposal_outcomes,
    to_prior_proposal_outcome,
)
from iou_ai.models import PlannerProposal, ReviewerVerdict, TelemetryPacket
from iou_ai.validator import validate_reviewer


ROOT = Path(__file__).resolve().parents[1]


def _fixtures() -> tuple[TelemetryPacket, PlannerProposal]:
    return (
        TelemetryPacket.model_validate_json(
            (ROOT / "examples" / "telemetry.sample.json").read_text(encoding="utf-8")
        ),
        PlannerProposal.model_validate_json(
            (ROOT / "examples" / "proposal.mock.json").read_text(encoding="utf-8")
        ),
    )


def _reject_verdict(proposal: PlannerProposal) -> ReviewerVerdict:
    data = json.loads(
        (ROOT / "examples" / "reviewer.mock.json").read_text(encoding="utf-8")
    )
    data.update(
        {
            "verdict": "reject",
            "summary": "Reviewer prose naming /root/private and a candidate seed must disappear.",
            "required_changes": [
                "Provider-authored instructions and private paths must not be persisted."
            ],
            "residual_risk": "high",
            "safe_for_quarantine": False,
            "findings": [
                {
                    "finding_id": "finding:unsafe-seed-prose",
                    "severity": "high",
                    "category": "safety",
                    "message": (
                        "Raw candidate bytes and /root/private/crash.log must not "
                        "be retained."
                    ),
                    "evidence_refs": ["evidence:coverage-read-link-plateau"],
                    "program_id": "",
                    "step_id": "",
                }
            ],
        }
    )
    data["proposal_id"] = proposal.proposal_id
    data["packet_id"] = proposal.packet_id
    return ReviewerVerdict.model_validate_json(json.dumps(data))


def _record() -> ReviewFeedbackRecord:
    telemetry, proposal = _fixtures()
    verdict = _reject_verdict(proposal)
    report = validate_reviewer(telemetry, proposal, verdict)
    return build_review_feedback(
        telemetry,
        proposal,
        verdict,
        report,
        now=datetime(2026, 7, 16, 16, 0, tzinfo=timezone.utc),
    )


def test_rejected_review_is_persistable_without_provider_prose_or_artifacts(
    tmp_path: Path,
) -> None:
    record = _record()
    store = FeedbackStore(tmp_path)
    digest, path = store.put(record)

    assert path.name == f"{digest}.json"
    assert path.read_bytes() == path.read_bytes().strip()
    wire = path.read_text(encoding="utf-8")
    assert record.verdict.value == "reject"
    assert record.findings[0].category.value == "safety"
    assert record.findings[0].severity.value == "high"
    assert "Reviewer prose" not in wire
    assert "Provider-authored" not in wire
    assert "candidate bytes" not in wire
    assert "/root/" not in wire
    assert '"message"' not in wire
    assert '"required_changes"' not in wire
    assert '"program_id"' not in wire
    assert '"step_id"' not in wire

    verified = list(store.iter_verified())
    assert verified == [(digest, record)]


def test_structurally_invalid_review_cannot_enter_feedback_store() -> None:
    telemetry, proposal = _fixtures()
    verdict_data = _reject_verdict(proposal).model_dump(mode="json")
    verdict_data["packet_id"] = "packet:wrong"
    verdict = ReviewerVerdict.model_validate_json(json.dumps(verdict_data))
    report = validate_reviewer(telemetry, proposal, verdict)

    assert "review.binding" in report.failed_check_ids
    with pytest.raises(FeedbackError, match="structural"):
        build_review_feedback(telemetry, proposal, verdict, report)


def test_escalation_is_bounded_feedback_and_maps_to_rejected_outcome() -> None:
    telemetry, proposal = _fixtures()
    data = _reject_verdict(proposal).model_dump(mode="json")
    data["verdict"] = "escalate"
    verdict = ReviewerVerdict.model_validate_json(json.dumps(data))
    report = validate_reviewer(telemetry, proposal, verdict)

    record = build_review_feedback(telemetry, proposal, verdict, report)
    assert record.verdict.value == "escalate"
    assert to_prior_proposal_outcome(record).outcome.value == "rejected"


def test_loader_keeps_only_newest_twelve_verified_target_bound_records(
    tmp_path: Path,
) -> None:
    base = _record()
    store = FeedbackStore(tmp_path)
    start = datetime(2026, 7, 16, 16, 0, tzinfo=timezone.utc)
    for index in range(13):
        data = base.model_dump(mode="json")
        data.update(
            {
                "created_at": (start + timedelta(seconds=index))
                .isoformat()
                .replace("+00:00", "Z"),
                "proposal_id": f"proposal:feedback-{index:02d}",
                "proposal_hash": "sha256:" + f"{index + 1:064x}",
                "packet_hash": "sha256:" + f"{index + 101:064x}",
            }
        )
        store.put(ReviewFeedbackRecord.model_validate_json(json.dumps(data)))

    other_target = base.model_dump(mode="json")
    other_target["proposal_id"] = "proposal:wrong-target"
    other_target["proposal_hash"] = "sha256:" + "e" * 64
    other_target["packet_hash"] = "sha256:" + "f" * 64
    other_target["target_hashes"]["harness_hash"] = "sha256:" + "d" * 64
    store.put(ReviewFeedbackRecord.model_validate_json(json.dumps(other_target)))

    outcomes = load_prior_proposal_outcomes(
        tmp_path,
        target_hashes=base.target_hashes,
    )

    assert len(outcomes) == 12
    assert outcomes[0].proposal_id == "proposal:feedback-12"
    assert outcomes[-1].proposal_id == "proposal:feedback-01"
    assert all(item.outcome.value == "rejected" for item in outcomes)
    assert all("verdict=reject" in item.summary for item in outcomes)
    assert all("safety/high" in item.summary for item in outcomes)
    assert all("Reviewer prose" not in item.summary for item in outcomes)


def test_mutated_feedback_fails_closed_instead_of_being_skipped(tmp_path: Path) -> None:
    store = FeedbackStore(tmp_path)
    _, path = store.put(_record())
    path.chmod(0o600)
    path.write_text("{}", encoding="utf-8")

    with pytest.raises(FeedbackError, match="content verification"):
        list(store.iter_verified())
