from __future__ import annotations

from datetime import datetime, timezone
import hashlib
from pathlib import Path

import pytest

from iou_ai.decisions import (
    DecisionArchive,
    DecisionError,
    ExecutionDecision,
    HumanDecision,
    sign_decision,
)
from iou_ai.events import (
    EventOutbox,
    ExecutionReadyEvent,
    project_execution_ready,
    render_fixed_message,
)
from iou_ai.execution import (
    CanaryOutcome,
    CanaryReport,
    ExecutionAuthorityStore,
    ExecutionCandidate,
    PromotionScope,
    WorkerSet,
)
from iou_ai.models import TargetHashes
from iou_ai.quarantine import canonical_json


NOW = datetime(2026, 7, 17, 8, 0, tzinfo=timezone.utc)
SECRET = b"x" * 32
TARGETS = TargetHashes(
    harness_hash="sha256:" + "1" * 64,
    compiler_hash="sha256:" + "2" * 64,
    op_table_hash="sha256:" + "3" * 64,
    fleet_config_hash="sha256:" + "4" * 64,
)
SCOPE = PromotionScope(
    campaign_id="campaign:io-uring-native",
    destination_id="native_ai_sync",
    worker_set=WorkerSet.NATIVE_STABLE,
)


def _candidate() -> ExecutionCandidate:
    return ExecutionCandidate(
        candidate_id="candidate-execution-probe",
        ready_at="2026-07-17T07:59:00Z",
        envelope_digest="sha256:" + "5" * 64,
        artifact_manifest_digest="sha256:" + "6" * 64,
        artifact_digest="sha256:" + "7" * 64,
        artifact_size_bytes=11,
        validation_report_digest="sha256:" + "8" * 64,
        canary_report_digest="sha256:" + "9" * 64,
        target_hashes=TARGETS,
        promotion_scope=SCOPE,
    )


def _event(tmp_path: Path) -> tuple[EventOutbox, ExecutionReadyEvent, str]:
    authority = ExecutionAuthorityStore(tmp_path / "authority")
    authority.put_candidate(_candidate())
    outbox = EventOutbox(tmp_path / "events")
    projected = project_execution_ready(
        authority.candidate_root,
        outbox,
        created_at=NOW,
        nonce_source=lambda count: b"n" * count,
    )
    assert len(projected) == 1
    event = projected[0]
    digest = "sha256:" + hashlib.sha256(
        canonical_json(event.model_dump(mode="json"))
    ).hexdigest()
    return outbox, event, digest


def _decision(event: ExecutionReadyEvent, event_digest: str) -> ExecutionDecision:
    return ExecutionDecision(
        signer_id="relay:telegram-v1",
        channel="telegram",
        event_digest=event_digest,
        candidate_digest=event.candidate_digest,
        envelope_digest=event.envelope_digest,
        artifact_manifest_digest=event.artifact_manifest_digest,
        artifact_digest=event.artifact_digest,
        artifact_size_bytes=event.artifact_size_bytes,
        validation_report_digest=event.validation_report_digest,
        canary_report_digest=event.canary_report_digest,
        target_hashes=event.target_hashes,
        promotion_scope=event.promotion_scope,
        approval_binding_digest=event.approval.binding_digest,
        decision_nonce=event.approval.nonce,
        human_code=event.approval.human_code,
        sender_binding="sha256:" + "a" * 64,
        action="approve_for_live_execution",
        reason_code="operator_approved_live_execution",
        issued_at="2026-07-17T08:01:00Z",
        expires_at=event.approval.expires_at,
    )


def test_local_operator_approval_verifies_and_archives(tmp_path: Path) -> None:
    # The on-box operator approval (iou-ai-approve) mints an ExecutionDecision
    # with the operator:local-v1 signer and must pass the exact same verifying
    # import path as a relay-signed Telegram approval.
    from iou_ai.approve_cli import _operator_decision
    from iou_ai.decisions import DecisionArchive, sign_decision

    outbox, event, _digest = _event(tmp_path)
    decision = _operator_decision(event, SECRET, "2026-07-17T08:01:00Z")
    assert decision.signer_id == "operator:local-v1"
    assert decision.channel == "operator"
    assert decision.action == "approve_for_live_execution"
    signed = sign_decision(decision, SECRET)
    archive = DecisionArchive(
        tmp_path / "archive", events=outbox, verification_key=SECRET
    )
    when = datetime(2026, 7, 17, 8, 2, tzinfo=timezone.utc)
    digest, path = archive.import_signed(signed, now=when)
    assert path.exists()
    again, _ = archive.import_signed(signed, now=when)
    assert again == digest  # idempotent


def test_auto_approval_uses_a_distinct_signer_identity(tmp_path: Path) -> None:
    # Unattended auto-promote must be distinguishable from a human approval in the
    # archive forever after. Same key and same verifying path, but a different
    # signer identity and a different sender binding, so an audit can always tell
    # "the auto policy accepted this" from "aedyn approved this".
    import json

    from iou_ai.approve_cli import _operator_decision
    from iou_ai.decisions import DecisionArchive, sign_decision

    outbox, event, _digest = _event(tmp_path)
    auto = _operator_decision(event, SECRET, "2026-07-17T08:01:00Z", auto=True)
    human = _operator_decision(event, SECRET, "2026-07-17T08:01:00Z")
    assert auto.signer_id == "operator:auto-v1"
    assert human.signer_id == "operator:local-v1"
    assert auto.sender_binding != human.sender_binding
    # The action/reason invariant is untouched by the auto path.
    assert auto.action == "approve_for_live_execution"
    assert auto.reason_code == "operator_approved_live_execution"

    archive = DecisionArchive(
        tmp_path / "archive", events=outbox, verification_key=SECRET
    )
    when = datetime(2026, 7, 17, 8, 2, tzinfo=timezone.utc)
    digest, path = archive.import_signed(sign_decision(auto, SECRET), now=when)
    assert path.exists()
    assert json.loads(path.read_text())["decision"]["signer_id"] == "operator:auto-v1"
    again, _ = archive.import_signed(sign_decision(auto, SECRET), now=when)
    assert again == digest  # idempotent


def test_execution_event_is_redacted_single_approval_and_idempotent(
    tmp_path: Path,
) -> None:
    outbox, event, _ = _event(tmp_path)
    assert event.schema_version == "redacted-event.v2"
    assert event.approval.allowed_actions == (
        "approve_for_live_execution",
        "deny",
    )
    message = render_fixed_message(event)
    assert "LIVE EXECUTION APPROVAL" in message
    assert event.artifact_digest[:19].removeprefix("sha256:") in message
    assert len(
        project_execution_ready(
            tmp_path / "authority" / "candidates",
            outbox,
            created_at=NOW,
            nonce_source=lambda count: b"z" * count,
        )
    ) == 0


def test_signed_execution_decision_binds_every_authority_field(
    tmp_path: Path,
) -> None:
    outbox, event, event_digest = _event(tmp_path)
    archive = DecisionArchive(
        tmp_path / "archive",
        events=outbox,
        verification_key=SECRET,
    )
    signed = sign_decision(_decision(event, event_digest), SECRET)
    first = archive.import_signed(signed, now=datetime(2026, 7, 17, 8, 2, tzinfo=timezone.utc))
    second = archive.import_signed(signed, now=datetime(2026, 7, 17, 8, 2, tzinfo=timezone.utc))
    assert first == second


def test_execution_decision_rejects_resigned_artifact_or_scope_mutation(
    tmp_path: Path,
) -> None:
    outbox, event, event_digest = _event(tmp_path)
    archive = DecisionArchive(
        tmp_path / "archive",
        events=outbox,
        verification_key=SECRET,
    )
    decision = _decision(event, event_digest)
    for mutation in (
        {"artifact_digest": "sha256:" + "b" * 64},
        {
            "promotion_scope": PromotionScope(
                campaign_id="campaign:other",
                destination_id="native_ai_sync",
                worker_set=WorkerSet.NATIVE_STABLE,
            )
        },
    ):
        with pytest.raises(DecisionError, match="exact canaried artifact"):
            archive.import_signed(
                sign_decision(decision.model_copy(update=mutation), SECRET),
                now=datetime(2026, 7, 17, 8, 2, tzinfo=timezone.utc),
            )


def test_offline_v1_decision_cannot_authorize_execution_event(tmp_path: Path) -> None:
    outbox, event, event_digest = _event(tmp_path)
    archive = DecisionArchive(
        tmp_path / "archive",
        events=outbox,
        verification_key=SECRET,
    )
    offline = HumanDecision(
        signer_id="relay:telegram-v1",
        channel="telegram",
        event_digest=event_digest,
        envelope_digest=event.envelope_digest,
        target_hashes=event.target_hashes,
        approval_binding_digest=event.approval.binding_digest,
        decision_nonce=event.approval.nonce,
        human_code=event.approval.human_code,
        sender_binding="sha256:" + "a" * 64,
        action="approve_for_offline_validation",
        reason_code="operator_approved",
        issued_at="2026-07-17T08:01:00Z",
        expires_at=event.approval.expires_at,
    )
    with pytest.raises(DecisionError, match="offline decision"):
        archive.import_signed(
            sign_decision(offline, SECRET),
            now=datetime(2026, 7, 17, 8, 2, tzinfo=timezone.utc),
        )


def test_canary_report_cannot_claim_pass_without_measured_dry_run() -> None:
    with pytest.raises(ValueError, match="outcome does not match"):
        CanaryReport(
            report_id="canary-invalid",
            started_at="2026-07-17T08:00:00Z",
            finished_at="2026-07-17T08:00:10Z",
            envelope_digest="sha256:" + "5" * 64,
            validation_report_digest="sha256:" + "8" * 64,
            artifact_manifest_digest="sha256:" + "6" * 64,
            artifact_digest="sha256:" + "7" * 64,
            target_hashes=TARGETS,
            runner_hash="sha256:" + "c" * 64,
            runner_result_digest="sha256:" + "d" * 64,
            outcome=CanaryOutcome.PASSED,
            exact_seed_dry_runs=0,
            executions_total=0,
            timeout_seconds=10,
            harness_accepted=False,
            infrastructure_error=False,
            runner_exit_code=1,
            timed_out=False,
            signal_number=0,
            fleet_snapshot_before="sha256:" + "e" * 64,
            fleet_snapshot_after="sha256:" + "e" * 64,
        )
