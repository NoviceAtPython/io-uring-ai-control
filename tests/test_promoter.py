from __future__ import annotations

from datetime import datetime, timezone
import hashlib
from pathlib import Path

import pytest

from iou_ai.decisions import DecisionArchive, ExecutionDecision, sign_decision
from iou_ai.events import EventOutbox, project_execution_ready
from iou_ai.execution import (
    CanaryOutcome,
    CanaryReport,
    ExecutionAuthorityStore,
    PromotionScope,
    WorkerSet,
    build_execution_candidate,
    build_validation_report,
    content_digest,
)
from iou_ai.promoter import DestinationSpec, PromotionError, Promoter
from iou_ai.quarantine import QuarantineStore, canonical_json

from test_validation_authority import NOW, _authority


SECRET = b"p" * 32
TIME = datetime(2026, 7, 17, 8, 2, tzinfo=timezone.utc)


def _runner(tmp_path: Path) -> tuple[Path, str]:
    path = tmp_path / "nyx-canary-runner"
    path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    digest = "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
    return path, digest


def _prepared(tmp_path: Path):
    artifacts, envelope, envelope_digest, manifest, manifest_digest, payload = _authority(
        tmp_path
    )
    quarantine = QuarantineStore(tmp_path / "quarantine")
    stored_digest, _ = quarantine.put(envelope.model_dump(mode="json"))
    assert "sha256:" + stored_digest == envelope_digest

    authority = ExecutionAuthorityStore(tmp_path / "authority")
    validation = build_validation_report(
        envelope_digest=envelope_digest,
        envelope=envelope,
        artifact_manifest_digest=manifest_digest,
        manifest=manifest,
        payload=payload,
        created_at=NOW,
    )
    validation_digest, _ = authority.put_validation(validation)
    _, runner_hash = _runner(tmp_path)
    fleet_snapshot = "sha256:" + "a" * 64
    canary = CanaryReport(
        report_id="canary-promoter-test",
        started_at="2026-07-17T08:00:00Z",
        finished_at="2026-07-17T08:00:01Z",
        envelope_digest=envelope_digest,
        validation_report_digest=validation_digest,
        artifact_manifest_digest=manifest_digest,
        artifact_digest=manifest.payload_digest,
        target_hashes=manifest.target_hashes,
        runner_hash=runner_hash,
        runner_result_digest="sha256:" + "b" * 64,
        outcome=CanaryOutcome.PASSED,
        exact_seed_dry_runs=1,
        executions_total=1,
        timeout_seconds=10,
        harness_accepted=True,
        infrastructure_error=False,
        runner_exit_code=0,
        timed_out=False,
        signal_number=0,
        fleet_snapshot_before=fleet_snapshot,
        fleet_snapshot_after=fleet_snapshot,
    )
    canary_digest, _ = authority.put_report(canary)
    scope = PromotionScope(
        campaign_id="campaign:promoter-test",
        destination_id="native_ai_sync",
        worker_set=WorkerSet.NATIVE_STABLE,
    )
    candidate = build_execution_candidate(
        validation_report_digest=validation_digest,
        validation=validation,
        canary_report_digest=canary_digest,
        canary=canary,
        artifact_manifest_digest=manifest_digest,
        manifest=manifest,
        promotion_scope=scope,
        ready_at="2026-07-17T08:00:01Z",
        allowed_runner_hashes=frozenset({runner_hash}),
    )
    candidate_digest, _ = authority.put_candidate(candidate)

    events = EventOutbox(tmp_path / "events")
    (event,) = project_execution_ready(
        authority.candidate_root,
        events,
        created_at=datetime(2026, 7, 17, 8, 0, tzinfo=timezone.utc),
        nonce_source=lambda count: b"n" * count,
    )
    event_digest = content_digest(canonical_json(event.model_dump(mode="json")))
    archive = DecisionArchive(
        tmp_path / "decisions", events=events, verification_key=SECRET
    )
    return {
        "archive": archive,
        "artifacts": artifacts,
        "authority": authority,
        "candidate": candidate,
        "candidate_digest": candidate_digest,
        "envelope": envelope,
        "event": event,
        "event_digest": event_digest,
        "events": events,
        "payload": payload,
        "quarantine": quarantine,
        "runner_hash": runner_hash,
    }


def _decision(state: dict, *, action: str = "approve_for_live_execution") -> ExecutionDecision:
    candidate = state["candidate"]
    event = state["event"]
    return ExecutionDecision(
        signer_id="relay:telegram-v1",
        channel="telegram",
        event_digest=state["event_digest"],
        candidate_digest=state["candidate_digest"],
        envelope_digest=candidate.envelope_digest,
        artifact_manifest_digest=candidate.artifact_manifest_digest,
        artifact_digest=candidate.artifact_digest,
        artifact_size_bytes=candidate.artifact_size_bytes,
        validation_report_digest=candidate.validation_report_digest,
        canary_report_digest=candidate.canary_report_digest,
        target_hashes=candidate.target_hashes,
        promotion_scope=candidate.promotion_scope,
        approval_binding_digest=event.approval.binding_digest,
        decision_nonce=event.approval.nonce,
        human_code=event.approval.human_code,
        sender_binding="sha256:" + "c" * 64,
        action=action,
        reason_code=(
            "operator_approved_live_execution"
            if action == "approve_for_live_execution"
            else "operator_denied"
        ),
        issued_at="2026-07-17T08:01:00Z",
        expires_at=event.approval.expires_at,
    )


def _promoter(tmp_path: Path, state: dict, *, current_target_probe):
    root = tmp_path / "promotion"
    inbox = root / "native_ai_sync" / "queue"
    inbox.mkdir(parents=True)
    spec = DestinationSpec(
        destination_id="native_ai_sync",
        campaign_id="campaign:promoter-test",
        worker_set=WorkerSet.NATIVE_STABLE,
        inbox=inbox,
        allowed_root=root,
        allowed_runner_hashes=frozenset({state["runner_hash"]}),
    )
    return (
        Promoter(
            events=state["events"],
            decisions=state["archive"],
            quarantine=state["quarantine"],
            artifacts=state["artifacts"],
            authority=state["authority"],
            receipts=tmp_path / "receipts",
            destinations={"native_ai_sync": spec},
            current_target_probe=current_target_probe,
        ),
        inbox,
    )


def test_approved_exact_candidate_publishes_once_and_is_idempotent(
    tmp_path: Path,
) -> None:
    state = _prepared(tmp_path)
    state["archive"].import_signed(sign_decision(_decision(state), SECRET), now=TIME)
    promoter, inbox = _promoter(
        tmp_path,
        state,
        current_target_probe=lambda: state["candidate"].target_hashes,
    )

    first = promoter.promote(state["candidate_digest"], now=TIME)
    second = promoter.promote(state["candidate_digest"], now=TIME)

    assert first == second
    expected = inbox / (
        "artifact-"
        + state["candidate"].artifact_digest.removeprefix("sha256:")
        + ".seed"
    )
    assert expected.read_bytes() == state["payload"]
    assert list((tmp_path / "receipts").glob("*.json"))


def test_denied_candidate_never_writes_a_seed(tmp_path: Path) -> None:
    state = _prepared(tmp_path)
    state["archive"].import_signed(
        sign_decision(_decision(state, action="deny"), SECRET), now=TIME
    )
    promoter, inbox = _promoter(
        tmp_path,
        state,
        current_target_probe=lambda: state["candidate"].target_hashes,
    )

    with pytest.raises(PromotionError, match="not approved"):
        promoter.promote(state["candidate_digest"], now=TIME)
    assert list(inbox.iterdir()) == []


def test_target_drift_before_or_during_lock_prevents_publication(tmp_path: Path) -> None:
    state = _prepared(tmp_path)
    state["archive"].import_signed(sign_decision(_decision(state), SECRET), now=TIME)
    different = state["candidate"].target_hashes.model_copy(
        update={"harness_hash": "sha256:" + "d" * 64}
    )
    observations = iter((state["candidate"].target_hashes, different))
    promoter, inbox = _promoter(
        tmp_path,
        state,
        current_target_probe=lambda: next(observations),
    )

    with pytest.raises(PromotionError, match="drifted during promotion"):
        promoter.promote(state["candidate_digest"], now=TIME)
    assert list(inbox.iterdir()) == []


def test_preexisting_wrong_destination_bytes_fail_closed(tmp_path: Path) -> None:
    state = _prepared(tmp_path)
    state["archive"].import_signed(sign_decision(_decision(state), SECRET), now=TIME)
    promoter, inbox = _promoter(
        tmp_path,
        state,
        current_target_probe=lambda: state["candidate"].target_hashes,
    )
    visible = inbox / (
        "artifact-"
        + state["candidate"].artifact_digest.removeprefix("sha256:")
        + ".seed"
    )
    visible.write_bytes(b"wrong bytes")

    with pytest.raises(PromotionError, match="wrong bytes"):
        promoter.promote(state["candidate_digest"], now=TIME)
    assert visible.read_bytes() == b"wrong bytes"
