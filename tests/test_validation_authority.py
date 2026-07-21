from __future__ import annotations

from datetime import datetime, timezone
import hashlib
from pathlib import Path

import pytest

from iou_ai.artifacts import ArtifactStore
from iou_ai.compiler import compile_program, compiler_hash
from iou_ai.contract import _flags, _operations, _profiles
from iou_ai.execution import (
    CanaryOutcome,
    CanaryReport,
    ExecutionAuthorityError,
    ExecutionAuthorityStore,
    PromotionScope,
    WorkerSet,
    build_execution_candidate,
    build_validation_report,
    content_digest,
)
from iou_ai.harness_codec import AUDITED_HARNESS_HASH
from iou_ai.models import (
    HarnessContract,
    HarnessEnvironment,
    Hypothesis,
    LaneKind,
    LinkMode,
    PlannerProgram,
    PlannerProposal,
    PromotionState,
    ProviderRole,
    ProviderTrace,
    QuarantineEnvelope,
    ResidualRisk,
    ReviewerVerdict,
    SymbolicStep,
    TargetHashes,
    ValidationRecord,
    VerdictKind,
)
from iou_ai.quarantine import canonical_json
from iou_ai.validator import VALIDATOR_HASH, VALIDATOR_VERSION


NOW = "2026-07-17T12:00:00Z"


def _contract() -> HarnessContract:
    return HarnessContract(
        schema_version="harness-contract.v1",
        contract_id="harness:production.typed.validation-test",
        generated_at=NOW,
        environment=HarnessEnvironment.PRODUCTION,
        verified=True,
        test_only=False,
        verified_by="verifier:test",
        verification_evidence_hash="sha256:" + "1" * 64,
        source_revision_hash="sha256:" + "2" * 64,
        target_hashes=TargetHashes(
            harness_hash=AUDITED_HARNESS_HASH,
            compiler_hash=compiler_hash(),
            op_table_hash="sha256:" + "3" * 64,
            fleet_config_hash="sha256:" + "4" * 64,
        ),
        input_max_bytes=2048,
        operation_max_count=96,
        operation_selector_modulus=61,
        deterministic_compiler=True,
        decode_round_trip_verified=True,
        profiles=_profiles(),
        resources=[],
        flags=_flags(),
        operations=_operations(),
        forbidden_profile_ids=["sqpoll"],
        notes=["Validation authority test contract."],
    )


def _program() -> PlannerProgram:
    return PlannerProgram(
        program_id="validation_probe",
        objective="Validate one canonical no-op artifact before an isolated canary.",
        lane=LaneKind.STABLE_COVERAGE,
        ring_profile_id="plain",
        resources=[],
        steps=[
            SymbolicStep(
                step_id="step_a",
                ordinal=0,
                operation="nop",
                ring_ref="plain",
                arguments=[],
                flags=[],
                link_mode=LinkMode.NONE,
                expected_result_classes=["success"],
            )
        ],
        perturbations=[],
        requested_local_variants=1,
        expected_signals=["The exact canonical no-op is accepted."],
        safety_notes=["No live fleet path is reachable."],
    )


def _digest(model) -> str:
    return content_digest(canonical_json(model.model_dump(mode="json")))


def _authority(tmp_path: Path):
    contract = _contract()
    program = _program()
    proposal = PlannerProposal(
        schema_version="planner-proposal.v1",
        proposal_id="proposal:validation-probe",
        packet_id="packet:validation-probe",
        target_hashes=contract.target_hashes,
        hypothesis=Hypothesis(
            claim="A canonical no-op can validate the deterministic handoff.",
            evidence_refs=["evidence:validation-probe"],
            expected_signal="The local codec returns identical bytes.",
        ),
        abstain=False,
        abstain_reason="",
        analysis_only=False,
        research_priorities=[],
        programs=[program],
    )
    reviewer = ReviewerVerdict(
        schema_version="reviewer-verdict.v1",
        review_id="review:validation-probe",
        proposal_id=proposal.proposal_id,
        packet_id=proposal.packet_id,
        verdict=VerdictKind.ACCEPT,
        summary="The bounded canonical no-op is suitable for deterministic validation.",
        findings=[],
        checked_evidence_refs=["evidence:validation-probe"],
        required_changes=[],
        residual_risk=ResidualRisk.LOW,
        safe_for_quarantine=True,
    )
    compiled = compile_program(program, contract)
    artifacts = ArtifactStore(tmp_path / "artifacts")
    manifest_digest, _, _ = artifacts.put(
        compiled,
        proposal_digest=_digest(proposal),
        program_digest=_digest(program),
        harness_contract_digest=_digest(contract),
        validator_version=VALIDATOR_VERSION,
        validator_hash=VALIDATOR_HASH,
        target_hashes=contract.target_hashes,
    )
    manifest = artifacts.get_manifest(manifest_digest)
    payload = artifacts.get_payload(manifest)
    envelope = QuarantineEnvelope(
        schema_version="quarantine-envelope.v1",
        envelope_id="env-validation-probe",
        created_at=NOW,
        promotion_state=PromotionState.QUARANTINED,
        human_approval_required=True,
        isolated_canary_required=True,
        telemetry_packet_hash="sha256:" + "5" * 64,
        proposal_hash=_digest(proposal),
        reviewer_verdict_hash=_digest(reviewer),
        auditor_verdict_hash=None,
        harness_contract_hash=_digest(contract),
        compiled_artifact_hashes=[manifest_digest],
        target_hashes=contract.target_hashes,
        proposal=proposal,
        reviewer_verdict=reviewer,
        auditor_verdict=None,
        validations=[
            ValidationRecord(
                validator_version=VALIDATOR_VERSION,
                validator_hash=VALIDATOR_HASH,
                passed_check_ids=["preflight.test"],
                failed_check_ids=[],
            )
        ],
        provider_traces=[
            ProviderTrace(
                role=ProviderRole.PLANNER,
                provider="openai",
                model="gpt-5.6-sol",
                response_id="response-planner",
                client_request_id="planner-validation",
                input_tokens=1,
                output_tokens=1,
                reasoning_tokens=0,
                cost_microusd=1,
            ),
            ProviderTrace(
                role=ProviderRole.REVIEWER,
                provider="anthropic",
                model="claude-sonnet-5",
                response_id="response-reviewer",
                client_request_id="reviewer-validation",
                input_tokens=1,
                output_tokens=1,
                reasoning_tokens=0,
                cost_microusd=1,
            ),
        ],
    )
    envelope_digest = _digest(envelope)
    return artifacts, envelope, envelope_digest, manifest, manifest_digest, payload


def test_validation_report_rechecks_and_stores_every_authority(tmp_path: Path) -> None:
    (
        _,
        envelope,
        envelope_digest,
        manifest,
        manifest_digest,
        payload,
    ) = _authority(tmp_path)
    report = build_validation_report(
        envelope_digest=envelope_digest,
        envelope=envelope,
        artifact_manifest_digest=manifest_digest,
        manifest=manifest,
        payload=payload,
        created_at=NOW,
    )
    assert report.valid is True
    assert report.decode_reencode_equal is True
    assert report.live_fleet_touched is False
    assert report.failed_check_ids == []
    store = ExecutionAuthorityStore(tmp_path / "execution")
    digest, _ = store.put_validation(report)
    assert store.get_validation(digest) == report


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("envelope_digest", "sha256:" + "a" * 64, "envelope digest"),
        ("artifact_manifest_digest", "sha256:" + "b" * 64, "manifest digest"),
    ],
)
def test_validation_report_rejects_authority_digest_drift(
    tmp_path: Path,
    field: str,
    value: str,
    message: str,
) -> None:
    (
        _,
        envelope,
        envelope_digest,
        manifest,
        manifest_digest,
        payload,
    ) = _authority(tmp_path)
    arguments = {
        "envelope_digest": envelope_digest,
        "envelope": envelope,
        "artifact_manifest_digest": manifest_digest,
        "manifest": manifest,
        "payload": payload,
        "created_at": NOW,
    }
    arguments[field] = value
    with pytest.raises(ExecutionAuthorityError, match=message):
        build_validation_report(**arguments)


def test_validation_report_rejects_payload_mutation(tmp_path: Path) -> None:
    (
        _,
        envelope,
        envelope_digest,
        manifest,
        manifest_digest,
        payload,
    ) = _authority(tmp_path)
    with pytest.raises(ExecutionAuthorityError, match="payload digest"):
        build_validation_report(
            envelope_digest=envelope_digest,
            envelope=envelope,
            artifact_manifest_digest=manifest_digest,
            manifest=manifest,
            payload=payload + b"\x00",
            created_at=NOW,
        )


def test_execution_candidate_requires_exact_validation_canary_and_runner(
    tmp_path: Path,
) -> None:
    (
        _,
        envelope,
        envelope_digest,
        manifest,
        manifest_digest,
        payload,
    ) = _authority(tmp_path)
    validation = build_validation_report(
        envelope_digest=envelope_digest,
        envelope=envelope,
        artifact_manifest_digest=manifest_digest,
        manifest=manifest,
        payload=payload,
        created_at=NOW,
    )
    validation_digest = content_digest(
        canonical_json(validation.model_dump(mode="json"))
    )
    runner_hash = "sha256:" + "a" * 64
    snapshot = "sha256:" + "b" * 64
    canary = CanaryReport(
        report_id="canary-validation-probe",
        started_at="2026-07-17T12:00:01Z",
        finished_at="2026-07-17T12:00:02Z",
        envelope_digest=envelope_digest,
        validation_report_digest=validation_digest,
        artifact_manifest_digest=manifest_digest,
        artifact_digest=manifest.payload_digest,
        target_hashes=manifest.target_hashes,
        runner_hash=runner_hash,
        runner_result_digest="sha256:" + "c" * 64,
        outcome=CanaryOutcome.PASSED,
        exact_seed_dry_runs=1,
        executions_total=1,
        timeout_seconds=10,
        harness_accepted=True,
        infrastructure_error=False,
        runner_exit_code=0,
        timed_out=False,
        signal_number=0,
        fleet_snapshot_before=snapshot,
        fleet_snapshot_after=snapshot,
    )
    canary_digest = content_digest(canonical_json(canary.model_dump(mode="json")))
    candidate = build_execution_candidate(
        validation_report_digest=validation_digest,
        validation=validation,
        canary_report_digest=canary_digest,
        canary=canary,
        artifact_manifest_digest=manifest_digest,
        manifest=manifest,
        promotion_scope=PromotionScope(
            campaign_id="campaign:validation-probe",
            destination_id="native_ai_sync",
            worker_set=WorkerSet.NATIVE_STABLE,
        ),
        ready_at="2026-07-17T12:00:03Z",
        allowed_runner_hashes=frozenset({runner_hash}),
    )
    assert candidate.live_promotion_authorized is False
    with pytest.raises(ExecutionAuthorityError, match="not allowlisted"):
        build_execution_candidate(
            validation_report_digest=validation_digest,
            validation=validation,
            canary_report_digest=canary_digest,
            canary=canary,
            artifact_manifest_digest=manifest_digest,
            manifest=manifest,
            promotion_scope=candidate.promotion_scope,
            ready_at="2026-07-17T12:00:03Z",
            allowed_runner_hashes=frozenset(),
        )
