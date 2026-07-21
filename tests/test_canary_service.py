from __future__ import annotations

import hashlib
import json
from pathlib import Path

from iou_ai.canary import CanaryConfig, RunnerResult
from iou_ai.canary_service import CanaryBridge
from iou_ai.execution import CanaryOutcome, ExecutionAuthorityStore, PromotionScope, WorkerSet
from iou_ai.quarantine import QuarantineStore

from test_validation_authority import _authority


def _runner_setup(tmp_path: Path):
    runner = tmp_path / "nyx_canary_oneshot.sh"
    runner.write_text("#!/bin/sh\n# fake runner for the bridge test\n", encoding="utf-8")
    runner_hash = "sha256:" + hashlib.sha256(runner.read_bytes()).hexdigest()
    config = CanaryConfig(
        runner_command=("/bin/true",),
        runner_path=runner,
        timeout_seconds=30,
        dry_runs=1,
    )
    return config, frozenset({runner_hash})


def _runner(document: dict):
    def run(_argv):
        return RunnerResult(
            stdout=json.dumps(document).encode("utf-8"), exit_code=0, timed_out=False
        )

    return run


_PASS = _runner(
    {
        "executions_total": 3,
        "harness_accepted": True,
        "timed_out": False,
        "signal_number": 0,
        "infrastructure_error": False,
    }
)
_CRASH = _runner(
    {
        "executions_total": 1,
        "harness_accepted": False,
        "timed_out": False,
        "signal_number": 11,
        "infrastructure_error": False,
    }
)


def _bridge(tmp_path: Path, runner):
    artifacts, envelope, envelope_digest, _manifest, _manifest_digest, _payload = _authority(
        tmp_path
    )
    quarantine = QuarantineStore(tmp_path / "quarantine")
    hex_digest, _ = quarantine.put(envelope.model_dump(mode="json"))
    assert "sha256:" + hex_digest == envelope_digest
    config, allowed = _runner_setup(tmp_path)
    bridge = CanaryBridge(
        quarantine=quarantine,
        artifacts=artifacts,
        authority=ExecutionAuthorityStore(tmp_path / "execution"),
        canary_config=config,
        promotion_scope=PromotionScope(
            campaign_id="campaign:bridge-test",
            destination_id="native_ai_sync",
            worker_set=WorkerSet.NATIVE_STABLE,
        ),
        allowed_runner_hashes=allowed,
        fleet_probe=lambda: "sha256:" + "a" * 64,
        runner=runner,
    )
    return bridge, hex_digest


def test_clean_artifact_becomes_execution_candidate(tmp_path: Path) -> None:
    bridge, hex_digest = _bridge(tmp_path, _PASS)
    results = bridge.process_envelope(hex_digest)
    assert len(results) == 1
    result = results[0]
    assert result.outcome == "candidate_ready"
    assert result.candidate_digest is not None
    candidate = bridge.authority.get_candidate(result.candidate_digest)
    assert candidate.canary_outcome is CanaryOutcome.PASSED
    assert candidate.human_execution_approval_required is True
    assert candidate.live_promotion_authorized is False


def test_crashing_artifact_yields_no_candidate(tmp_path: Path) -> None:
    bridge, hex_digest = _bridge(tmp_path, _CRASH)
    results = bridge.process_envelope(hex_digest)
    assert len(results) == 1
    result = results[0]
    assert result.outcome == "rejected"
    assert result.candidate_digest is None
