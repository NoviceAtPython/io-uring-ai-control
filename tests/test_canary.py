from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

import pytest

from iou_ai.canary import (
    CanaryBinding,
    CanaryConfig,
    CanaryRunError,
    RunnerResult,
    run_canary,
)
from iou_ai.execution import CanaryOutcome
from iou_ai.models import TargetHashes


def _d(seed: str) -> str:
    return "sha256:" + hashlib.sha256(seed.encode()).hexdigest()


def _binding() -> CanaryBinding:
    return CanaryBinding(
        envelope_digest=_d("env"),
        validation_report_digest=_d("val"),
        artifact_manifest_digest=_d("man"),
        artifact_digest=_d("art"),
        target_hashes=TargetHashes(
            harness_hash=_d("h"),
            compiler_hash=_d("c"),
            op_table_hash=_d("o"),
            fleet_config_hash=_d("f"),
        ),
    )


def _config(tmp_path: Path, *, dry_runs: int = 1) -> CanaryConfig:
    runner = tmp_path / "runner.sh"
    runner.write_text("#!/bin/sh\n# isolated nyx one-shot\n", encoding="utf-8")
    return CanaryConfig(
        runner_command=("/bin/true",),
        runner_path=runner,
        timeout_seconds=30,
        dry_runs=dry_runs,
    )


def _clock():
    times = iter(
        [
            datetime(2026, 7, 17, 8, 0, 0, tzinfo=timezone.utc),
            datetime(2026, 7, 17, 8, 0, 5, tzinfo=timezone.utc),
        ]
    )
    return lambda: next(times)


def _stable_probe():
    return "sha256:" + "a" * 64


def _runner_reporting(document: dict, *, exit_code: int = 0, timed_out: bool = False):
    def run(argv):
        return RunnerResult(
            stdout=json.dumps(document).encode("utf-8"),
            exit_code=exit_code,
            timed_out=timed_out,
        )

    return run


def test_clean_seed_passes(tmp_path: Path) -> None:
    report = run_canary(
        binding=_binding(),
        config=_config(tmp_path),
        seed_path=tmp_path / "seed.bin",
        fleet_probe=_stable_probe,
        runner=_runner_reporting(
            {
                "executions_total": 3,
                "harness_accepted": True,
                "timed_out": False,
                "signal_number": 0,
                "infrastructure_error": False,
            }
        ),
        now=_clock(),
    )
    assert report.outcome is CanaryOutcome.PASSED
    assert report.harness_accepted is True
    assert report.fleet_snapshot_before == report.fleet_snapshot_after
    assert report.artifact_digest == _binding().artifact_digest


def test_crashing_seed_is_rejected(tmp_path: Path) -> None:
    report = run_canary(
        binding=_binding(),
        config=_config(tmp_path),
        seed_path=tmp_path / "seed.bin",
        fleet_probe=_stable_probe,
        runner=_runner_reporting(
            {
                "executions_total": 1,
                "harness_accepted": False,
                "timed_out": False,
                "signal_number": 11,
                "infrastructure_error": False,
            }
        ),
        now=_clock(),
    )
    assert report.outcome is CanaryOutcome.REJECTED
    assert report.signal_number == 11


def test_seed_timeout_is_rejected(tmp_path: Path) -> None:
    report = run_canary(
        binding=_binding(),
        config=_config(tmp_path),
        seed_path=tmp_path / "seed.bin",
        fleet_probe=_stable_probe,
        runner=_runner_reporting(
            {
                "executions_total": 1,
                "harness_accepted": False,
                "timed_out": True,
                "signal_number": 0,
                "infrastructure_error": False,
            }
        ),
        now=_clock(),
    )
    assert report.outcome is CanaryOutcome.REJECTED
    assert report.timed_out is True


def test_malformed_runner_output_is_infrastructure_failure(tmp_path: Path) -> None:
    def runner(argv):
        return RunnerResult(stdout=b"not json at all", exit_code=0, timed_out=False)

    report = run_canary(
        binding=_binding(),
        config=_config(tmp_path),
        seed_path=tmp_path / "seed.bin",
        fleet_probe=_stable_probe,
        runner=runner,
        now=_clock(),
    )
    assert report.outcome is CanaryOutcome.INFRASTRUCTURE_FAILURE
    assert report.infrastructure_error is True


def test_fleet_disturbance_aborts_hard(tmp_path: Path) -> None:
    probes = iter(["sha256:" + "a" * 64, "sha256:" + "b" * 64])
    with pytest.raises(CanaryRunError):
        run_canary(
            binding=_binding(),
            config=_config(tmp_path),
            seed_path=tmp_path / "seed.bin",
            fleet_probe=lambda: next(probes),
            runner=_runner_reporting(
                {
                    "executions_total": 3,
                    "harness_accepted": True,
                    "timed_out": False,
                    "signal_number": 0,
                    "infrastructure_error": False,
                }
            ),
            now=_clock(),
        )
