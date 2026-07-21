"""Isolated Nyx canary orchestration.

Proves that exactly one compiled candidate seed runs cleanly in a throwaway,
resource-bounded Nyx/QEMU job before it can ever be promoted to the live fleet.

This module does not itself boot a VM. It invokes a separate, root-owned runner
(the only component with the Nyx toolchain), measures the outcome, confirms the
live AFL/Nyx worker set is untouched, and emits a signed ``CanaryReport`` bound
to the exact artifact and validation digests. It has no network client, no
provider adapter, and no model-visible path. The runner is addressed only by a
hash that a root-owned destination policy must allowlist.

Runner contract (the box-side job must satisfy this exactly):
  invocation : ``<runner_command...> <seed_path>``
  stdout     : one JSON object with keys
                 executions_total    int   >= 0
                 harness_accepted    bool  (harness consumed the payload and
                                            returned to its loop without abort)
                 timed_out           bool  (seed made the guest exceed the
                                            per-seed timeout -- a REJECT, clean)
                 signal_number       int   (guest/harness fatal signal, else 0)
                 infrastructure_error bool (VM/toolchain failure, not the seed)
  exit code  : 0 for a completed measurement (PASS or seed-REJECT); non-zero
               only for an infrastructure failure.
A guest crash (KASAN panic / harness abort) is a REJECT, not a PASS, and is
surfaced for human triage -- it may be a real bug, never an auto-promotion.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
from typing import Callable

from .execution import CanaryOutcome, CanaryReport, content_digest
from .models import TargetHashes


class CanaryRunError(RuntimeError):
    """The canary could not be orchestrated (never yields a PASS)."""


# A probe returning a stable digest of the live fleet's worker set. It must be
# invariant under normal fuzzing but change if the canary disturbs the fleet.
FleetProbe = Callable[[], str]


@dataclass(frozen=True, slots=True)
class RunnerResult:
    stdout: bytes
    exit_code: int
    timed_out: bool


# A runner takes the full argv and returns the raw measurement. Injectable so
# the orchestration is testable without the Nyx toolchain.
Runner = Callable[[list[str]], RunnerResult]


@dataclass(frozen=True, slots=True)
class CanaryBinding:
    """The exact authority digests one canary result must be stamped against."""

    envelope_digest: str
    validation_report_digest: str
    artifact_manifest_digest: str
    artifact_digest: str
    target_hashes: TargetHashes


@dataclass(frozen=True, slots=True)
class CanaryConfig:
    runner_command: tuple[str, ...]
    runner_path: Path
    timeout_seconds: int
    dry_runs: int
    outer_slack_seconds: int = 15

    def __post_init__(self) -> None:
        if not self.runner_command:
            raise CanaryRunError("canary runner command is empty")
        if not 1 <= self.timeout_seconds <= 120:
            raise CanaryRunError("canary timeout must be 1..120 seconds")
        if not 1 <= self.dry_runs <= 4:
            raise CanaryRunError("canary dry-run count must be 1..4")


def _timestamp(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise CanaryRunError("canary time must be timezone-aware")
    return (
        value.astimezone(timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )


def _runner_hash(path: Path) -> str:
    try:
        return content_digest(path.read_bytes())
    except OSError as exc:
        raise CanaryRunError("canary runner is unavailable") from exc


def fleet_pid_snapshot() -> str:
    """Default box probe: digest the live AFL/Nyx worker PID set.

    Long-running workers keep stable PIDs during normal fuzzing; the set only
    changes if the canary kills, restarts, or spawns a live worker. This proves
    the canary did not disturb the fleet without hashing the constantly-changing
    queue contents.
    """

    entries: list[str] = []
    for pattern in ("afl-fuzz", "qemu-system-x86"):
        completed = subprocess.run(
            ["pgrep", "-x", pattern],
            capture_output=True,
            text=True,
            check=False,
        )
        for pid in sorted(completed.stdout.split()):
            entries.append(f"{pattern}:{pid}")
    return content_digest(("|".join(sorted(entries)) or "empty").encode())


def _default_runner(timeout_seconds: int) -> Runner:
    def run(argv: list[str]) -> RunnerResult:
        try:
            completed = subprocess.run(
                argv,
                capture_output=True,
                timeout=timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return RunnerResult(stdout=b"", exit_code=-1, timed_out=True)
        return RunnerResult(
            stdout=completed.stdout,
            exit_code=completed.returncode,
            timed_out=False,
        )

    return run


def _parse_measurement(result: RunnerResult) -> dict[str, object]:
    """Parse the runner's single JSON line, failing closed to infra error."""

    if result.timed_out:
        return {
            "executions_total": 0,
            "harness_accepted": False,
            "timed_out": True,
            "signal_number": 0,
            "infrastructure_error": True,
        }
    try:
        document = json.loads(result.stdout.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return {
            "executions_total": 0,
            "harness_accepted": False,
            "timed_out": False,
            "signal_number": 0,
            "infrastructure_error": True,
        }
    if not isinstance(document, dict):
        return {
            "executions_total": 0,
            "harness_accepted": False,
            "timed_out": False,
            "signal_number": 0,
            "infrastructure_error": True,
        }
    return document


def _coerce_int(value: object, *, low: int, high: int) -> int | None:
    if type(value) is not int or not low <= value <= high:
        return None
    return value


def run_canary(
    *,
    binding: CanaryBinding,
    config: CanaryConfig,
    seed_path: str | Path,
    fleet_probe: FleetProbe = fleet_pid_snapshot,
    runner: Runner | None = None,
    now: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
) -> CanaryReport:
    """Run one isolated canary and emit a signed, digest-bound CanaryReport."""

    runner_hash = _runner_hash(config.runner_path)
    active_runner = runner or _default_runner(
        config.timeout_seconds + config.outer_slack_seconds
    )

    started = now()
    snapshot_before = fleet_probe()
    argv = [*config.runner_command, str(seed_path)]
    result = active_runner(argv)
    snapshot_after = fleet_probe()
    finished = now()

    measurement = _parse_measurement(result)
    runner_result_digest = content_digest(
        result.stdout
        or json.dumps(measurement, sort_keys=True).encode("utf-8")
    )

    executions_total = _coerce_int(
        measurement.get("executions_total"), low=0, high=1_000_000
    )
    signal_number = _coerce_int(measurement.get("signal_number"), low=0, high=128)
    harness_accepted = measurement.get("harness_accepted")
    timed_out = measurement.get("timed_out")
    infrastructure_error = measurement.get("infrastructure_error")

    malformed = (
        executions_total is None
        or signal_number is None
        or type(harness_accepted) is not bool
        or type(timed_out) is not bool
        or type(infrastructure_error) is not bool
    )
    if malformed:
        executions_total = 0
        signal_number = 0
        harness_accepted = False
        timed_out = False
        infrastructure_error = True

    if snapshot_before != snapshot_after:
        # A changed live worker set is never a normal outcome; the report model
        # cannot even represent it. Abort hard rather than emit anything.
        raise CanaryRunError(
            "canary disturbed the live fleet worker set; refusing to emit a report"
        )

    passed = (
        config.dry_runs >= 1
        and executions_total >= config.dry_runs
        and harness_accepted
        and not infrastructure_error
        and result.exit_code == 0
        and not timed_out
        and signal_number == 0
    )
    if infrastructure_error:
        outcome = CanaryOutcome.INFRASTRUCTURE_FAILURE
    elif passed:
        outcome = CanaryOutcome.PASSED
    else:
        outcome = CanaryOutcome.REJECTED

    report_id = "canary-" + hashlib.sha256(
        (runner_result_digest + binding.artifact_digest).encode()
    ).hexdigest()[:24]

    return CanaryReport(
        report_id=report_id,
        started_at=_timestamp(started),
        finished_at=_timestamp(finished),
        envelope_digest=binding.envelope_digest,
        validation_report_digest=binding.validation_report_digest,
        artifact_manifest_digest=binding.artifact_manifest_digest,
        artifact_digest=binding.artifact_digest,
        target_hashes=binding.target_hashes,
        runner_hash=runner_hash,
        runner_result_digest=runner_result_digest,
        outcome=outcome,
        exact_seed_dry_runs=config.dry_runs,
        executions_total=executions_total,
        timeout_seconds=config.timeout_seconds,
        harness_accepted=harness_accepted,
        infrastructure_error=infrastructure_error,
        runner_exit_code=max(-255, min(255, result.exit_code)),
        timed_out=timed_out,
        signal_number=signal_number,
        fleet_snapshot_before=snapshot_before,
        fleet_snapshot_after=snapshot_after,
        live_fleet_touched=False,
    )


__all__ = [
    "CanaryBinding",
    "CanaryConfig",
    "CanaryRunError",
    "CanaryReport",
    "Runner",
    "RunnerResult",
    "fleet_pid_snapshot",
    "run_canary",
]
