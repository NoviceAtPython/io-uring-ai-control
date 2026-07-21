"""Root CLI: canary compiled quarantine artifacts into approval-ready candidates.

Runs as root because the isolated one-shot Nyx canary needs KVM. It reads the
shared controller paths (quarantine, artifacts, execution authority) from the
config, then runs the CanaryBridge on one or more quarantine envelopes that
carry compiled artifacts. It never promotes anything and never writes to the
live AFL/Nyx corpus.
"""

from __future__ import annotations

import argparse
from datetime import timedelta
import hashlib
import json
from pathlib import Path
import sys

from .artifacts import ArtifactStore
from .canary import CanaryConfig, CanaryRunError
from .canary_service import CanaryBridge, CanaryServiceError
from .config import AppConfig, ConfigError, load_config
from .events import EventOutbox, EventProjectionError, project_execution_ready
from .execution import ExecutionAuthorityStore, PromotionScope, WorkerSet
from .quarantine import QuarantineStore


# worker-set name -> (enum, promotion destination id)
_WORKER_SETS: dict[str, tuple[WorkerSet, str]] = {
    "native_stable": (WorkerSet.NATIVE_STABLE, "native_ai_sync"),
    "kasan_triage": (WorkerSet.KASAN_TRIAGE, "kasan_ai_sync"),
}


def _runner_hash(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _build_bridge(
    config: AppConfig,
    *,
    runner: Path,
    campaign: str,
    worker_set: str,
    dry_runs: int,
    timeout: int,
) -> CanaryBridge:
    worker_enum, destination_id = _WORKER_SETS[worker_set]
    authority_root = config.events.execution_candidate_dir.parent
    return CanaryBridge(
        quarantine=QuarantineStore(config.runtime.quarantine_dir),
        artifacts=ArtifactStore(config.runtime.artifact_dir),
        authority=ExecutionAuthorityStore(authority_root),
        canary_config=CanaryConfig(
            runner_command=("/bin/sh", str(runner)),
            runner_path=runner,
            timeout_seconds=timeout,
            dry_runs=dry_runs,
        ),
        promotion_scope=PromotionScope(
            campaign_id=campaign,
            destination_id=destination_id,
            worker_set=worker_enum,
        ),
        allowed_runner_hashes=frozenset({_runner_hash(runner)}),
    )


def _attempts(processed_dir: Path | None, hex_digest: str) -> int:
    if processed_dir is None:
        return 0
    try:
        return int((processed_dir / f"{hex_digest}.attempts").read_text().strip() or 0)
    except (OSError, ValueError):
        return 0


def _record_attempt(
    processed_dir: Path | None, hex_digest: str, *, passed: bool, max_attempts: int
) -> None:
    """Retire an envelope on success, else count the attempt and retire it only
    after ``max_attempts``.

    The canary gate is non-deterministic: harness stability is ~29%, so a
    perfectly good artifact is rejected a large fraction of the time. Retiring an
    envelope on a single rejection would silently discard artifacts the paid
    planner produced. Bounded retries keep a flaky reject recoverable while still
    guaranteeing a genuinely bad envelope stops consuming canary time.
    """

    if processed_dir is None:
        return
    processed_dir.mkdir(parents=True, exist_ok=True)
    if passed:
        (processed_dir / f"{hex_digest}.done").touch()
        return
    attempts = _attempts(processed_dir, hex_digest) + 1
    (processed_dir / f"{hex_digest}.attempts").write_text(str(attempts))
    if attempts >= max_attempts:
        (processed_dir / f"{hex_digest}.done").touch()


def _pending_envelopes(
    quarantine: QuarantineStore, processed_dir: Path | None, max_attempts: int = 4
):
    """Yield hex digests of quarantine envelopes that carry compiled artifacts
    and have not already been canaried (per a marker directory)."""

    for hex_digest, raw in quarantine.iter_verified():
        if not raw.get("compiled_artifact_hashes"):
            continue
        if processed_dir is not None and (processed_dir / f"{hex_digest}.done").exists():
            continue
        if _attempts(processed_dir, hex_digest) >= max_attempts:
            continue
        yield hex_digest


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="iou-ai-canary",
        description="Isolated-canary bridge: compiled artifacts -> execution candidates (root)",
    )
    parser.add_argument("--config", type=Path, default=Path("/etc/iou-ai/config.toml"))
    parser.add_argument(
        "--runner", type=Path, required=True, help="path to nyx_canary_oneshot.sh"
    )
    parser.add_argument("--campaign", required=True, help="promotion campaign identifier")
    parser.add_argument(
        "--worker-set", choices=sorted(_WORKER_SETS), default="native_stable"
    )
    parser.add_argument("--dry-runs", type=int, default=1, help="canary dry-run count (1-4)")
    parser.add_argument(
        "--timeout", type=int, default=90, help="per-seed canary timeout seconds (1-120)"
    )
    parser.add_argument(
        "--envelope",
        action="append",
        default=[],
        metavar="HEX",
        help="specific quarantine envelope hex digest (repeatable)",
    )
    parser.add_argument(
        "--scan",
        action="store_true",
        help="also process un-processed envelopes carrying compiled artifacts",
    )
    parser.add_argument(
        "--processed-dir",
        type=Path,
        default=None,
        help="marker directory of <hex>.done files for scan de-duplication",
    )
    parser.add_argument("--max", type=int, default=8, help="max envelopes per run in scan mode")
    parser.add_argument(
        "--max-attempts",
        type=int,
        default=4,
        help=(
            "retire an envelope after this many canary rejections (the gate is "
            "flaky under ~29%% harness stability, so one reject must not discard "
            "a good artifact)"
        ),
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        config = load_config(args.config)
    except (ConfigError, OSError) as exc:
        print(f"blocked: {exc}", file=sys.stderr)
        return 2
    if not args.runner.is_file():
        print(f"blocked: canary runner not found: {args.runner}", file=sys.stderr)
        return 2

    quarantine = QuarantineStore(config.runtime.quarantine_dir)
    targets: list[str] = list(args.envelope)
    if args.scan:
        pending = list(
            _pending_envelopes(quarantine, args.processed_dir, args.max_attempts)
        )
        targets.extend(pending[: max(0, args.max)])
    targets = list(dict.fromkeys(targets))  # de-dup, preserve order

    if not targets:
        print(json.dumps({"status": "no_pending_envelopes", "results": []}))
        return 0

    try:
        bridge = _build_bridge(
            config,
            runner=args.runner,
            campaign=args.campaign,
            worker_set=args.worker_set,
            dry_runs=args.dry_runs,
            timeout=args.timeout,
        )
    except (CanaryServiceError, ValueError) as exc:
        print(f"blocked: {exc}", file=sys.stderr)
        return 2

    results: list[dict[str, object]] = []
    disturbed = False
    for hex_digest in targets:
        passed = False
        try:
            for outcome in bridge.process_envelope(hex_digest):
                if outcome.outcome == "candidate_ready":
                    passed = True
                results.append(
                    {
                        "envelope": hex_digest,
                        "artifact": outcome.artifact_manifest_digest,
                        "outcome": outcome.outcome,
                        "candidate": outcome.candidate_digest,
                        "detail": outcome.detail,
                    }
                )
        except CanaryRunError as exc:
            # A live-fleet disturbance is critical; stop immediately. Deliberately
            # do NOT count this as an attempt: the envelope was never fairly tried.
            results.append({"envelope": hex_digest, "outcome": "aborted", "detail": str(exc)})
            disturbed = True
            break
        except CanaryServiceError as exc:
            results.append({"envelope": hex_digest, "outcome": "error", "detail": str(exc)})
            _record_attempt(
                args.processed_dir,
                hex_digest,
                passed=False,
                max_attempts=args.max_attempts,
            )
            continue
        _record_attempt(
            args.processed_dir, hex_digest, passed=passed, max_attempts=args.max_attempts
        )

    # Emit the redacted execution-ready approval event(s) for any candidate that
    # does not yet have an outstanding challenge. The unprivileged event-projector
    # cannot read the root-owned candidate authority tree, so the root canary --
    # which created those candidates -- projects them itself into the shared,
    # group-readable outbox, where the running notify timer delivers them. This
    # keeps the authority tree private and reuses the same tested projection the
    # projector uses for every other event kind. It must never abort the canary.
    execution_events = 0
    if config.events.enabled and not disturbed:
        try:
            emitted = project_execution_ready(
                config.events.execution_candidate_dir,
                EventOutbox(config.events.outbox_dir),
                decision_ttl=timedelta(minutes=config.events.decision_ttl_minutes),
            )
            execution_events = len(emitted)
        except (EventProjectionError, OSError) as exc:
            results.append({"outcome": "notify_projection_error", "detail": str(exc)})

    print(
        json.dumps(
            {
                "status": "aborted" if disturbed else "complete",
                "results": results,
                "execution_events_emitted": execution_events,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 3 if disturbed else 0


if __name__ == "__main__":
    raise SystemExit(main())
