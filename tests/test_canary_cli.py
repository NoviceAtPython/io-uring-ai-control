from __future__ import annotations

import hashlib
from pathlib import Path

from iou_ai.canary_cli import (
    _WORKER_SETS,
    _pending_envelopes,
    _record_attempt,
    _runner_hash,
    main,
)
from iou_ai.execution import WorkerSet
from iou_ai.quarantine import QuarantineStore


def test_pending_envelopes_selects_executable_unprocessed(tmp_path: Path) -> None:
    quarantine = QuarantineStore(tmp_path / "q")
    executable, _ = quarantine.put({"compiled_artifact_hashes": ["sha256:" + "a" * 64], "k": 1})
    analysis_only, _ = quarantine.put({"compiled_artifact_hashes": [], "k": 2})
    already_done, _ = quarantine.put({"compiled_artifact_hashes": ["sha256:" + "b" * 64], "k": 3})

    processed = tmp_path / "processed"
    processed.mkdir()
    (processed / f"{already_done}.done").touch()

    pending = set(_pending_envelopes(quarantine, processed))
    assert executable in pending
    assert analysis_only not in pending  # carries no compiled artifacts
    assert already_done not in pending  # already canaried


def test_flaky_reject_is_retried_but_retirement_is_bounded(tmp_path: Path) -> None:
    # The canary gate is non-deterministic (~29% harness stability), so a single
    # rejection must NOT retire a good artifact the paid planner produced -- that
    # would silently discard work. But a genuinely bad envelope must stop
    # consuming canary time eventually.
    quarantine = QuarantineStore(tmp_path / "q")
    envelope, _ = quarantine.put({"compiled_artifact_hashes": ["sha256:" + "c" * 64]})
    processed = tmp_path / "processed"

    for attempt in range(1, 4):
        assert envelope in set(_pending_envelopes(quarantine, processed, 4)), (
            f"still retryable after {attempt - 1} flaky rejects"
        )
        _record_attempt(processed, envelope, passed=False, max_attempts=4)

    # Fourth rejection exhausts the budget and retires it.
    _record_attempt(processed, envelope, passed=False, max_attempts=4)
    assert envelope not in set(_pending_envelopes(quarantine, processed, 4))
    assert (processed / f"{envelope}.done").exists()


def test_canary_pass_retires_envelope_immediately(tmp_path: Path) -> None:
    quarantine = QuarantineStore(tmp_path / "q")
    envelope, _ = quarantine.put({"compiled_artifact_hashes": ["sha256:" + "d" * 64]})
    processed = tmp_path / "processed"

    _record_attempt(processed, envelope, passed=True, max_attempts=4)
    assert (processed / f"{envelope}.done").exists()
    assert envelope not in set(_pending_envelopes(quarantine, processed, 4))


def test_runner_hash_and_worker_set_mapping(tmp_path: Path) -> None:
    runner = tmp_path / "runner.sh"
    runner.write_bytes(b"#!/bin/sh\n")
    assert _runner_hash(runner) == "sha256:" + hashlib.sha256(b"#!/bin/sh\n").hexdigest()
    assert _WORKER_SETS["native_stable"] == (WorkerSet.NATIVE_STABLE, "native_ai_sync")
    assert _WORKER_SETS["kasan_triage"] == (WorkerSet.KASAN_TRIAGE, "kasan_ai_sync")


def test_main_fails_closed_without_config(tmp_path: Path) -> None:
    rc = main(
        [
            "--config",
            str(tmp_path / "absent.toml"),
            "--runner",
            str(tmp_path / "absent.sh"),
            "--campaign",
            "ai-io-uring",
        ]
    )
    assert rc == 2
