"""Allowlist-only AFL++ fleet-stat aggregation into external-safe telemetry."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from statistics import median
from typing import Iterable

from .feedback import FeedbackError, load_prior_proposal_outcomes
from .models import HarnessContract, TelemetryPacket
from .quarantine import canonical_json


_INTEGER_KEYS = frozenset(
    {
        "start_time",
        "last_update",
        "run_time",
        "execs_done",
        "corpus_count",
        "paths_total",
        "corpus_favored",
        "pending_total",
        "saved_crashes",
        "saved_hangs",
        "total_tmouts",
        "edges_found",
        "cycles_wo_finds",
    }
)
_FLOAT_KEYS = frozenset({"execs_per_sec", "stability", "bitmap_cvg"})
_WORKER_RE = re.compile(r"^[0-9]{1,3}$")


class TelemetryError(RuntimeError):
    pass


def _parse_number(value: str, *, integer: bool) -> int | float:
    cleaned = value.strip().removesuffix("%").strip()
    if not cleaned or len(cleaned) > 40:
        raise ValueError("invalid numeric stat")
    return int(cleaned, 10) if integer else float(cleaned)


def parse_fuzzer_stats(path: Path) -> dict[str, int | float]:
    """Parse only known numeric keys; command lines and paths are never retained."""
    try:
        text = path.read_text(encoding="utf-8", errors="strict")
    except OSError as exc:
        raise TelemetryError("fuzzer stats are unreadable") from exc
    if len(text.encode("utf-8")) > 128 * 1024:
        raise TelemetryError("fuzzer stats exceed the local size limit")
    result: dict[str, int | float] = {}
    for line in text.splitlines():
        key, separator, value = line.partition(":")
        if not separator:
            continue
        key = key.strip()
        try:
            if key in _INTEGER_KEYS:
                result[key] = _parse_number(value, integer=True)
            elif key in _FLOAT_KEYS:
                result[key] = _parse_number(value, integer=False)
        except (ValueError, OverflowError) as exc:
            raise TelemetryError(f"invalid allowlisted stat: {key}") from exc
    for required in ("last_update", "execs_done", "execs_per_sec"):
        if required not in result:
            raise TelemetryError(f"required fuzzer stat is missing: {required}")
    return result


def load_worker_stats(directory: str | Path) -> list[tuple[int, dict[str, int | float]]]:
    root = Path(directory)
    workers: list[tuple[int, dict[str, int | float]]] = []
    for candidate in sorted(root.iterdir(), key=lambda item: item.name):
        if not candidate.is_dir() or not _WORKER_RE.fullmatch(candidate.name):
            continue
        stats_path = candidate / "fuzzer_stats"
        if stats_path.is_file():
            workers.append((int(candidate.name), parse_fuzzer_stats(stats_path)))
    if not workers:
        raise TelemetryError("no numeric worker fuzzer_stats files were found")
    return workers


def _int(stats: dict[str, int | float], *names: str) -> int:
    for name in names:
        value = stats.get(name)
        if isinstance(value, int) and not isinstance(value, bool):
            return max(value, 0)
    return 0


def _float(stats: dict[str, int | float], name: str) -> float:
    value = stats.get(name, 0.0)
    return max(float(value), 0.0)


def _lane_summary(
    lane: str,
    workers: list[tuple[int, dict[str, int | float]]],
) -> dict[str, object]:
    stability = [_float(stats, "stability") for _, stats in workers]
    median_stability = median(stability) if stability else 0.0
    return {
        "lane": lane,
        "workers_running": len(workers),
        "executions_total": sum(_int(stats, "execs_done") for _, stats in workers),
        "executions_per_second_milli": round(
            sum(_float(stats, "execs_per_sec") for _, stats in workers) * 1000
        ),
        "queue_entries": max(
            (_int(stats, "corpus_count", "paths_total") for _, stats in workers),
            default=0,
        ),
        "paths_new_in_window": 0,
        "novel_outcomes_in_window": 0,
        "timeout_count": max(
            (_int(stats, "saved_hangs", "total_tmouts") for _, stats in workers),
            default=0,
        ),
        "instability_ppm": round(max(0.0, 100.0 - median_stability) * 10_000),
    }


def _read_state(path: Path) -> dict[str, int]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    except (OSError, json.JSONDecodeError) as exc:
        raise TelemetryError("telemetry state is unreadable or invalid") from exc
    if not isinstance(value, dict):
        raise TelemetryError("telemetry state must be an object")
    result: dict[str, int] = {}
    for key in ("edges", "paths", "generated_epoch"):
        item = value.get(key)
        if isinstance(item, int) and item >= 0:
            result[key] = item
    return result


def _write_atomic(path: Path, payload: bytes, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + f".tmp-{os.getpid()}")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def load_lkml_evidence(state_dir: str | Path, *, limit: int = 8) -> list[dict[str, object]]:
    """Load only the collector's bounded structural JSON projections."""
    if not 0 <= limit <= 16:
        raise TelemetryError("LKML evidence limit must be between 0 and 16")
    root = Path(state_dir) / "evidence" / "sha256"
    if not root.exists() or limit == 0:
        return []
    candidates = sorted(
        root.glob("*/*.json"),
        key=lambda path: path.stat().st_mtime_ns,
        reverse=True,
    )[:limit]
    result: list[dict[str, object]] = []
    for path in candidates:
        try:
            if path.stat().st_size > 64 * 1024:
                raise TelemetryError("LKML evidence artifact exceeds size cap")
            item = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise TelemetryError("LKML evidence artifact is invalid") from exc
        if not isinstance(item, dict) or item.get("schema_version") != "lkml-evidence.v1":
            raise TelemetryError("LKML evidence artifact has the wrong schema")
        if item.get("trust") != "untrusted_public_input":
            raise TelemetryError("LKML evidence trust label is missing")
        digest = item.get("message_id_sha256")
        subject = item.get("subject")
        structural = item.get("structural_summary")
        public_url = item.get("public_url")
        paths = item.get("diff_file_paths")
        counts = item.get("diff_counts")
        if (
            not isinstance(digest, str)
            or not re.fullmatch(r"[0-9a-f]{64}", digest)
            or not isinstance(subject, str)
            or not isinstance(structural, str)
            or not isinstance(public_url, str)
            or not isinstance(paths, list)
            or not all(isinstance(value, str) for value in paths)
            or not isinstance(counts, dict)
        ):
            raise TelemetryError("LKML evidence fields are invalid")
        file_count = counts.get("files", 0)
        hunk_count = counts.get("hunks", 0)
        if not isinstance(file_count, int) or not isinstance(hunk_count, int):
            raise TelemetryError("LKML evidence counts are invalid")
        path_summary = ",".join(paths[:6]) if paths else "discussion-only"
        summary = (
            f"Untrusted public io-uring mail subject: {subject[:240]}; "
            f"{structural[:320]}; scoped_paths={path_summary[:180]}; url={public_url}"
        )
        summary = " ".join(summary.replace("\x00", " ").split())[:800]
        result.append(
            {
                "evidence_ref": "evidence:lkml-" + digest[:20],
                "kind": "kernel_patch" if file_count > 0 else "mail_thread",
                "summary": summary,
                "observation_count": max(1, hunk_count, file_count),
            }
        )
    return result


def load_corpus_operation_evidence(
    profile_path: str | Path,
    *,
    contract: HarnessContract,
) -> dict[str, object] | None:
    """Load a bounded, seed-free operation-frequency projection.

    The root exporter creates this projection from live AFL queues.  Treat it
    as an untrusted persisted boundary: its sole use is to tell the planner
    which *contract symbols* were least frequent in a bounded canonical sample.
    No profile is emitted when the codec was unavailable or no canonical inputs
    decoded, avoiding an unsupported "under-covered" claim.
    """

    path = Path(profile_path)
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError:
        # The operation profile is an optional optimization.  Its absence must
        # never suppress ordinary, already-sanitized fleet telemetry.
        return None
    except OSError as exc:
        raise TelemetryError("corpus operation profile is unavailable") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 32 * 1024:
            raise TelemetryError("corpus operation profile has invalid file bounds")
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = -1
            raw = handle.read(32 * 1024 + 1)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if len(raw) > 32 * 1024:
        raise TelemetryError("corpus operation profile exceeds its size bound")
    try:
        profile = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise TelemetryError("corpus operation profile is not valid JSON") from exc
    required = {
        "schema_version",
        "status",
        "sampled_files",
        "readable_files",
        "canonical_inputs",
        "decoded_operations",
        "skipped_files",
        "least_observed_operations",
        "minimum_observations",
    }
    if not isinstance(profile, dict) or set(profile) != required:
        raise TelemetryError("corpus operation profile has the wrong schema")
    numeric_names = required - {"schema_version", "status", "least_observed_operations"}
    if (
        profile["schema_version"] != "corpus-operation-profile.v1"
        or profile["status"] not in {"available", "unavailable"}
        or any(
            type(profile[name]) is not int or not 0 <= profile[name] <= 1_000_000
            for name in numeric_names
        )
        or not isinstance(profile["least_observed_operations"], list)
        or len(profile["least_observed_operations"]) > 24
        or not all(
            isinstance(name, str) and re.fullmatch(r"[a-z][a-z0-9_]*", name)
            for name in profile["least_observed_operations"]
        )
    ):
        raise TelemetryError("corpus operation profile has invalid fields")
    names = profile["least_observed_operations"]
    if len(names) != len(set(names)):
        raise TelemetryError("corpus operation profile repeats an operation")
    known = {operation.symbol for operation in contract.operations}
    if not set(names).issubset(known):
        raise TelemetryError("corpus operation profile names an unknown operation")
    if profile["status"] != "available":
        if any(profile[name] for name in numeric_names) or names:
            raise TelemetryError("unavailable corpus profile contains measurements")
        return None
    if (
        profile["canonical_inputs"] == 0
        or profile["decoded_operations"] == 0
        or not names
    ):
        return None
    if profile["readable_files"] > profile["sampled_files"] or profile["canonical_inputs"] > profile["readable_files"]:
        raise TelemetryError("corpus operation profile counters are inconsistent")
    display = ",".join(names)
    return {
        "evidence_ref": "evidence:fleet-corpus-operation-profile",
        "kind": "corpus_shape",
        "summary": (
            f"A bounded local sample decoded {profile['canonical_inputs']} canonical "
            f"inputs and {profile['decoded_operations']} operations. Least-observed "
            f"contract operations: {display}. This is operation-frequency evidence, "
            "not edge coverage."
        ),
        "observation_count": profile["canonical_inputs"],
    }


def build_packet(
    *,
    stats_dir: str | Path,
    contract: HarnessContract,
    state_file: str | Path,
    kernel_release: str,
    fleet_id: str = "fleet:umich-nyx",
    campaign_id: str = "campaign:io-uring",
    expected_workers: int = 10,
    native_workers: int = 8,
    now: datetime | None = None,
    extra_evidence: Iterable[dict[str, object]] = (),
    feedback_dir: str | Path | None = None,
    corpus_profile_path: str | Path | None = None,
) -> TelemetryPacket:
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    workers = load_worker_stats(stats_dir)
    previous = _read_state(Path(state_file))
    native = [item for item in workers if item[0] < native_workers]
    kasan = [item for item in workers if item[0] >= native_workers]
    newest_update = max(_int(stats, "last_update") for _, stats in workers)
    running = sum(
        1
        for _, stats in workers
        if current.timestamp() - _int(stats, "last_update") <= 20 * 60
    )
    paths = max(
        (_int(stats, "corpus_count", "paths_total") for _, stats in workers),
        default=0,
    )
    edges = max((_int(stats, "edges_found") for _, stats in workers), default=0)
    median_bitmap = median([_float(stats, "bitmap_cvg") for _, stats in workers])
    stable = _lane_summary("stable_coverage", native)
    race = _lane_summary("probabilistic_race", kasan)
    stable["paths_new_in_window"] = max(0, paths - previous.get("paths", paths))

    evidence: list[dict[str, object]] = [
        {
            "evidence_ref": "evidence:fleet-coverage-window",
            "kind": "coverage_delta",
            "summary": (
                f"The fleet recorded {max(0, edges - previous.get('edges', edges))} "
                "new aggregate edge identifiers since the previous sanitized snapshot."
            ),
            "observation_count": max(len(workers), 1),
        },
        {
            "evidence_ref": "evidence:fleet-stall-window",
            "kind": "stall_signal",
            "summary": (
                "The largest worker cycles-without-finds counter is "
                f"{max((_int(s, 'cycles_wo_finds') for _, s in workers), default=0)}."
            ),
            "observation_count": max(len(workers), 1),
        },
        {
            "evidence_ref": "evidence:fleet-corpus-shape",
            "kind": "corpus_shape",
            "summary": (
                f"The largest synchronized worker corpus count is {paths}; counts are "
                "not summed across synchronized workers."
            ),
            "observation_count": max(len(workers), 1),
        },
    ]
    if corpus_profile_path is not None:
        profile_evidence = load_corpus_operation_evidence(
            corpus_profile_path, contract=contract
        )
        if profile_evidence is not None:
            evidence.append(profile_evidence)
    evidence.extend(extra_evidence)
    if len(evidence) > 24:
        raise TelemetryError("more than 24 evidence summaries would be externalized")

    generated_at = current.isoformat().replace("+00:00", "Z")
    prior_epoch = previous.get("generated_epoch", int(current.timestamp()) - 3600)
    start = datetime.fromtimestamp(prior_epoch, timezone.utc)
    start_at = start.isoformat().replace("+00:00", "Z")
    duration = max(1, int(current.timestamp()) - prior_epoch)
    executions = sum(_int(stats, "execs_done") for _, stats in workers)
    crashes = max((_int(stats, "saved_crashes") for _, stats in workers), default=0)
    hangs = max((_int(stats, "saved_hangs") for _, stats in workers), default=0)
    try:
        prior_proposal_outcomes = (
            load_prior_proposal_outcomes(
                feedback_dir,
                target_hashes=contract.target_hashes,
                limit=12,
            )
            if feedback_dir is not None
            else []
        )
    except FeedbackError:
        # Feedback is an untrusted persisted boundary.  A mutated or malformed
        # object must stop packet generation rather than silently poisoning the
        # next planner request.
        raise TelemetryError("review feedback is invalid or unverifiable") from None

    data: dict[str, object] = {
        "schema_version": "telemetry.v1",
        "packet_id": "packet:" + current.strftime("%Y%m%dt%H%M%Sz").lower(),
        "packet_hash": "sha256:" + "0" * 64,
        "generated_at": generated_at,
        "fleet_id": fleet_id,
        "campaign_id": campaign_id,
        "kernel_release": kernel_release.strip()[:80],
        "target_hashes": contract.target_hashes.model_dump(mode="json"),
        "window": {
            "start_at": start_at,
            "end_at": generated_at,
            "duration_seconds": duration,
        },
        "fleet": {
            "workers_expected": expected_workers,
            "workers_running": running,
            "workers_stalled": max(0, expected_workers - running),
            "executions_total": executions,
            "executions_per_second_milli": round(
                sum(_float(stats, "execs_per_sec") for _, stats in workers) * 1000
            ),
            "queue_entries": paths,
            "favored_entries": max(
                (_int(stats, "corpus_favored") for _, stats in workers), default=0
            ),
            "pending_entries": max(
                (_int(stats, "pending_total") for _, stats in workers), default=0
            ),
        },
        "coverage": {
            "paths_total": paths,
            "paths_new_in_window": max(0, paths - previous.get("paths", paths)),
            "edges_total": edges,
            "edges_new_in_window": max(0, edges - previous.get("edges", edges)),
            "bitmap_density_ppm": round(min(median_bitmap, 100.0) * 10_000),
            "corpus_bytes_total": 0,
            "corpus_entry_bytes_p50": 0,
            "corpus_entry_bytes_p95": 0,
        },
        "lane_summaries": [stable, race],
        "outcome_classes": [
            {
                "outcome_class": "normal_completion",
                "count": max(0, executions - crashes - hangs),
                "reproducible_count": 0,
            },
            {
                "outcome_class": "saved_crash",
                "count": crashes,
                "reproducible_count": 0,
            },
            {
                "outcome_class": "saved_hang",
                "count": hangs,
                "reproducible_count": 0,
            },
        ],
        "evidence": evidence,
        "prior_proposal_outcomes": [
            item.model_dump(mode="json") for item in prior_proposal_outcomes
        ],
        "externalization": {
            "redaction_version": "redaction:v1",
            "sanitized_for_external_api": True,
            "contains_raw_logs": False,
            "contains_seed_bytes": False,
            "contains_source_code": False,
            "contains_filesystem_paths": False,
            "contains_usernames": False,
            "contains_credentials": False,
            "contains_crash_traces": False,
        },
    }
    hash_material = dict(data)
    hash_material.pop("packet_hash")
    data["packet_hash"] = "sha256:" + hashlib.sha256(
        canonical_json(hash_material)
    ).hexdigest()
    packet = TelemetryPacket.model_validate_json(json.dumps(data))
    _write_atomic(
        Path(state_file),
        canonical_json(
            {
                "edges": edges,
                "paths": paths,
                "generated_epoch": int(current.timestamp()),
                "latest_worker_update": newest_update,
            }
        ),
    )
    return packet


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build sanitized AFL telemetry")
    parser.add_argument("--stats-dir", type=Path, required=True)
    parser.add_argument("--contract", type=Path, required=True)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--kernel-release-file", type=Path, required=True)
    parser.add_argument("--lkml-state-dir", type=Path)
    parser.add_argument("--feedback-dir", type=Path)
    parser.add_argument("--corpus-profile", type=Path)
    args = parser.parse_args(argv)
    contract = HarnessContract.model_validate_json(
        args.contract.read_text(encoding="utf-8")
    )
    packet = build_packet(
        stats_dir=args.stats_dir,
        contract=contract,
        state_file=args.state,
        kernel_release=args.kernel_release_file.read_text(encoding="utf-8").strip(),
        extra_evidence=(
            load_lkml_evidence(args.lkml_state_dir)
            if args.lkml_state_dir is not None
            else ()
        ),
        feedback_dir=args.feedback_dir,
        corpus_profile_path=args.corpus_profile,
    )
    _write_atomic(args.output, canonical_json(packet.model_dump(mode="json")))
    print(packet.packet_id)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
