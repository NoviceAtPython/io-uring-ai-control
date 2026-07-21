"""Bounded, local-only operation-frequency profiling for AFL queue entries.

The profile is deliberately *not* coverage instrumentation and it never exports
seed contents, filenames, paths, command lines, or crash material.  It samples
only regular files from the numeric AFL worker ``queue`` directories, strictly
decodes canonical inputs against the audited grammar, and emits aggregate
operation-selector frequencies.  The unprivileged telemetry builder can turn
that small projection into evidence for the planner.
"""

from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
import json
import os
from pathlib import Path
import re
import stat
from typing import Iterable

from .harness_codec import (
    AUDITED_HARNESS_HASH,
    MAX_INPUT_BYTES,
    HarnessCodecError,
    decode_program,
)
from .models import HarnessContract
from .quarantine import canonical_json


PROFILE_VERSION = "corpus-operation-profile.v1"
_WORKER_RE = re.compile(r"^[0-9]{1,3}$")


class CorpusProfileError(RuntimeError):
    """A corpus profile could not be built without violating its bounds."""


@dataclass(frozen=True, slots=True)
class CorpusOperationProfile:
    schema_version: str
    status: str
    sampled_files: int
    readable_files: int
    canonical_inputs: int
    decoded_operations: int
    skipped_files: int
    least_observed_operations: tuple[str, ...]
    minimum_observations: int

    def document(self) -> dict[str, object]:
        result = asdict(self)
        result["least_observed_operations"] = list(self.least_observed_operations)
        return result


def _plain_directory(path: Path) -> bool:
    try:
        metadata = path.lstat()
    except OSError:
        return False
    return stat.S_ISDIR(metadata.st_mode) and not stat.S_ISLNK(metadata.st_mode)


def _read_seed(path: Path, *, max_bytes: int) -> bytes | None:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError:
        return None
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or not 1 <= metadata.st_size <= max_bytes:
            return None
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = -1
            payload = handle.read(max_bytes + 1)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    return payload if len(payload) <= max_bytes else None


def _queue_files(
    corpus_dir: Path,
    *,
    max_workers: int,
    max_per_worker: int,
) -> Iterable[Path]:
    if not _plain_directory(corpus_dir):
        raise CorpusProfileError("corpus root is unavailable")
    workers: list[Path] = []
    try:
        entries = tuple(corpus_dir.iterdir())
    except OSError as exc:
        raise CorpusProfileError("corpus root cannot be listed") from exc
    for candidate in entries:
        if _WORKER_RE.fullmatch(candidate.name) and _plain_directory(candidate):
            workers.append(candidate)
    for worker in sorted(workers, key=lambda item: int(item.name))[:max_workers]:
        queue = worker / "queue"
        if not _plain_directory(queue):
            continue
        try:
            files = tuple(queue.iterdir())
        except OSError:
            continue
        # Newer AFL names sort after older ones.  The bounded sample follows
        # current corpus behavior rather than its historical bootstrap seeds.
        selected = sorted(files, key=lambda item: item.name, reverse=True)[:max_per_worker]
        for candidate in selected:
            try:
                metadata = candidate.lstat()
            except OSError:
                continue
            if stat.S_ISREG(metadata.st_mode) and not stat.S_ISLNK(metadata.st_mode):
                yield candidate


def build_operation_profile(
    *,
    corpus_dir: str | Path,
    contract: HarnessContract,
    max_workers: int = 10,
    max_per_worker: int = 64,
    least_limit: int = 12,
) -> CorpusOperationProfile:
    """Build an aggregate profile, refusing unknown grammar authority.

    An unavailable codec/contract relationship is represented explicitly rather
    than guessing from raw bytes.  Callers may still export normal fleet
    telemetry, but must not treat this as operation-frequency evidence.
    """

    if not 1 <= max_workers <= 64 or not 1 <= max_per_worker <= 512:
        raise CorpusProfileError("corpus sampling bounds are invalid")
    if not 1 <= least_limit <= 24:
        raise CorpusProfileError("least-operation limit is invalid")
    symbols_by_selector = {
        operation.selector_modulus_value: operation.symbol
        for operation in contract.operations
    }
    if (
        contract.target_hashes.harness_hash != AUDITED_HARNESS_HASH
        or len(symbols_by_selector) != len(contract.operations)
        or set(symbols_by_selector) != set(range(len(contract.operations)))
    ):
        return CorpusOperationProfile(
            schema_version=PROFILE_VERSION,
            status="unavailable",
            sampled_files=0,
            readable_files=0,
            canonical_inputs=0,
            decoded_operations=0,
            skipped_files=0,
            least_observed_operations=(),
            minimum_observations=0,
        )

    counts = {symbol: 0 for symbol in symbols_by_selector.values()}
    sampled = readable = canonical = decoded = skipped = 0
    max_bytes = min(contract.input_max_bytes, MAX_INPUT_BYTES)
    for candidate in _queue_files(
        Path(corpus_dir), max_workers=max_workers, max_per_worker=max_per_worker
    ):
        sampled += 1
        payload = _read_seed(candidate, max_bytes=max_bytes)
        if payload is None:
            skipped += 1
            continue
        readable += 1
        try:
            program = decode_program(
                payload, harness_hash=contract.target_hashes.harness_hash
            )
        except HarnessCodecError:
            continue
        canonical += 1
        for operation in program.operations:
            counts[symbols_by_selector[operation.selector]] += 1
            decoded += 1

    least = tuple(
        name for _, name in sorted((count, name) for name, count in counts.items())[:least_limit]
    )
    minimum = min(counts.values(), default=0)
    return CorpusOperationProfile(
        schema_version=PROFILE_VERSION,
        status="available",
        sampled_files=sampled,
        readable_files=readable,
        canonical_inputs=canonical,
        decoded_operations=decoded,
        skipped_files=skipped,
        least_observed_operations=least,
        minimum_observations=minimum,
    )


def _write_atomic(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + f".tmp-{os.getpid()}")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o640)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Build a redacted operation-frequency profile from AFL queues"
    )
    parser.add_argument("--corpus-dir", type=Path, required=True)
    parser.add_argument("--contract", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--max-workers", type=int, default=10)
    parser.add_argument("--max-per-worker", type=int, default=64)
    args = parser.parse_args(argv)
    try:
        contract = HarnessContract.model_validate_json(
            args.contract.read_bytes(), strict=True
        )
        profile = build_operation_profile(
            corpus_dir=args.corpus_dir,
            contract=contract,
            max_workers=args.max_workers,
            max_per_worker=args.max_per_worker,
        )
        _write_atomic(args.output, canonical_json(profile.document()))
    except (CorpusProfileError, OSError, ValueError) as exc:
        print(f"blocked: {exc}")
        return 2
    print(profile.status)
    return 0


__all__ = [
    "CorpusOperationProfile",
    "CorpusProfileError",
    "PROFILE_VERSION",
    "build_operation_profile",
    "main",
]

