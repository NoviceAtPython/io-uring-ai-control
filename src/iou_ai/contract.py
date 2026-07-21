"""Build the hash-bound production contract for the audited native harness.

The contract exposes typed one-byte operands, not arbitrary payload bytes. The
only component allowed to turn those operands into a payload is the exact
compiler whose digest is embedded in ``target_hashes``.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import re
from typing import Iterable

from .models import (
    ByteOrder,
    HarnessArgumentKind,
    HarnessArgumentSpec,
    HarnessContract,
    HarnessEnvironment,
    HarnessFlagSpec,
    HarnessOperation,
    HarnessProfile,
    LaneKind,
    TargetHashes,
)
from .harness_codec import HarnessCodecError, operand_names, verify_audited_codec
from .quarantine import canonical_json


class ContractBuildError(RuntimeError):
    """The root authority snapshot does not match the audited deployment."""


SUPPORTED_SOURCE_HASH = (
    "sha256:64ba43a293ad00c1abb26fb3181ed8a24db2e59392382807466708b4625a5caf"
)
SUPPORTED_ELF_HASH = (
    "sha256:cbdebc2ae149cde0f9b0482a980d539031c7ea493c3ec8c7ff46832a5c09c180"
)

_STAMP_RE = re.compile(r"^\d{8}T\d{6}Z$")
_HEX_RE = re.compile(r"^[0-9a-f]{64}$")
_LANES = [LaneKind.STABLE_COVERAGE, LaneKind.PROBABILISTIC_RACE]

_PROFILES = (
    (
        "single_issuer_defer_coop",
        0,
        [
            "ioring_setup_single_issuer",
            "ioring_setup_defer_taskrun",
            "ioring_setup_coop_taskrun",
        ],
        "Single issuer with deferred and cooperative task work.",
    ),
    ("plain", 1, [], "Plain ring setup with no requested setup flags."),
    (
        "single_issuer_defer_cqsize",
        2,
        [
            "ioring_setup_single_issuer",
            "ioring_setup_defer_taskrun",
            "ioring_setup_cqsize",
        ],
        "Single issuer with deferred task work and an enlarged completion queue.",
    ),
    ("iopoll", 3, ["ioring_setup_iopoll"], "Polled I/O ring personality."),
    (
        "wide_sqe_cqe",
        4,
        ["ioring_setup_sqe128", "ioring_setup_cqe32"],
        "Ring with 128-byte submission entries and 32-byte completion entries.",
    ),
    (
        "clamp_submit_all_taskrun",
        5,
        [
            "ioring_setup_clamp",
            "ioring_setup_submit_all",
            "ioring_setup_taskrun_flag",
        ],
        "Clamped ring that submits all entries and reports task work.",
    ),
    (
        "no_sqarray_coop",
        6,
        ["ioring_setup_no_sqarray", "ioring_setup_coop_taskrun"],
        "Ring without a submission array and with cooperative task work.",
    ),
    (
        "disabled_until_register",
        7,
        ["ioring_setup_r_disabled"],
        "Ring initially disabled until a matching registration operation enables it.",
    ),
)

_FLAGS = (
    ("iosqe_fixed_file", 1, "Interpret the file descriptor as a registered-file index."),
    ("iosqe_io_drain", 2, "Defer this request until prior requests complete."),
    ("iosqe_io_link", 4, "Link this request to the next request."),
    ("iosqe_io_hardlink", 8, "Hard-link this request to the next request."),
    ("iosqe_async", 16, "Request asynchronous issue for this entry."),
    ("iosqe_buffer_select", 32, "Select a buffer from a registered buffer group."),
)

_OPERATION_SYMBOLS = (
    "nop",
    "readv",
    "writev",
    "read",
    "write",
    "fsync",
    "poll_add",
    "poll_remove",
    "timeout",
    "timeout_remove",
    "recv",
    "send",
    "fadvise",
    "fallocate",
    "openat",
    "splice",
    "tee",
    "epoll_ctl",
    "provide_buffers",
    "remove_buffers",
    "sync_file_range",
    "statx",
    "accept",
    "multishot_accept",
    "connect",
    "bind",
    "listen",
    "socket",
    "shutdown",
    "sendmsg",
    "recvmsg",
    "recvmsg_multishot",
    "recv_multishot",
    "send_zc",
    "sendmsg_zc",
    "cancel",
    "cancel_fd",
    "link_timeout",
    "timeout_update",
    "poll_update",
    "poll_multishot",
    "read_fixed",
    "write_fixed",
    "files_update",
    "fixed_fd_install",
    "close_direct",
    "close",
    "msg_ring",
    "msg_ring_fd",
    "futex_wake",
    "futex_wait",
    "futex_waitv",
    "waitid",
    "renameat",
    "unlinkat",
    "mkdirat",
    "linkat",
    "fsetxattr",
    "ftruncate",
    "epoll_wait",
    "register_raw",
)

_EXPECTED_RESULTS = [
    "success",
    "invalid",
    "retry",
    "short_io",
    "cancelled",
    "timeout",
    "not_supported",
    "resource_busy",
    "kernel_error",
]


def _digest_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _digest_file(path: Path) -> str:
    try:
        return _digest_bytes(path.read_bytes())
    except OSError as exc:
        raise ContractBuildError(f"authority artifact is unavailable: {path.name}") from exc


def _checksum(path: Path) -> str:
    try:
        token = path.read_text(encoding="utf-8").split()[0].lower()
    except (OSError, IndexError) as exc:
        raise ContractBuildError(f"checksum is unavailable or empty: {path.name}") from exc
    if not _HEX_RE.fullmatch(token):
        raise ContractBuildError(f"checksum is malformed: {path.name}")
    return "sha256:" + token


def _require(path: Path) -> Path:
    if not path.is_file():
        raise ContractBuildError(f"authority artifact is missing: {path.name}")
    return path


def _single(root: Path, pattern: str) -> Path:
    matches = sorted(root.glob(pattern))
    if len(matches) != 1:
        raise ContractBuildError(
            f"expected exactly one authority artifact matching {pattern!r}; found {len(matches)}"
        )
    return matches[0]


def _verified_file(checksum_path: Path) -> tuple[Path, str]:
    data_path = checksum_path.with_suffix(".bin")
    _require(data_path)
    declared = _checksum(checksum_path)
    actual = _digest_file(data_path)
    if declared != actual:
        raise ContractBuildError(f"authority checksum mismatch: {data_path.name}")
    return data_path, actual


def _profiles() -> list[HarnessProfile]:
    return [
        HarnessProfile(
            profile_id=profile_id,
            selector_value=selector,
            setup_flags=setup_flags,
            allowed_lanes=list(_LANES),
            summary=summary,
        )
        for profile_id, selector, setup_flags, summary in _PROFILES
    ]


def _flags() -> list[HarnessFlagSpec]:
    return [
        HarnessFlagSpec(symbol=symbol, bit_value=value, summary=summary)
        for symbol, value, summary in _FLAGS
    ]


def _operations() -> list[HarnessOperation]:
    profile_ids = [profile[0] for profile in _PROFILES]
    flag_ids = [flag[0] for flag in _FLAGS]
    return [
        HarnessOperation(
            symbol=symbol,
            selector_modulus_value=selector,
            arguments=[
                HarnessArgumentSpec(
                    name=name,
                    kind=HarnessArgumentKind.INTEGER,
                    byte_width=1,
                    signed=False,
                    byte_order=ByteOrder.LITTLE,
                    minimum_value=0,
                    maximum_value=255,
                    enum_symbols=[],
                    resource_kind="",
                    summary=(
                        f"Canonical one-byte {name.replace('_', ' ')} operand "
                        "in the audited ELF parser order."
                    ),
                )
                for name in operand_names(selector)
            ],
            allowed_flags=flag_ids,
            allowed_profiles=profile_ids,
            allowed_lanes=list(_LANES),
            expected_result_classes=list(_EXPECTED_RESULTS),
            summary=(
                f"Typed reference for the {symbol.replace('_', ' ')} operation "
                "family; opaque payload bytes remain unavailable."
            ),
        )
        for selector, symbol in enumerate(_OPERATION_SYMBOLS)
    ]


def _digest_map(paths: Iterable[Path]) -> dict[str, str]:
    return {path.name: _digest_file(_require(path)) for path in paths}


def _select_source(root: Path) -> tuple[Path, Path, str]:
    sources = sorted(root.glob("io_uring_harness_native.*.c"))
    if sources:
        source = sources[-1]
        stamp = source.name.removeprefix("io_uring_harness_native.").removesuffix(".c")
        checksum = source.with_suffix(".sha256")
    else:
        # The unprivileged authority handoff intentionally gives the source a
        # stable name while retaining stamped ELF evidence. Supporting that
        # shape lets an operator reproduce the contract without root access.
        source = root / "io_uring_harness_native.c"
        checksum = root / "io_uring_harness_native.sha256"
        _require(source)
        _require(checksum)
        native_stamps = {
            path.name.split(".")[1]
            for path in root.glob("iou_native.*.elf*.sha256")
            if len(path.name.split(".")) >= 4
        }
        kasan_stamps = {
            path.name.split(".")[1]
            for path in root.glob("iou_kasan.*.elf*.sha256")
            if len(path.name.split(".")) >= 4
        }
        common = sorted(native_stamps & kasan_stamps)
        if not common:
            raise ContractBuildError("authority handoff has no common native/KASAN stamp")
        stamp = common[-1]
    if not _STAMP_RE.fullmatch(stamp):
        raise ContractBuildError("latest harness source has an invalid authority stamp")
    return _require(source), _require(checksum), stamp


def build_contract(
    authority_dir: str | Path,
    *,
    now: datetime | None = None,
    supported_source_hash: str = SUPPORTED_SOURCE_HASH,
    supported_elf_hash: str = SUPPORTED_ELF_HASH,
) -> HarnessContract:
    """Build Gate A for one exact, independently audited authority snapshot."""

    root = Path(authority_dir)
    source, source_checksum, stamp = _select_source(root)
    declared_source_hash = _checksum(source_checksum)
    actual_source_hash = _digest_file(source)
    if declared_source_hash != actual_source_hash:
        raise ContractBuildError("harness source checksum does not match the snapshot")
    if actual_source_hash != supported_source_hash:
        raise ContractBuildError("harness source is not the independently audited revision")

    native_checksum = _single(root, f"iou_native.{stamp}.elf*.sha256")
    kasan_checksum = _single(root, f"iou_kasan.{stamp}.elf*.sha256")
    native_binary, native_hash = _verified_file(native_checksum)
    kasan_binary, kasan_hash = _verified_file(kasan_checksum)
    if native_hash != kasan_hash:
        raise ContractBuildError("native and KASAN lanes do not share one harness ELF")
    if native_hash != supported_elf_hash:
        raise ContractBuildError("live harness ELF is not the independently audited build")

    native_stem = native_checksum.name.removesuffix(".sha256")
    kasan_stem = kasan_checksum.name.removesuffix(".sha256")
    evidence_paths = [
        source,
        source_checksum,
        native_binary,
        native_checksum,
        _require(root / f"{native_stem}.metadata.txt"),
        _require(root / f"{native_stem}.main.objdump.txt"),
        kasan_binary,
        kasan_checksum,
        _require(root / f"{kasan_stem}.metadata.txt"),
        _require(root / f"{kasan_stem}.main.objdump.txt"),
        _require(root / f"iou_native.{stamp}.target.sha256"),
        _require(root / f"iou_native.{stamp}.target.inventory.txt"),
        _require(root / f"iou_kasan.{stamp}.target.sha256"),
        _require(root / f"iou_kasan.{stamp}.target.inventory.txt"),
    ]
    evidence = _digest_map(evidence_paths)
    evidence["contract_generator.py"] = _digest_file(Path(__file__))
    evidence["harness_codec.py"] = _digest_file(Path(__file__).with_name("harness_codec.py"))

    try:
        verify_audited_codec()
    except HarnessCodecError as exc:
        raise ContractBuildError("audited harness codec round trip failed") from exc

    operations = _operations()
    operation_material = [item.model_dump(mode="json") for item in operations]
    op_table_hash = _digest_bytes(canonical_json(operation_material))
    compiler_hash = _digest_file(Path(__file__).with_name("compiler.py"))
    # The authority snapshot uses timestamped filenames.  Those filenames are
    # evidence labels, not target configuration: hashing them here made a
    # harmless re-snapshot change ``fleet_config_hash`` and invalidated an
    # otherwise still-valid, human-approved candidate.  Bind the target
    # authority to the two manifest *contents* under stable logical names.
    # Both paths above are required before this point, so direct indexing also
    # makes a missing manifest fail closed rather than silently changing the
    # material being attested.
    fleet_material = {
        "native_target_manifest": evidence[f"iou_native.{stamp}.target.sha256"],
        "kasan_target_manifest": evidence[f"iou_kasan.{stamp}.target.sha256"],
    }
    fleet_config_hash = _digest_bytes(canonical_json(fleet_material))
    evidence_hash = _digest_bytes(
        canonical_json(
            {
                "authority_stamp": stamp,
                "artifacts": evidence,
                "semantic_op_table_hash": op_table_hash,
                "compiler_boundary_hash": compiler_hash,
            }
        )
    )

    generated = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    generated_at = generated.isoformat(timespec="seconds").replace("+00:00", "Z")
    return HarnessContract(
        schema_version="harness-contract.v1",
        contract_id=f"harness:production.typed.{stamp.lower()}",
        generated_at=generated_at,
        environment=HarnessEnvironment.PRODUCTION,
        verified=True,
        test_only=False,
        verified_by="verifier:codex.source_elf.audit.v1",
        verification_evidence_hash=evidence_hash,
        source_revision_hash=actual_source_hash,
        target_hashes=TargetHashes(
            harness_hash=native_hash,
            compiler_hash=compiler_hash,
            op_table_hash=op_table_hash,
            fleet_config_hash=fleet_config_hash,
        ),
        input_max_bytes=2048,
        operation_max_count=96,
        operation_selector_modulus=61,
        deterministic_compiler=True,
        decode_round_trip_verified=True,
        profiles=_profiles(),
        resources=[],
        flags=_flags(),
        operations=operations,
        forbidden_profile_ids=["sqpoll"],
        notes=[
            "Typed program planning is enabled only through the hash-bound deterministic compiler and independent decoder.",
            "Provider-visible operations omit source, paths, logs, credentials, crash traces, and opaque seed bytes.",
            "ELF-specific operand order for timeout, poll_update, files_update, and msg_ring is bound inside the inert local codec.",
            "Compiled artifacts remain quarantined until logical checks, isolated canarying, and an artifact-bound human execution approval pass.",
            "Ring setup personalities may fall back to a plain ring when the requested setup is unavailable.",
        ],
    )


def write_contract(path: str | Path, contract: HarnessContract) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    payload = canonical_json(contract.model_dump(mode="json"))
    temporary = destination.with_name(f".{destination.name}.tmp-{os.getpid()}")
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o640)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="iou-ai-contract",
        description="Build the hash-bound typed production harness contract",
    )
    parser.add_argument("--authority-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        contract = build_contract(args.authority_dir)
        write_contract(args.output, contract)
    except (ContractBuildError, OSError, ValueError) as exc:
        print(f"blocked: {exc}", file=os.sys.stderr)
        return 2
    print(
        f"installed typed contract {contract.contract_id}; "
        "compilation is hash-bound and live promotion remains disabled"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
