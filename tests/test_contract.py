from __future__ import annotations

from datetime import datetime, timezone
import hashlib
from pathlib import Path

import pytest

from iou_ai.contract import ContractBuildError, build_contract, write_contract
from iou_ai.models import HarnessContract, HarnessEnvironment


STAMP = "20260716T154444Z"


def _hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _write(path: Path, data: bytes) -> None:
    path.write_bytes(data)


def _authority(
    root: Path,
    *,
    stamp: str = STAMP,
    kasan_data: bytes | None = None,
) -> tuple[str, str]:
    source_data = b"audited harness source fixture\n"
    elf_data = b"audited harness elf fixture\n"
    kasan_data = elf_data if kasan_data is None else kasan_data

    source = root / f"io_uring_harness_native.{stamp}.c"
    _write(source, source_data)
    (root / f"io_uring_harness_native.{stamp}.sha256").write_text(
        f"{_hex(source_data)}  {source}\n", encoding="utf-8"
    )

    for flavor, data in (("native", elf_data), ("kasan", kasan_data)):
        prefix = root / f"iou_{flavor}.{stamp}"
        binary = root / f"{prefix.name}.elf001.bin"
        _write(binary, data)
        (root / f"{prefix.name}.elf001.sha256").write_text(
            f"{_hex(data)}  {binary}\n", encoding="utf-8"
        )
        (root / f"{prefix.name}.elf001.metadata.txt").write_text(
            "bounded metadata\n", encoding="utf-8"
        )
        (root / f"{prefix.name}.elf001.main.objdump.txt").write_text(
            "bounded disassembly evidence\n", encoding="utf-8"
        )
        (root / f"{prefix.name}.target.sha256").write_text(
            f"{_hex(data)}  /authority/{flavor}\n", encoding="utf-8"
        )
        (root / f"{prefix.name}.target.inventory.txt").write_text(
            f"live_qemu_references={'8' if flavor == 'native' else '2'}\n",
            encoding="utf-8",
        )
    return "sha256:" + _hex(source_data), "sha256:" + _hex(elf_data)


def test_builds_typed_hash_bound_production_contract(tmp_path: Path) -> None:
    source_hash, elf_hash = _authority(tmp_path)
    contract = build_contract(
        tmp_path,
        now=datetime(2026, 7, 16, 16, 0, tzinfo=timezone.utc),
        supported_source_hash=source_hash,
        supported_elf_hash=elf_hash,
    )

    assert contract.environment is HarnessEnvironment.PRODUCTION
    assert contract.verified is True
    assert contract.test_only is False
    assert contract.deterministic_compiler is True
    assert contract.decode_round_trip_verified is True
    assert contract.source_revision_hash == source_hash
    assert contract.target_hashes.harness_hash == elf_hash
    assert len(contract.profiles) == 8
    assert len(contract.operations) == 61
    assert [operation.selector_modulus_value for operation in contract.operations] == list(range(61))
    assert contract.contract_id.startswith("harness:production.typed.")
    assert contract.operations[0].arguments == []
    assert [argument.name for argument in contract.operations[8].arguments] == [
        "flags",
        "count",
    ]
    assert all(
        argument.byte_width == 1
        for operation in contract.operations
        for argument in operation.arguments
    )
    assert {operation.symbol for operation in contract.operations} >= {
        "timeout",
        "poll_update",
        "files_update",
        "msg_ring",
    }

    output = tmp_path / "contract.json"
    write_contract(output, contract)
    loaded = HarnessContract.model_validate_json(output.read_text(encoding="utf-8"))
    assert loaded == contract


def test_rejects_cross_lane_elf_drift(tmp_path: Path) -> None:
    source_hash, elf_hash = _authority(tmp_path, kasan_data=b"different kasan elf\n")
    with pytest.raises(ContractBuildError, match="do not share one harness ELF"):
        build_contract(
            tmp_path,
            supported_source_hash=source_hash,
            supported_elf_hash=elf_hash,
        )


def test_rejects_unreviewed_source_revision(tmp_path: Path) -> None:
    _, elf_hash = _authority(tmp_path)
    with pytest.raises(ContractBuildError, match="not the independently audited revision"):
        build_contract(
            tmp_path,
            supported_source_hash="sha256:" + "0" * 64,
            supported_elf_hash=elf_hash,
        )


def test_fleet_authority_ignores_snapshot_timestamp(tmp_path: Path) -> None:
    """A re-snapshot of identical target manifests must not revoke authority."""

    first = tmp_path / "first"
    second = tmp_path / "second"
    first.mkdir()
    second.mkdir()
    source_hash, elf_hash = _authority(first, stamp="20260716T154444Z")
    _authority(second, stamp="20260719T151352Z")

    first_contract = build_contract(
        first,
        now=datetime(2026, 7, 19, 15, 14, tzinfo=timezone.utc),
        supported_source_hash=source_hash,
        supported_elf_hash=elf_hash,
    )
    second_contract = build_contract(
        second,
        now=datetime(2026, 7, 19, 15, 15, tzinfo=timezone.utc),
        supported_source_hash=source_hash,
        supported_elf_hash=elf_hash,
    )

    assert (
        first_contract.target_hashes.fleet_config_hash
        == second_contract.target_hashes.fleet_config_hash
    )
