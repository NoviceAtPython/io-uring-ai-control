from __future__ import annotations

from datetime import datetime, timezone

import pytest

from iou_ai.compiler import (
    CompilationBlocked,
    compile_program,
    compiler_hash,
    status,
)
from iou_ai.contract import _flags, _operations, _profiles
from iou_ai.harness_codec import AUDITED_HARNESS_HASH
from iou_ai.models import (
    ArgumentValueKind,
    HarnessContract,
    HarnessEnvironment,
    LaneKind,
    LinkMode,
    PlannerProgram,
    SymbolicArgument,
    SymbolicStep,
    TargetHashes,
)


def _contract() -> HarnessContract:
    return HarnessContract(
        schema_version="harness-contract.v1",
        contract_id="harness:production.typed.test",
        generated_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
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
        notes=["Test contract bound to the production compiler and audited codec."],
    )


def _integer(name: str, value: int) -> SymbolicArgument:
    return SymbolicArgument(
        name=name,
        kind=ArgumentValueKind.INTEGER,
        integer_value=value,
        boolean_value=False,
        symbol_value="",
        resource_ref="",
    )


def _program(
    operation: str,
    arguments: list[SymbolicArgument],
    *,
    flags: list[str] | None = None,
) -> PlannerProgram:
    return PlannerProgram(
        program_id="compile_probe",
        objective="Exercise one canonical operation through the deterministic compiler.",
        lane=LaneKind.STABLE_COVERAGE,
        ring_profile_id="plain",
        resources=[],
        steps=[
            SymbolicStep(
                step_id="step_a",
                ordinal=0,
                operation=operation,
                ring_ref="plain",
                arguments=arguments,
                flags=flags or [],
                link_mode=LinkMode.NONE,
                expected_result_classes=["success"],
            )
        ],
        perturbations=[],
        requested_local_variants=1,
        expected_signals=["The canonical payload reaches the selected operation family."],
        safety_notes=["The artifact remains quarantined."],
    )


def test_compiler_requires_an_explicit_hash_bound_contract() -> None:
    assert status().enabled is False
    drifted = _contract().model_copy(
        update={
            "target_hashes": _contract().target_hashes.model_copy(
                update={"compiler_hash": "sha256:" + "0" * 64}
            )
        }
    )
    assert status(drifted).enabled is False
    with pytest.raises(CompilationBlocked):
        compile_program(_program("nop", []), drifted)


def test_nop_compiles_and_round_trips_to_exact_bytes() -> None:
    contract = _contract()
    assert status(contract).enabled is True
    compiled = compile_program(_program("nop", []), contract)
    assert compiled.payload == bytes((1, 0, 0))
    assert compiled.operation_count == 1
    assert compiled.compiler_hash == compiler_hash()


def test_elf_audited_operand_order_is_contract_order_not_json_order() -> None:
    contract = _contract()
    compiled = compile_program(
        _program(
            "poll_update",
            [
                _integer("old_user_data", 6),
                _integer("flags", 1),
                _integer("new_user_data", 2),
            ],
        ),
        contract,
    )
    assert compiled.payload == bytes((1, 39, 1, 2, 6, 0))


def test_compiler_rejects_non_byte_and_mismatched_argument_grammar() -> None:
    contract = _contract()
    with pytest.raises(CompilationBlocked, match="outside the canonical byte range"):
        compile_program(
            _program("read", [_integer("fd", 256), _integer("length", 64)]),
            contract,
        )
    with pytest.raises(CompilationBlocked, match="exactly match"):
        compile_program(_program("read", []), contract)
