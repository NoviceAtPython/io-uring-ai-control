"""Deterministic, hash-bound compiler for the audited native Nyx harness.

The provider-facing planner emits typed semantic IR.  This module is the only
bridge from that IR to native harness bytes.  It accepts no source, shell text,
paths, or opaque byte arrays.  Compilation is enabled only for a production
contract that is bound to this exact compiler file and the independently
audited harness ELF.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path

from .harness_codec import (
    AUDITED_HARNESS_HASH,
    NativeOperation,
    NativeProgram,
    decode_program,
    encode_program,
    operand_names,
    verify_audited_codec,
)
from .models import (
    ArgumentValueKind,
    HarnessArgumentKind,
    HarnessContract,
    HarnessEnvironment,
    PlannerProgram,
)


COMPILER_VERSION = "native-ir-compiler.v1"


class CompilationBlocked(RuntimeError):
    """A program or authority contract cannot safely produce native bytes."""


@dataclass(frozen=True, slots=True)
class CompilerStatus:
    enabled: bool
    reason: str
    compiler_hash: str


@dataclass(frozen=True, slots=True)
class CompiledProgram:
    """One canonical, independently decoded native payload."""

    program_id: str
    payload: bytes
    payload_hash: str
    operation_count: int
    compiler_hash: str
    harness_hash: str


def compiler_hash() -> str:
    """Digest the installed compiler implementation used by the contract."""

    return "sha256:" + hashlib.sha256(Path(__file__).read_bytes()).hexdigest()


def status(contract: HarnessContract | None = None) -> CompilerStatus:
    """Return whether one explicit contract authorizes deterministic emission."""

    digest = compiler_hash()
    if contract is None:
        return CompilerStatus(
            enabled=False,
            reason="an explicit hash-bound harness contract is required",
            compiler_hash=digest,
        )
    conditions = (
        contract.environment is HarnessEnvironment.PRODUCTION,
        contract.verified,
        not contract.test_only,
        contract.deterministic_compiler,
        contract.decode_round_trip_verified,
        contract.target_hashes.harness_hash == AUDITED_HARNESS_HASH,
        contract.target_hashes.compiler_hash == digest,
    )
    if not all(conditions):
        return CompilerStatus(
            enabled=False,
            reason=(
                "the contract is not a verified production contract for this "
                "exact compiler and audited harness ELF"
            ),
            compiler_hash=digest,
        )
    try:
        verify_audited_codec()
    except ValueError:
        return CompilerStatus(
            enabled=False,
            reason="the audited encoder/decoder proof failed",
            compiler_hash=digest,
        )
    return CompilerStatus(
        enabled=True,
        reason="verified production compiler and codec are hash-bound",
        compiler_hash=digest,
    )


def _integer_argument(value: object, *, label: str) -> int:
    if getattr(value, "kind", None) is not ArgumentValueKind.INTEGER:
        raise CompilationBlocked(f"{label} is not a byte-valued integer")
    integer = getattr(value, "integer_value", None)
    if type(integer) is not int or not 0 <= integer <= 255:
        raise CompilationBlocked(f"{label} is outside the canonical byte range")
    return integer


def _compile_native(
    program: PlannerProgram,
    contract: HarnessContract,
) -> NativeProgram:
    profiles = {profile.profile_id: profile for profile in contract.profiles}
    operations = {operation.symbol: operation for operation in contract.operations}
    flags = {flag.symbol: flag.bit_value for flag in contract.flags}

    profile = profiles.get(program.ring_profile_id)
    if profile is None or profile.selector_value >= 8:
        raise CompilationBlocked("program references a non-canonical ring profile")

    native_operations: list[NativeOperation] = []
    for step in program.steps:
        operation = operations.get(step.operation)
        if operation is None:
            raise CompilationBlocked("program references an unknown operation")
        selector = operation.selector_modulus_value
        if selector >= contract.operation_selector_modulus:
            raise CompilationBlocked("operation selector exceeds the contract modulus")

        expected_names = operand_names(selector)
        contract_names = tuple(argument.name for argument in operation.arguments)
        if contract_names != expected_names:
            raise CompilationBlocked(
                "operation arguments differ from the audited parser order"
            )
        provided = {argument.name: argument for argument in step.arguments}
        if set(provided) != set(expected_names):
            raise CompilationBlocked(
                "operation arguments do not exactly match the audited grammar"
            )
        for specification in operation.arguments:
            if (
                specification.kind is not HarnessArgumentKind.INTEGER
                or specification.byte_width != 1
                or specification.minimum_value != 0
                or specification.maximum_value != 255
            ):
                raise CompilationBlocked(
                    "operation contract contains a non-canonical operand specification"
                )
        operands = tuple(
            _integer_argument(
                provided[name],
                label=f"{program.program_id}.{step.step_id}.{name}",
            )
            for name in expected_names
        )

        control = 0
        for flag in step.flags:
            value = flags.get(flag)
            if value is None or value & ~0x3F:
                raise CompilationBlocked("step contains a non-canonical SQE flag")
            control |= value
        native_operations.append(
            NativeOperation(
                selector=selector,
                operands=operands,
                sqe_control=control,
            )
        )

    return NativeProgram(
        ring_selector=profile.selector_value,
        operations=tuple(native_operations),
    )


def compile_program(
    program: PlannerProgram,
    contract: HarnessContract,
) -> CompiledProgram:
    """Compile, decode independently, and re-encode one validated program."""

    compiler_status = status(contract)
    if not compiler_status.enabled:
        raise CompilationBlocked(compiler_status.reason)
    native = _compile_native(program, contract)
    payload = encode_program(
        native,
        harness_hash=contract.target_hashes.harness_hash,
    )
    decoded = decode_program(
        payload,
        harness_hash=contract.target_hashes.harness_hash,
    )
    if decoded != native:
        raise CompilationBlocked("independent decoder changed the native program")
    if (
        encode_program(
            decoded,
            harness_hash=contract.target_hashes.harness_hash,
        )
        != payload
    ):
        raise CompilationBlocked("encode-decode-encode byte equality failed")
    if len(payload) > contract.input_max_bytes:
        raise CompilationBlocked("compiled payload exceeds the contract byte limit")
    return CompiledProgram(
        program_id=program.program_id,
        payload=payload,
        payload_hash="sha256:" + hashlib.sha256(payload).hexdigest(),
        operation_count=len(native.operations),
        compiler_hash=compiler_status.compiler_hash,
        harness_hash=contract.target_hashes.harness_hash,
    )


__all__ = [
    "COMPILER_VERSION",
    "CompilationBlocked",
    "CompiledProgram",
    "CompilerStatus",
    "compile_program",
    "compiler_hash",
    "status",
]
