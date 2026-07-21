"""Exact, inert codec for the audited AFL/Nyx native harness byte grammar.

This module proves that a local, canonical representation can round-trip to the
byte stream consumed by one exact harness ELF.  It is intentionally not wired
to model output, human decisions, a canary, or the production corpus.

The four operand orders that are not portable from the C source alone are bound
to the independently audited ELF.  Any harness hash drift fails closed.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final, Iterable


AUDITED_HARNESS_HASH: Final[str] = (
    "sha256:cbdebc2ae149cde0f9b0482a980d539031c7ea493c3ec8c7ff46832a5c09c180"
)
RING_COUNT: Final[int] = 8
OPERATION_COUNT: Final[int] = 61
MAX_OPERATIONS: Final[int] = 96
MAX_INPUT_BYTES: Final[int] = 2048


class HarnessCodecError(ValueError):
    """The requested program is not canonical for the audited harness."""


@dataclass(frozen=True, slots=True)
class NativeOperation:
    """One local harness operation in exact parser read order.

    ``operands`` are deliberately opaque bytes.  Provider-facing contracts do
    not import this type and cannot select these values directly.
    """

    selector: int
    operands: tuple[int, ...]
    sqe_control: int


@dataclass(frozen=True, slots=True)
class NativeProgram:
    ring_selector: int
    operations: tuple[NativeOperation, ...]


# Encoder authority: names document the exact read order.  Cases 8, 39, 43 and
# 47 reflect the audited ELF, not an assumption about C argument evaluation.
_ENCODER_OPERAND_NAMES: Final[tuple[tuple[str, ...], ...]] = (
    (),
    ("fd",),
    ("fd",),
    ("fd", "length"),
    ("fd",),
    ("fd", "datasync"),
    ("fd",),
    ("user_data",),
    ("flags", "count"),
    ("user_data",),
    ("fd",),
    ("fd",),
    ("fd",),
    ("fd",),
    (),
    ("input_fd", "output_fd"),
    ("input_fd", "output_fd"),
    ("fd",),
    ("buffer_group",),
    ("buffer_group",),
    ("fd",),
    ("fd",),
    ("accept_flags",),
    (),
    ("fd",),
    ("fd",),
    ("fd", "backlog"),
    ("socket_type",),
    ("fd", "how"),
    ("fd",),
    ("fd",),
    ("fd",),
    ("fd",),
    ("fd", "zc_flags"),
    ("fd",),
    ("user_data",),
    ("fd", "cancel_flags"),
    ("timeout_flags",),
    ("user_data",),
    ("flags", "new_user_data", "old_user_data"),
    ("fd",),
    ("fd", "buffer_index"),
    ("fd", "buffer_index"),
    ("offset", "count"),
    ("fd",),
    ("file_index",),
    ("fd",),
    ("data", "length"),
    ("fd", "file_index"),
    (),
    ("expected_value",),
    (),
    (),
    (),
    ("unlink_flags",),
    (),
    (),
    ("fd",),
    ("fd", "length_units"),
    (),
    ("register_opcode", "register_count"),
)


# Decoder authority is intentionally expressed independently from the encoder
# names.  Round-trip tests compare the two complete grammars and all 61 golden
# single-operation vectors.
_DECODER_OPERAND_COUNTS: Final[tuple[int, ...]] = (
    0, 1, 1, 2, 1, 2, 1, 1, 2, 1,
    1, 1, 1, 1, 0, 2, 2, 1, 1, 1,
    1, 1, 1, 0, 1, 1, 2, 1, 2, 1,
    1, 1, 1, 2, 1, 1, 2, 1, 1, 3,
    1, 2, 2, 2, 1, 1, 1, 2, 2, 0,
    1, 0, 0, 0, 1, 0, 0, 1, 2, 0,
    2,
)


def operand_names(selector: int) -> tuple[str, ...]:
    """Return documented operand names in the audited parser's read order."""

    _require_int_byte(selector, "operation selector")
    if selector >= OPERATION_COUNT:
        raise HarnessCodecError("operation selector is not canonical")
    return _ENCODER_OPERAND_NAMES[selector]


def _require_hash(harness_hash: str) -> None:
    if harness_hash != AUDITED_HARNESS_HASH:
        raise HarnessCodecError("harness ELF hash is not the audited codec target")


def _require_int_byte(value: int, label: str) -> None:
    if type(value) is not int or not 0 <= value <= 255:
        raise HarnessCodecError(f"{label} must be an integer byte")


def _canonical_operation(operation: NativeOperation) -> bytes:
    _require_int_byte(operation.selector, "operation selector")
    if operation.selector >= OPERATION_COUNT:
        raise HarnessCodecError("operation selector is not canonical")
    expected = len(_ENCODER_OPERAND_NAMES[operation.selector])
    if len(operation.operands) != expected:
        raise HarnessCodecError("operation operand count does not match the audited grammar")
    for value in operation.operands:
        _require_int_byte(value, "operand")
    _require_int_byte(operation.sqe_control, "SQE control")
    return bytes((operation.selector, *operation.operands, operation.sqe_control))


def encode_program(program: NativeProgram, *, harness_hash: str) -> bytes:
    """Encode a complete canonical program for the exact audited ELF."""

    _require_hash(harness_hash)
    _require_int_byte(program.ring_selector, "ring selector")
    if program.ring_selector >= RING_COUNT:
        raise HarnessCodecError("ring selector is not canonical")
    if len(program.operations) > MAX_OPERATIONS:
        raise HarnessCodecError("program exceeds the harness operation maximum")

    payload = bytes((program.ring_selector,)) + b"".join(
        _canonical_operation(operation) for operation in program.operations
    )
    if len(payload) > MAX_INPUT_BYTES:
        raise HarnessCodecError("program exceeds the harness input byte maximum")
    return payload


def decode_program(payload: bytes, *, harness_hash: str) -> NativeProgram:
    """Strictly decode one complete canonical program without harness execution."""

    _require_hash(harness_hash)
    if type(payload) is not bytes:
        raise HarnessCodecError("payload must be immutable bytes")
    if not payload:
        raise HarnessCodecError("payload omits the ring selector")
    if len(payload) > MAX_INPUT_BYTES:
        raise HarnessCodecError("payload exceeds the harness input byte maximum")

    ring_selector = payload[0]
    if ring_selector >= RING_COUNT:
        raise HarnessCodecError("ring selector is not canonical")

    cursor = 1
    operations: list[NativeOperation] = []
    while cursor < len(payload):
        if len(operations) >= MAX_OPERATIONS:
            raise HarnessCodecError("payload exceeds the harness operation maximum")
        selector = payload[cursor]
        cursor += 1
        if selector >= OPERATION_COUNT:
            raise HarnessCodecError("payload contains a non-canonical operation selector")
        operand_count = _DECODER_OPERAND_COUNTS[selector]
        end = cursor + operand_count
        if end >= len(payload):
            raise HarnessCodecError("payload truncates operation operands or SQE control")
        operands = tuple(payload[cursor:end])
        sqe_control = payload[end]
        cursor = end + 1
        operations.append(
            NativeOperation(
                selector=selector,
                operands=operands,
                sqe_control=sqe_control,
            )
        )

    return NativeProgram(ring_selector=ring_selector, operations=tuple(operations))


def verify_round_trip(programs: Iterable[NativeProgram], *, harness_hash: str) -> None:
    """Fail unless each independently decoded encoding is exactly identical."""

    _require_hash(harness_hash)
    for program in programs:
        payload = encode_program(program, harness_hash=harness_hash)
        decoded = decode_program(payload, harness_hash=harness_hash)
        if decoded != program:
            raise HarnessCodecError("independent decoder round trip failed")


def verify_audited_codec() -> None:
    """Verify both complete grammar authorities with 61 canonical vectors."""

    if len(_ENCODER_OPERAND_NAMES) != OPERATION_COUNT:
        raise HarnessCodecError("encoder operation table is incomplete")
    if len(_DECODER_OPERAND_COUNTS) != OPERATION_COUNT:
        raise HarnessCodecError("decoder operation table is incomplete")
    programs: list[NativeProgram] = []
    for selector in range(OPERATION_COUNT):
        operands = tuple(
            (selector * 17 + index * 29) & 0xFF
            for index in range(len(_ENCODER_OPERAND_NAMES[selector]))
        )
        programs.append(
            NativeProgram(
                ring_selector=selector % RING_COUNT,
                operations=(
                    NativeOperation(
                        selector=selector,
                        operands=operands,
                        sqe_control=(selector * 7) & 0xFF,
                    ),
                ),
            )
        )
    verify_round_trip(programs, harness_hash=AUDITED_HARNESS_HASH)


__all__ = [
    "AUDITED_HARNESS_HASH",
    "HarnessCodecError",
    "MAX_INPUT_BYTES",
    "MAX_OPERATIONS",
    "NativeOperation",
    "NativeProgram",
    "decode_program",
    "encode_program",
    "operand_names",
    "verify_round_trip",
    "verify_audited_codec",
]
