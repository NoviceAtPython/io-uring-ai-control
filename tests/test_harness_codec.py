from __future__ import annotations

import pytest

from iou_ai.harness_codec import (
    AUDITED_HARNESS_HASH,
    HarnessCodecError,
    NativeOperation,
    NativeProgram,
    decode_program,
    encode_program,
    operand_names,
    verify_audited_codec,
    verify_round_trip,
)


def _op(selector: int, *, control: int = 0x35) -> NativeOperation:
    operands = tuple((selector * 17 + index * 29) & 0xFF for index in range(len(operand_names(selector))))
    return NativeOperation(selector=selector, operands=operands, sqe_control=control)


def test_all_61_operation_golden_vectors_round_trip_independently() -> None:
    verify_audited_codec()
    programs = [NativeProgram(ring_selector=selector % 8, operations=(_op(selector),)) for selector in range(61)]
    verify_round_trip(programs, harness_hash=AUDITED_HARNESS_HASH)

    for selector, program in enumerate(programs):
        payload = encode_program(program, harness_hash=AUDITED_HARNESS_HASH)
        assert payload == bytes((selector % 8, selector, *program.operations[0].operands, 0x35))
        assert decode_program(payload, harness_hash=AUDITED_HARNESS_HASH) == program


def test_elf_specific_ambiguous_operand_orders_are_documented() -> None:
    assert operand_names(8) == ("flags", "count")
    assert operand_names(39) == ("flags", "new_user_data", "old_user_data")
    assert operand_names(43) == ("offset", "count")
    assert operand_names(47) == ("data", "length")


def test_multi_operation_program_round_trips_exactly() -> None:
    program = NativeProgram(
        ring_selector=7,
        operations=tuple(_op(selector, control=(selector * 7) & 0xFF) for selector in range(61)),
    )
    payload = encode_program(program, harness_hash=AUDITED_HARNESS_HASH)
    assert decode_program(payload, harness_hash=AUDITED_HARNESS_HASH) == program


@pytest.mark.parametrize(
    "payload",
    [
        b"",
        bytes((8,)),
        bytes((0, 61, 0)),
        bytes((0, 39, 1, 2, 3)),
        bytes((0, 0)),
    ],
)
def test_decoder_rejects_noncanonical_or_truncated_payloads(payload: bytes) -> None:
    with pytest.raises(HarnessCodecError):
        decode_program(payload, harness_hash=AUDITED_HARNESS_HASH)


def test_codec_rejects_hash_drift() -> None:
    program = NativeProgram(ring_selector=0, operations=(_op(0),))
    drift = "sha256:" + "0" * 64
    with pytest.raises(HarnessCodecError, match="not the audited codec target"):
        encode_program(program, harness_hash=drift)
    with pytest.raises(HarnessCodecError, match="not the audited codec target"):
        decode_program(b"\x00", harness_hash=drift)


def test_encoder_rejects_wrong_operand_count_and_non_integer_bytes() -> None:
    with pytest.raises(HarnessCodecError, match="operand count"):
        encode_program(
            NativeProgram(
                ring_selector=0,
                operations=(NativeOperation(selector=39, operands=(1, 2), sqe_control=0),),
            ),
            harness_hash=AUDITED_HARNESS_HASH,
        )
    with pytest.raises(HarnessCodecError, match="integer byte"):
        encode_program(
            NativeProgram(
                ring_selector=0,
                operations=(NativeOperation(selector=0, operands=(), sqe_control=True),),
            ),
            harness_hash=AUDITED_HARNESS_HASH,
        )


def test_operation_count_is_bounded() -> None:
    program = NativeProgram(ring_selector=0, operations=tuple(_op(0) for _ in range(97)))
    with pytest.raises(HarnessCodecError, match="operation maximum"):
        encode_program(program, harness_hash=AUDITED_HARNESS_HASH)

    payload = bytes((0,)) + bytes((0, 0)) * 97
    with pytest.raises(HarnessCodecError, match="operation maximum"):
        decode_program(payload, harness_hash=AUDITED_HARNESS_HASH)
