from __future__ import annotations

from iou_ai.harness_codec import AUDITED_HARNESS_HASH, encode_program, NativeOperation, NativeProgram
from iou_ai.repro import decode_executed, format_trace, operation_family


def test_lenient_decode_wraps_like_the_harness_not_the_strict_codec() -> None:
    # Arbitrary AFL bytes: ring 200 % 8 == 0, op 100 % 61 == 39 (a 3-operand op).
    # The strict codec would reject these; the harness (and this triage) wraps.
    payload = bytes([200, 100, 1, 2, 3, 0xAB])  # ring, sel, 3 operands, control
    decoded = decode_executed(payload)
    assert decoded.ring == 0
    assert len(decoded.ops) == 1
    op = decoded.ops[0]
    assert op.selector == 39
    assert len(op.operands) == 3
    assert op.control == 0xAB
    assert op.buffer_group == 0xA  # 0xAB >> 4
    assert op.flag_nibble == 0xB


def test_decode_matches_a_known_canonical_program() -> None:
    # Encode a real 2-op program via the audited codec, then confirm triage reads
    # the same ring and operation selectors back out of the bytes.
    prog = NativeProgram(
        ring_selector=3,
        operations=(
            NativeOperation(selector=1, operands=(7,), sqe_control=0x10),
            NativeOperation(selector=36, operands=(9, 4), sqe_control=0x22),
        ),
    )
    payload = encode_program(prog, harness_hash=AUDITED_HARNESS_HASH)
    decoded = decode_executed(payload)
    assert decoded.ring == 3
    assert [o.selector for o in decoded.ops] == [1, 36]
    assert decoded.ops[1].operands[0][0] in ("fd", "user_data")  # named operands
    assert decoded.ops[1].buffer_group == 0x2


def test_truncated_trailing_op_is_not_counted() -> None:
    # An operation without its trailing SQE-control byte is not fully formed.
    payload = bytes([0, 3, 5])  # sel 3 needs 2 operands + control; only 1 operand
    decoded = decode_executed(payload)
    assert decoded.ops == ()


def test_family_labels_cover_the_ranges() -> None:
    assert operation_family(0) == "nop/ring-setup"
    assert operation_family(37) == "cancel/link/timeout"
    assert operation_family(47) == "msg_ring"
    assert operation_family(60) == "io_uring_register"


def test_format_trace_is_readable_and_inert() -> None:
    payload = bytes([1, 36, 9, 4, 0x22, 47, 2, 0x11])
    text = format_trace(decode_executed(payload), source="crash-1")
    assert "crash-1" in text
    assert "cancel/link/timeout" in text or "msg_ring" in text
    # Never emits anything executable.
    assert "#include" not in text and "system(" not in text
