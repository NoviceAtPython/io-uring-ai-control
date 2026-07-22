"""Crash triage: explain a raw fuzzer input the way the guest harness runs it.

This is the portable half of the repro lane. It never executes anything -- it
only decodes bytes into a human-readable operation trace so a crash can be
understood and, on the host, minimized and turned into a reproducer.

Two decoders exist for the same grammar. ``harness_codec`` is STRICT: it rejects
any non-canonical byte stream and is used to prove the compiler's authority. The
in-guest harness is LENIENT: it takes ``ring % RING_COUNT`` and
``op % OPERATION_COUNT`` and consumes operand/control bytes until the input runs
out. A real crashing input from AFL is arbitrary bytes, so triage must mirror the
lenient parse to show what actually ran. Operand read order is taken from the
audited codec, so the per-operation fields are the same ones the compiler binds.
"""

from __future__ import annotations

from dataclasses import dataclass

from .harness_codec import OPERATION_COUNT, RING_COUNT, operand_names


def operation_family(selector: int) -> str:
    """Coarse operation family from the harness selector layout.

    Ranges follow the documented harness op groups. This labels for triage; it
    does not assert a specific IORING_OP constant (the exact opcode mapping lives
    in the harness ELF).
    """

    if selector == 0:
        return "nop/ring-setup"
    if 1 <= selector <= 21:
        return "file-io"
    if 22 <= selector <= 34:
        return "socket"
    if 35 <= selector <= 40:
        return "cancel/link/timeout"
    if 41 <= selector <= 46:
        return "fixed-io/registered"
    if 47 <= selector <= 48:
        return "msg_ring"
    if 49 <= selector <= 52:
        return "futex/waitid"
    if 53 <= selector <= 58:
        return "path/xattr"
    if selector == 60:
        return "io_uring_register"
    return "other"


@dataclass(frozen=True, slots=True)
class DecodedOp:
    index: int
    selector: int
    family: str
    operands: tuple[tuple[str, int], ...]
    control: int
    buffer_group: int  # control >> 4 (verified)
    flag_nibble: int  # control & 0xF; exact IOSQE mapping is contract-defined


@dataclass(frozen=True, slots=True)
class DecodedInput:
    ring: int
    ops: tuple[DecodedOp, ...]
    total_bytes: int
    consumed_bytes: int  # trailing bytes the harness would not reach are total-consumed


def decode_executed(payload: bytes) -> DecodedInput:
    """Mirror the harness's lenient parse: ring % 8, op % 61, consume to EOF."""

    if not payload:
        return DecodedInput(ring=0, ops=(), total_bytes=0, consumed_bytes=0)
    ring = payload[0] % RING_COUNT
    ops: list[DecodedOp] = []
    cursor = 1
    n = len(payload)
    while cursor < n:
        selector = payload[cursor] % OPERATION_COUNT
        cursor += 1
        names = operand_names(selector)
        operands: list[tuple[str, int]] = []
        truncated = False
        for name in names:
            if cursor >= n:
                truncated = True
                break
            operands.append((name, payload[cursor]))
            cursor += 1
        if truncated or cursor >= n:
            # The harness needs a trailing SQE-control byte; without it the op is
            # not fully formed and is not counted.
            break
        control = payload[cursor]
        cursor += 1
        ops.append(
            DecodedOp(
                index=len(ops),
                selector=selector,
                family=operation_family(selector),
                operands=tuple(operands),
                control=control,
                buffer_group=control >> 4,
                flag_nibble=control & 0x0F,
            )
        )
    return DecodedInput(
        ring=ring, ops=tuple(ops), total_bytes=n, consumed_bytes=cursor
    )


def format_trace(decoded: DecodedInput, *, source: str | None = None) -> str:
    """A compact, human-readable triage trace for a crash input."""

    lines: list[str] = []
    if source is not None:
        lines.append(f"# crash input: {source}")
    lines.append(
        f"# {decoded.total_bytes} bytes, {len(decoded.ops)} operation(s), "
        f"ring personality {decoded.ring}"
    )
    for op in decoded.ops:
        args = ", ".join(f"{name}={value}" for name, value in op.operands) or "-"
        flags = f"flags=0x{op.flag_nibble:x}"
        if op.family in ("fixed-io/registered", "msg_ring") or op.buffer_group:
            flags += f" buf_group={op.buffer_group}"
        lines.append(
            f"  [{op.index:2d}] sel={op.selector:<2d} {op.family:<20s} {args}  ({flags})"
        )
    if not decoded.ops:
        lines.append("  (no fully-formed operations decoded)")
    return "\n".join(lines)
