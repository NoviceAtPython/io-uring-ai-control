"""``iou-ai-repro``: decode a crash input into a human-readable operation trace.

Read-only and inert: it decodes bytes, it never executes them. Point it at a file
from ``nat_out/*/crashes/`` (or pass ``-`` to read stdin) to see the ring
personality and the exact operation sequence the harness ran, which is the first
step of turning a raw crash into a reportable finding.
"""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

from .harness_codec import MAX_INPUT_BYTES
from .repro import decode_executed, format_trace


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="iou-ai-repro",
        description="Decode a fuzzer crash input into a human-readable op trace (inert)",
    )
    parser.add_argument(
        "crash", help="path to a crash input file, or - for stdin"
    )
    parser.add_argument(
        "--hex", action="store_true", help="also print the raw bytes as hex"
    )
    args = parser.parse_args(argv)

    if args.crash == "-":
        data = sys.stdin.buffer.read()
    else:
        path = Path(args.crash)
        if not path.is_file():
            print(f"not a file: {path}", file=sys.stderr)
            return 2
        data = path.read_bytes()

    # The harness only ever reads its input cap; triage the same bytes it would.
    payload = data[:MAX_INPUT_BYTES]
    decoded = decode_executed(payload)
    print(format_trace(decoded, source=(None if args.crash == "-" else args.crash)))
    if args.hex:
        print("# hex:")
        print(payload.hex())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
