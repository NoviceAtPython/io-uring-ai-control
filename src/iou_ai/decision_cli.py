"""No-network importer for relay-signed human decision bundles."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

from pydantic import ValidationError

from .decisions import DecisionArchive, DecisionError, SignedDecision
from .events import EventOutbox
from .quarantine import canonical_json


def _bundles(root: Path):
    if not root.exists():
        return
    for path in sorted(root.iterdir(), key=lambda item: item.name):
        match = re.fullmatch(r"([0-9a-f]{64})\.json", path.name)
        if match is None:
            continue
        if path.is_symlink() or not path.is_file():
            raise DecisionError("decision inbox item is not a regular file")
        payload = path.read_bytes()
        if hashlib.sha256(payload).hexdigest() != match.group(1):
            raise DecisionError("decision inbox item digest mismatch")
        try:
            signed = SignedDecision.model_validate_json(payload, strict=True)
        except ValidationError as exc:
            raise DecisionError("decision inbox item is invalid") from exc
        if canonical_json(signed.model_dump(mode="json")) != payload:
            raise DecisionError("decision inbox item is not canonical")
        yield signed


def import_inbox(
    *, events: Path, inbox: Path, archive: Path, key_file: Path
) -> dict[str, int | str]:
    try:
        key = key_file.read_bytes().strip()
    except OSError as exc:
        raise DecisionError("decision verification credential is unavailable") from exc
    store = DecisionArchive(
        archive,
        events=EventOutbox(events),
        verification_key=key,
    )
    imported = 0
    skipped = 0
    for signed in _bundles(inbox):
        try:
            store.import_signed(signed)
            imported += 1
        except DecisionError:
            # A single terminal, un-archivable bundle (e.g. an approval that was
            # never archived and whose response window has since closed) must not
            # wedge the importer for every other valid decision in the inbox.
            # Skip it and continue; the count is surfaced in the result.
            skipped += 1
    return {"status": "verified", "bundles": imported, "skipped": skipped}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="iou-ai-decisions",
        description="Verify and archive signed human decisions without execution authority",
    )
    parser.add_argument("--events", type=Path, required=True)
    parser.add_argument("--inbox", type=Path, required=True)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--key-file", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        result = import_inbox(
            events=args.events,
            inbox=args.inbox,
            archive=args.archive,
            key_file=args.key_file,
        )
    except (DecisionError, OSError) as exc:
        print(f"blocked: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

