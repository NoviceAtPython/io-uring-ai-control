"""Content-addressed, create-only shadow quarantine."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
from typing import Any


class QuarantineError(RuntimeError):
    pass


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def sha256_json(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


class QuarantineStore:
    """Writes immutable JSON envelopes; it never imports them into AFL."""

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)

    def put(self, envelope: dict[str, Any]) -> tuple[str, Path]:
        payload = canonical_json(envelope)
        digest = hashlib.sha256(payload).hexdigest()
        self.root.mkdir(parents=True, exist_ok=True)
        destination = self.root / f"{digest}.json"
        try:
            descriptor = os.open(
                destination,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o440,
            )
        except FileExistsError:
            existing = destination.read_bytes()
            if existing != payload:
                raise QuarantineError("digest collision or mutated quarantine item")
            return digest, destination
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
        except BaseException:
            destination.unlink(missing_ok=True)
            raise
        return digest, destination

    def get(self, digest: str, *, max_bytes: int = 2 * 1024 * 1024) -> dict[str, Any]:
        """Read one object only after binding its bytes to its filename digest.

        Quarantine data is an untrusted handoff boundary even though it was
        written locally.  Refuse traversal, symlinks, non-regular files,
        oversized objects, mutated bytes, and non-object JSON.
        """

        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise QuarantineError("invalid quarantine digest")
        if max_bytes <= 0:
            raise QuarantineError("max_bytes must be positive")
        path = self.root / f"{digest}.json"
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(path, flags)
        except OSError as exc:
            raise QuarantineError("quarantine object is unavailable") from exc
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode):
                raise QuarantineError("quarantine object is not a regular file")
            if metadata.st_size > max_bytes:
                raise QuarantineError("quarantine object exceeds the size limit")
            with os.fdopen(descriptor, "rb") as handle:
                descriptor = -1
                payload = handle.read(max_bytes + 1)
        finally:
            if descriptor >= 0:
                os.close(descriptor)
        if len(payload) > max_bytes:
            raise QuarantineError("quarantine object exceeds the size limit")
        if hashlib.sha256(payload).hexdigest() != digest:
            raise QuarantineError("quarantine object digest mismatch")
        try:
            value = json.loads(payload)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise QuarantineError("quarantine object is invalid JSON") from exc
        if not isinstance(value, dict):
            raise QuarantineError("quarantine object must be a JSON object")
        if canonical_json(value) != payload:
            raise QuarantineError("quarantine object is not canonical")
        return value

    def iter_verified(
        self, *, max_items: int = 1024, max_bytes: int = 2 * 1024 * 1024
    ):
        """Yield digest/object pairs in stable order after full verification."""

        if max_items <= 0:
            raise QuarantineError("max_items must be positive")
        if not self.root.exists():
            return
        count = 0
        for path in sorted(self.root.iterdir(), key=lambda item: item.name):
            match = re.fullmatch(r"([0-9a-f]{64})\.json", path.name)
            if match is None:
                continue
            count += 1
            if count > max_items:
                raise QuarantineError("quarantine item count exceeds the limit")
            digest = match.group(1)
            yield digest, self.get(digest, max_bytes=max_bytes)
