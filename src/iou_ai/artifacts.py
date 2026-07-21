"""Content-addressed compiled artifacts for pre-execution quarantine.

This store is intentionally separate from the live AFL/Nyx corpus.  It accepts
only bytes emitted by :mod:`iou_ai.compiler`, binds them to the proposal,
program, contract, validator, and target hashes, and writes immutable files.
Nothing in this module can execute or promote an artifact.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import stat
from typing import Annotated, Literal

from pydantic import Field

from .compiler import COMPILER_VERSION, CompiledProgram
from .models import Digest, Identifier, StrictModel, TargetHashes
from .quarantine import canonical_json


class ArtifactError(RuntimeError):
    """An artifact failed integrity, authority, or create-only storage checks."""


class ArtifactManifest(StrictModel):
    schema_version: Literal["compiled-artifact.v1"] = "compiled-artifact.v1"
    artifact_id: Identifier
    program_id: Identifier
    proposal_digest: Digest
    program_digest: Digest
    harness_contract_digest: Digest
    payload_digest: Digest
    payload_size_bytes: Annotated[int, Field(ge=1, le=2048)]
    operation_count: Annotated[int, Field(ge=1, le=96)]
    compiler_version: Literal["native-ir-compiler.v1"] = COMPILER_VERSION
    compiler_hash: Digest
    validator_version: Identifier
    validator_hash: Digest
    target_hashes: TargetHashes
    isolated_canary_required: Literal[True] = True
    live_promotion_authorized: Literal[False] = False


def _digest(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _read_regular(path: Path, *, max_bytes: int) -> bytes:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ArtifactError("artifact object is unavailable") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ArtifactError("artifact object is not a regular file")
        if metadata.st_size > max_bytes:
            raise ArtifactError("artifact object exceeds the size limit")
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = -1
            payload = handle.read(max_bytes + 1)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if len(payload) > max_bytes:
        raise ArtifactError("artifact object exceeds the size limit")
    return payload


def _create_only(path: Path, payload: bytes, *, mode: int) -> None:
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    except FileExistsError:
        existing = _read_regular(path, max_bytes=max(len(payload), 1))
        if existing != payload:
            raise ArtifactError("artifact digest collision or mutation")
        return
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


class ArtifactStore:
    """Immutable manifest/payload storage with no execution capability."""

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)
        self.payload_root = self.root / "payloads"
        self.manifest_root = self.root / "manifests"

    def put(
        self,
        compiled: CompiledProgram,
        *,
        proposal_digest: str,
        program_digest: str,
        harness_contract_digest: str,
        validator_version: str,
        validator_hash: str,
        target_hashes: TargetHashes,
    ) -> tuple[str, Path, Path]:
        if _digest(compiled.payload) != compiled.payload_hash:
            raise ArtifactError("compiled payload digest changed before storage")
        if compiled.harness_hash != target_hashes.harness_hash:
            raise ArtifactError("compiled payload targets a different harness")
        if compiled.compiler_hash != target_hashes.compiler_hash:
            raise ArtifactError("compiled payload targets a different compiler")
        if not 1 <= len(compiled.payload) <= 2048:
            raise ArtifactError("compiled payload size is outside the harness bound")
        if not 1 <= compiled.operation_count <= 96:
            raise ArtifactError("compiled operation count is outside the harness bound")

        manifest = ArtifactManifest(
            artifact_id="artifact-" + compiled.payload_hash[-24:],
            program_id=compiled.program_id,
            proposal_digest=proposal_digest,
            program_digest=program_digest,
            harness_contract_digest=harness_contract_digest,
            payload_digest=compiled.payload_hash,
            payload_size_bytes=len(compiled.payload),
            operation_count=compiled.operation_count,
            compiler_hash=compiled.compiler_hash,
            validator_version=validator_version,
            validator_hash=validator_hash,
            target_hashes=target_hashes,
        )
        manifest_payload = canonical_json(manifest.model_dump(mode="json"))
        manifest_digest = _digest(manifest_payload)

        self.payload_root.mkdir(parents=True, exist_ok=True)
        self.manifest_root.mkdir(parents=True, exist_ok=True)
        payload_path = self.payload_root / (
            compiled.payload_hash.removeprefix("sha256:") + ".bin"
        )
        manifest_path = self.manifest_root / (
            manifest_digest.removeprefix("sha256:") + ".json"
        )
        _create_only(payload_path, compiled.payload, mode=0o440)
        _create_only(manifest_path, manifest_payload, mode=0o440)
        return manifest_digest, manifest_path, payload_path

    @staticmethod
    def _read_regular(path: Path, *, max_bytes: int) -> bytes:
        return _read_regular(path, max_bytes=max_bytes)

    def get_manifest(self, digest: str) -> ArtifactManifest:
        if re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is None:
            raise ArtifactError("invalid manifest digest")
        path = self.manifest_root / f"{digest.removeprefix('sha256:')}.json"
        payload = self._read_regular(path, max_bytes=64 * 1024)
        if _digest(payload) != digest:
            raise ArtifactError("manifest digest mismatch")
        try:
            manifest = ArtifactManifest.model_validate_json(payload, strict=True)
        except Exception as exc:
            raise ArtifactError("artifact manifest is invalid") from exc
        if canonical_json(manifest.model_dump(mode="json")) != payload:
            raise ArtifactError("artifact manifest is not canonical")
        return manifest

    def get_payload(self, manifest: ArtifactManifest) -> bytes:
        path = self.payload_root / (
            manifest.payload_digest.removeprefix("sha256:") + ".bin"
        )
        payload = self._read_regular(path, max_bytes=2048)
        if _digest(payload) != manifest.payload_digest:
            raise ArtifactError("payload digest mismatch")
        if len(payload) != manifest.payload_size_bytes:
            raise ArtifactError("payload size differs from the manifest")
        return payload


__all__ = [
    "ArtifactError",
    "ArtifactManifest",
    "ArtifactStore",
]
