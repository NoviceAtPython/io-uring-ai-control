from __future__ import annotations

from pathlib import Path

import pytest

from iou_ai.artifacts import ArtifactError, ArtifactStore
from iou_ai.compiler import CompiledProgram
from iou_ai.models import TargetHashes


TARGETS = TargetHashes(
    harness_hash="sha256:" + "1" * 64,
    compiler_hash="sha256:" + "2" * 64,
    op_table_hash="sha256:" + "3" * 64,
    fleet_config_hash="sha256:" + "4" * 64,
)


def _compiled(payload: bytes = b"\x01\x00\x00") -> CompiledProgram:
    import hashlib

    return CompiledProgram(
        program_id="artifact_probe",
        payload=payload,
        payload_hash="sha256:" + hashlib.sha256(payload).hexdigest(),
        operation_count=1,
        compiler_hash=TARGETS.compiler_hash,
        harness_hash=TARGETS.harness_hash,
    )


def _put(store: ArtifactStore, compiled: CompiledProgram | None = None):
    return store.put(
        compiled or _compiled(),
        proposal_digest="sha256:" + "5" * 64,
        program_digest="sha256:" + "6" * 64,
        harness_contract_digest="sha256:" + "7" * 64,
        validator_version="semantic-validator.v4",
        validator_hash="sha256:" + "8" * 64,
        target_hashes=TARGETS,
    )


def test_store_is_content_addressed_idempotent_and_round_trips(tmp_path: Path) -> None:
    store = ArtifactStore(tmp_path)
    first = _put(store)
    second = _put(store)
    assert first == second
    manifest = store.get_manifest(first[0])
    assert manifest.live_promotion_authorized is False
    assert manifest.isolated_canary_required is True
    assert store.get_payload(manifest) == b"\x01\x00\x00"


def test_store_rejects_digest_and_target_drift(tmp_path: Path) -> None:
    store = ArtifactStore(tmp_path)
    drifted = _compiled()
    drifted = CompiledProgram(
        program_id=drifted.program_id,
        payload=drifted.payload,
        payload_hash="sha256:" + "0" * 64,
        operation_count=drifted.operation_count,
        compiler_hash=drifted.compiler_hash,
        harness_hash=drifted.harness_hash,
    )
    with pytest.raises(ArtifactError, match="digest changed"):
        _put(store, drifted)

    wrong_target = _compiled()
    wrong_target = CompiledProgram(
        program_id=wrong_target.program_id,
        payload=wrong_target.payload,
        payload_hash=wrong_target.payload_hash,
        operation_count=wrong_target.operation_count,
        compiler_hash="sha256:" + "9" * 64,
        harness_hash=wrong_target.harness_hash,
    )
    with pytest.raises(ArtifactError, match="different compiler"):
        _put(store, wrong_target)


def test_manifest_and_payload_mutation_fail_closed(tmp_path: Path) -> None:
    store = ArtifactStore(tmp_path)
    digest, manifest_path, payload_path = _put(store)
    manifest_path.chmod(0o600)
    manifest_path.write_bytes(manifest_path.read_bytes() + b" ")
    with pytest.raises(ArtifactError, match="manifest digest mismatch"):
        store.get_manifest(digest)

    # Use a fresh store entry so manifest validation succeeds before payload QA.
    other = ArtifactStore(tmp_path / "other")
    other_digest, _, other_payload = _put(other)
    manifest = other.get_manifest(other_digest)
    other_payload.chmod(0o600)
    other_payload.write_bytes(b"\x00")
    with pytest.raises(ArtifactError, match="payload digest mismatch"):
        other.get_payload(manifest)
