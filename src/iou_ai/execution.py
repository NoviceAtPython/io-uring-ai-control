"""Strict authority records between canary completion and live approval.

Execution candidates contain hashes and constrained identifiers only.  They do
not contain payload bytes, filesystem paths, model prose, or a destination
chosen by a provider.  A separate root-owned promoter resolves the signed scope
through a static local allowlist.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
import hashlib
import os
from pathlib import Path
import re
import stat
from typing import Annotated, Literal

from pydantic import Field, model_validator

from .artifacts import ArtifactManifest
from .harness_codec import HarnessCodecError, decode_program, encode_program
from .models import (
    Digest,
    Identifier,
    QuarantineEnvelope,
    StrictModel,
    TargetHashes,
    Timestamp,
)
from .quarantine import canonical_json


class ExecutionAuthorityError(RuntimeError):
    """An execution authority object failed strict integrity validation."""


class WorkerSet(str, Enum):
    NATIVE_STABLE = "native_stable"
    KASAN_TRIAGE = "kasan_triage"


class PromotionScope(StrictModel):
    schema_version: Literal["promotion-scope.v1"] = "promotion-scope.v1"
    campaign_id: Identifier
    destination_id: Literal["native_ai_sync", "kasan_ai_sync"]
    worker_set: WorkerSet
    mode: Literal["afl_foreign_sync_seed"] = "afl_foreign_sync_seed"
    max_artifacts: Literal[1] = 1

    @model_validator(mode="after")
    def destination_matches_workers(self) -> "PromotionScope":
        expected = {
            WorkerSet.NATIVE_STABLE: "native_ai_sync",
            WorkerSet.KASAN_TRIAGE: "kasan_ai_sync",
        }[self.worker_set]
        if self.destination_id != expected:
            raise ValueError("promotion destination does not match the worker set")
        return self


class CanaryOutcome(str, Enum):
    PASSED = "passed"
    REJECTED = "rejected"
    INFRASTRUCTURE_FAILURE = "infrastructure_failure"


class CanaryReport(StrictModel):
    schema_version: Literal["nyx-canary-report.v1"] = "nyx-canary-report.v1"
    report_id: Identifier
    started_at: Timestamp
    finished_at: Timestamp
    envelope_digest: Digest
    validation_report_digest: Digest
    artifact_manifest_digest: Digest
    artifact_digest: Digest
    target_hashes: TargetHashes
    runner_hash: Digest
    runner_result_digest: Digest
    outcome: CanaryOutcome
    exact_seed_dry_runs: Annotated[int, Field(ge=0, le=4)]
    executions_total: Annotated[int, Field(ge=0, le=1_000_000)]
    timeout_seconds: Annotated[int, Field(ge=1, le=120)]
    harness_accepted: bool
    infrastructure_error: bool
    runner_exit_code: Annotated[int, Field(ge=-255, le=255)]
    timed_out: bool
    signal_number: Annotated[int, Field(ge=0, le=128)]
    fleet_snapshot_before: Digest
    fleet_snapshot_after: Digest
    live_fleet_touched: Literal[False] = False

    @model_validator(mode="after")
    def outcome_matches_measurements(self) -> "CanaryReport":
        try:
            started = datetime.fromisoformat(self.started_at.replace("Z", "+00:00"))
            finished = datetime.fromisoformat(self.finished_at.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("canary timestamps are invalid") from exc
        if started.tzinfo is None or finished.tzinfo is None or finished < started:
            raise ValueError("canary time interval is invalid")
        passed = (
            self.exact_seed_dry_runs >= 1
            and self.executions_total >= self.exact_seed_dry_runs
            and self.harness_accepted
            and not self.infrastructure_error
            and self.runner_exit_code == 0
            and not self.timed_out
            and self.signal_number == 0
            and self.fleet_snapshot_before == self.fleet_snapshot_after
        )
        if (self.outcome is CanaryOutcome.PASSED) != passed:
            raise ValueError("canary outcome does not match its measurements")
        if (
            self.outcome is CanaryOutcome.INFRASTRUCTURE_FAILURE
        ) != self.infrastructure_error:
            raise ValueError("infrastructure outcome does not match error state")
        if self.live_fleet_touched or (
            self.fleet_snapshot_before != self.fleet_snapshot_after
        ):
            raise ValueError("canary changed the production fleet snapshot")
        return self


class DeterministicValidationReport(StrictModel):
    """Immutable proof that one artifact agrees with all pre-canary authority."""

    schema_version: Literal["deterministic-validation-report.v1"] = (
        "deterministic-validation-report.v1"
    )
    report_id: Identifier
    created_at: Timestamp
    envelope_digest: Digest
    artifact_manifest_digest: Digest
    artifact_digest: Digest
    artifact_size_bytes: Annotated[int, Field(ge=1, le=2048)]
    operation_count: Annotated[int, Field(ge=1, le=96)]
    proposal_digest: Digest
    program_digest: Digest
    harness_contract_digest: Digest
    target_hashes: TargetHashes
    compiler_version: Identifier
    compiler_hash: Digest
    validator_version: Identifier
    validator_hash: Digest
    source_validation_count: Annotated[int, Field(ge=1, le=16)]
    passed_check_ids: Annotated[list[Identifier], Field(min_length=4, max_length=128)]
    failed_check_ids: Annotated[list[Identifier], Field(max_length=0)]
    decode_reencode_equal: Literal[True] = True
    valid: Literal[True] = True
    live_fleet_touched: Literal[False] = False

    @model_validator(mode="after")
    def checks_are_unique_and_target_bound(self) -> "DeterministicValidationReport":
        if len(self.passed_check_ids) != len(set(self.passed_check_ids)):
            raise ValueError("validation check identifiers must be unique")
        if self.compiler_hash != self.target_hashes.compiler_hash:
            raise ValueError("validation compiler hash differs from target authority")
        return self


class ExecutionCandidate(StrictModel):
    schema_version: Literal["execution-candidate.v1"] = "execution-candidate.v1"
    candidate_id: Identifier
    ready_at: Timestamp
    envelope_digest: Digest
    artifact_manifest_digest: Digest
    artifact_digest: Digest
    artifact_size_bytes: Annotated[int, Field(ge=1, le=2048)]
    validation_report_digest: Digest
    canary_report_digest: Digest
    target_hashes: TargetHashes
    promotion_scope: PromotionScope
    canary_outcome: Literal[CanaryOutcome.PASSED] = CanaryOutcome.PASSED
    human_execution_approval_required: Literal[True] = True
    live_promotion_authorized: Literal[False] = False


def content_digest(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _read_regular(path: Path, *, max_bytes: int) -> bytes:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ExecutionAuthorityError("authority object is unavailable") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > max_bytes:
            raise ExecutionAuthorityError("authority object is not a bounded regular file")
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = -1
            payload = handle.read(max_bytes + 1)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if len(payload) > max_bytes:
        raise ExecutionAuthorityError("authority object is not a bounded regular file")
    return payload


def build_validation_report(
    *,
    envelope_digest: str,
    envelope: QuarantineEnvelope,
    artifact_manifest_digest: str,
    manifest: ArtifactManifest,
    payload: bytes,
    created_at: str,
) -> DeterministicValidationReport:
    """Independently revalidate one compiled artifact before any canary starts."""

    expected_envelope_digest = content_digest(
        canonical_json(envelope.model_dump(mode="json"))
    )
    if envelope_digest != expected_envelope_digest:
        raise ExecutionAuthorityError("quarantine envelope digest mismatch")
    expected_manifest_digest = content_digest(
        canonical_json(manifest.model_dump(mode="json"))
    )
    if artifact_manifest_digest != expected_manifest_digest:
        raise ExecutionAuthorityError("artifact manifest digest mismatch")
    if artifact_manifest_digest not in envelope.compiled_artifact_hashes:
        raise ExecutionAuthorityError("artifact manifest is absent from the envelope")
    if content_digest(payload) != manifest.payload_digest:
        raise ExecutionAuthorityError("artifact payload digest mismatch")
    if len(payload) != manifest.payload_size_bytes:
        raise ExecutionAuthorityError("artifact payload size mismatch")
    if manifest.proposal_digest != envelope.proposal_hash:
        raise ExecutionAuthorityError("artifact proposal binding mismatch")
    if manifest.harness_contract_digest != envelope.harness_contract_hash:
        raise ExecutionAuthorityError("artifact contract binding mismatch")
    if manifest.target_hashes != envelope.target_hashes:
        raise ExecutionAuthorityError("artifact target binding mismatch")
    if manifest.compiler_hash != envelope.target_hashes.compiler_hash:
        raise ExecutionAuthorityError("artifact compiler authority mismatch")
    if content_digest(canonical_json(envelope.proposal.model_dump(mode="json"))) != (
        envelope.proposal_hash
    ):
        raise ExecutionAuthorityError("envelope proposal digest mismatch")
    if content_digest(
        canonical_json(envelope.reviewer_verdict.model_dump(mode="json"))
    ) != envelope.reviewer_verdict_hash:
        raise ExecutionAuthorityError("envelope reviewer digest mismatch")
    if envelope.auditor_verdict is not None:
        if content_digest(
            canonical_json(envelope.auditor_verdict.model_dump(mode="json"))
        ) != envelope.auditor_verdict_hash:
            raise ExecutionAuthorityError("envelope auditor digest mismatch")
    if any(record.failed_check_ids for record in envelope.validations):
        raise ExecutionAuthorityError("envelope contains a failed validation")
    if not any(
        record.validator_version == manifest.validator_version
        and record.validator_hash == manifest.validator_hash
        for record in envelope.validations
    ):
        raise ExecutionAuthorityError("artifact validator is absent from the envelope")

    try:
        decoded = decode_program(
            payload,
            harness_hash=manifest.target_hashes.harness_hash,
        )
        reencoded = encode_program(
            decoded,
            harness_hash=manifest.target_hashes.harness_hash,
        )
    except HarnessCodecError as exc:
        raise ExecutionAuthorityError("artifact failed independent codec validation") from exc
    if reencoded != payload:
        raise ExecutionAuthorityError("artifact failed decode/re-encode equality")
    if len(decoded.operations) != manifest.operation_count:
        raise ExecutionAuthorityError("artifact operation count mismatch")

    passed = {
        check_id
        for record in envelope.validations
        for check_id in record.passed_check_ids
    }
    passed.update(
        {
            "authority.envelope-digest",
            "authority.manifest-binding",
            "authority.payload-digest",
            "authority.target-binding",
            "codec.decode-reencode-equality",
        }
    )
    return DeterministicValidationReport(
        report_id="validation-" + artifact_manifest_digest[-24:],
        created_at=created_at,
        envelope_digest=envelope_digest,
        artifact_manifest_digest=artifact_manifest_digest,
        artifact_digest=manifest.payload_digest,
        artifact_size_bytes=manifest.payload_size_bytes,
        operation_count=manifest.operation_count,
        proposal_digest=manifest.proposal_digest,
        program_digest=manifest.program_digest,
        harness_contract_digest=manifest.harness_contract_digest,
        target_hashes=manifest.target_hashes,
        compiler_version=manifest.compiler_version,
        compiler_hash=manifest.compiler_hash,
        validator_version=manifest.validator_version,
        validator_hash=manifest.validator_hash,
        source_validation_count=len(envelope.validations),
        passed_check_ids=sorted(passed),
        failed_check_ids=[],
    )


def build_execution_candidate(
    *,
    validation_report_digest: str,
    validation: DeterministicValidationReport,
    canary_report_digest: str,
    canary: CanaryReport,
    artifact_manifest_digest: str,
    manifest: ArtifactManifest,
    promotion_scope: PromotionScope,
    ready_at: str,
    allowed_runner_hashes: frozenset[str],
) -> ExecutionCandidate:
    """Cross-bind a passed canary to one exact, locally validated artifact."""

    if content_digest(
        canonical_json(validation.model_dump(mode="json"))
    ) != validation_report_digest:
        raise ExecutionAuthorityError("deterministic validation report digest mismatch")
    if content_digest(canonical_json(canary.model_dump(mode="json"))) != (
        canary_report_digest
    ):
        raise ExecutionAuthorityError("canary report digest mismatch")
    if content_digest(canonical_json(manifest.model_dump(mode="json"))) != (
        artifact_manifest_digest
    ):
        raise ExecutionAuthorityError("candidate artifact manifest digest mismatch")
    if validation_report_digest != canary.validation_report_digest:
        raise ExecutionAuthorityError("canary is not bound to the validation report")
    if canary.outcome is not CanaryOutcome.PASSED:
        raise ExecutionAuthorityError("canary did not pass")
    if canary.runner_hash not in allowed_runner_hashes:
        raise ExecutionAuthorityError("canary runner hash is not allowlisted")
    common = (
        validation.envelope_digest == canary.envelope_digest
        and validation.artifact_manifest_digest
        == canary.artifact_manifest_digest
        == artifact_manifest_digest
        and validation.artifact_digest
        == canary.artifact_digest
        == manifest.payload_digest
        and validation.artifact_size_bytes == manifest.payload_size_bytes
        and validation.target_hashes
        == canary.target_hashes
        == manifest.target_hashes
    )
    if not common:
        raise ExecutionAuthorityError("canary authority bindings disagree")
    return ExecutionCandidate(
        candidate_id="candidate-" + canary_report_digest[-24:],
        ready_at=ready_at,
        envelope_digest=validation.envelope_digest,
        artifact_manifest_digest=artifact_manifest_digest,
        artifact_digest=manifest.payload_digest,
        artifact_size_bytes=manifest.payload_size_bytes,
        validation_report_digest=validation_report_digest,
        canary_report_digest=canary_report_digest,
        target_hashes=manifest.target_hashes,
        promotion_scope=promotion_scope,
    )


class ExecutionAuthorityStore:
    """Create-only canonical storage for canary reports and ready candidates."""

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)
        self.validation_root = self.root / "validation-reports"
        self.report_root = self.root / "canary-reports"
        self.candidate_root = self.root / "candidates"

    @staticmethod
    def _put(root: Path, model: StrictModel) -> tuple[str, Path]:
        payload = canonical_json(model.model_dump(mode="json"))
        digest = content_digest(payload)
        root.mkdir(parents=True, exist_ok=True)
        destination = root / f"{digest.removeprefix('sha256:')}.json"
        try:
            descriptor = os.open(
                destination,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o440,
            )
        except FileExistsError:
            if _read_regular(destination, max_bytes=max(len(payload), 1)) != payload:
                raise ExecutionAuthorityError("authority digest collision or mutation")
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

    def put_report(self, report: CanaryReport) -> tuple[str, Path]:
        return self._put(self.report_root, report)

    def put_validation(
        self,
        report: DeterministicValidationReport,
    ) -> tuple[str, Path]:
        return self._put(self.validation_root, report)

    def put_candidate(self, candidate: ExecutionCandidate) -> tuple[str, Path]:
        return self._put(self.candidate_root, candidate)

    @staticmethod
    def _get(root: Path, digest: str, model_type: type[StrictModel]) -> StrictModel:
        if re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is None:
            raise ExecutionAuthorityError("invalid authority digest")
        path = root / f"{digest.removeprefix('sha256:')}.json"
        payload = _read_regular(path, max_bytes=64 * 1024)
        if len(payload) > 64 * 1024 or content_digest(payload) != digest:
            raise ExecutionAuthorityError("authority object digest mismatch")
        try:
            model = model_type.model_validate_json(payload, strict=True)
        except Exception as exc:
            raise ExecutionAuthorityError("authority object is invalid") from exc
        if canonical_json(model.model_dump(mode="json")) != payload:
            raise ExecutionAuthorityError("authority object is not canonical")
        return model

    def get_report(self, digest: str) -> CanaryReport:
        return self._get(self.report_root, digest, CanaryReport)  # type: ignore[return-value]

    def get_validation(self, digest: str) -> DeterministicValidationReport:
        return self._get(  # type: ignore[return-value]
            self.validation_root,
            digest,
            DeterministicValidationReport,
        )

    def get_candidate(self, digest: str) -> ExecutionCandidate:
        return self._get(self.candidate_root, digest, ExecutionCandidate)  # type: ignore[return-value]


__all__ = [
    "CanaryOutcome",
    "CanaryReport",
    "DeterministicValidationReport",
    "ExecutionAuthorityError",
    "ExecutionAuthorityStore",
    "ExecutionCandidate",
    "PromotionScope",
    "WorkerSet",
    "build_execution_candidate",
    "build_validation_report",
    "content_digest",
]
