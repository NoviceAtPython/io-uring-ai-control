"""Root canary bridge: compiled quarantine artifacts -> approval-ready candidates.

This runs as root because the isolated one-shot Nyx canary needs KVM. For each
compiled artifact a quarantine envelope references, it:

  1. independently re-validates the artifact against the envelope (bindings,
     codec decode/re-encode) -- a DeterministicValidationReport,
  2. runs the isolated Nyx canary on the exact compiled bytes, and
  3. ONLY if the canary passes, records a signed ExecutionCandidate bound to that
     exact artifact + validation + canary.

It never writes to the live AFL/Nyx corpus and never promotes anything: live
promotion stays in the separate, human-approval-gated promoter. A rejected or
infrastructure-failed canary yields no candidate (fail-closed).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
import tempfile
from typing import Callable

from pydantic import ValidationError

from .artifacts import ArtifactStore
from .canary import (
    CanaryBinding,
    CanaryConfig,
    Runner,
    fleet_pid_snapshot,
    run_canary,
)
from .execution import (
    CanaryOutcome,
    ExecutionAuthorityStore,
    PromotionScope,
    build_execution_candidate,
    build_validation_report,
)
from .models import QuarantineEnvelope
from .quarantine import QuarantineError, QuarantineStore, canonical_json


class CanaryServiceError(RuntimeError):
    """The canary bridge could not process an envelope (never yields a candidate)."""


@dataclass(frozen=True, slots=True)
class CanaryServiceResult:
    envelope_digest: str  # "sha256:..."
    artifact_manifest_digest: str
    outcome: str  # "candidate_ready" | "rejected" | "infrastructure_failure"
    canary_report_digest: str
    candidate_digest: str | None
    detail: str


def _now_iso() -> str:
    return (
        datetime.now(timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )


class CanaryBridge:
    """Chain quarantined compiled artifacts through the isolated Nyx canary."""

    def __init__(
        self,
        *,
        quarantine: QuarantineStore,
        artifacts: ArtifactStore,
        authority: ExecutionAuthorityStore,
        canary_config: CanaryConfig,
        promotion_scope: PromotionScope,
        allowed_runner_hashes: frozenset[str],
        fleet_probe: Callable[[], str] = fleet_pid_snapshot,
        runner: Runner | None = None,
        now: Callable[[], str] = _now_iso,
    ) -> None:
        self.quarantine = quarantine
        self.artifacts = artifacts
        self.authority = authority
        self.canary_config = canary_config
        self.promotion_scope = promotion_scope
        self.allowed_runner_hashes = frozenset(allowed_runner_hashes)
        self.fleet_probe = fleet_probe
        self.runner = runner
        self.now = now
        if not self.allowed_runner_hashes:
            raise CanaryServiceError("allowed_runner_hashes must not be empty")

    def process_envelope(self, envelope_hex_digest: str) -> list[CanaryServiceResult]:
        """Canary every compiled artifact referenced by one quarantine envelope."""

        try:
            raw = self.quarantine.get(envelope_hex_digest)
        except QuarantineError as exc:
            raise CanaryServiceError(f"quarantine envelope unavailable: {exc}") from exc
        # Validate from the canonical JSON bytes (not the dict): the strict model
        # config only coerces string enum values through the JSON validator.
        try:
            envelope = QuarantineEnvelope.model_validate_json(canonical_json(raw))
        except ValidationError as exc:
            raise CanaryServiceError("quarantine envelope is invalid") from exc

        envelope_digest = "sha256:" + envelope_hex_digest
        results: list[CanaryServiceResult] = []
        for manifest_digest in envelope.compiled_artifact_hashes:
            results.append(
                self._process_artifact(envelope_digest, envelope, manifest_digest)
            )
        return results

    def _process_artifact(
        self,
        envelope_digest: str,
        envelope: QuarantineEnvelope,
        manifest_digest: str,
    ) -> CanaryServiceResult:
        manifest = self.artifacts.get_manifest(manifest_digest)
        payload = self.artifacts.get_payload(manifest)

        # Independent re-validation before anything is executed.
        validation = build_validation_report(
            envelope_digest=envelope_digest,
            envelope=envelope,
            artifact_manifest_digest=manifest_digest,
            manifest=manifest,
            payload=payload,
            created_at=self.now(),
        )
        validation_report_digest, _ = self.authority.put_validation(validation)

        binding = CanaryBinding(
            envelope_digest=envelope_digest,
            validation_report_digest=validation_report_digest,
            artifact_manifest_digest=manifest_digest,
            artifact_digest=manifest.payload_digest,
            target_hashes=manifest.target_hashes,
        )

        # Run the exact bytes in an isolated throwaway VM. A fleet disturbance
        # raises CanaryRunError out of run_canary and deliberately halts here.
        with tempfile.TemporaryDirectory(prefix="iou-canary-seed.") as scratch:
            seed_path = Path(scratch) / "candidate.seed"
            seed_path.write_bytes(payload)
            canary = run_canary(
                binding=binding,
                config=self.canary_config,
                seed_path=seed_path,
                fleet_probe=self.fleet_probe,
                runner=self.runner,
            )
        canary_report_digest, _ = self.authority.put_report(canary)

        if canary.outcome is not CanaryOutcome.PASSED:
            outcome = (
                "infrastructure_failure"
                if canary.outcome is CanaryOutcome.INFRASTRUCTURE_FAILURE
                else "rejected"
            )
            return CanaryServiceResult(
                envelope_digest=envelope_digest,
                artifact_manifest_digest=manifest_digest,
                outcome=outcome,
                canary_report_digest=canary_report_digest,
                candidate_digest=None,
                detail=f"canary {canary.outcome.value}; artifact not promoted",
            )

        candidate = build_execution_candidate(
            validation_report_digest=validation_report_digest,
            validation=validation,
            canary_report_digest=canary_report_digest,
            canary=canary,
            artifact_manifest_digest=manifest_digest,
            manifest=manifest,
            promotion_scope=self.promotion_scope,
            ready_at=self.now(),
            allowed_runner_hashes=self.allowed_runner_hashes,
        )
        candidate_digest, _ = self.authority.put_candidate(candidate)
        return CanaryServiceResult(
            envelope_digest=envelope_digest,
            artifact_manifest_digest=manifest_digest,
            outcome="candidate_ready",
            canary_report_digest=canary_report_digest,
            candidate_digest=candidate_digest,
            detail="canary passed; execution candidate awaiting human approval",
        )


__all__ = [
    "CanaryBridge",
    "CanaryServiceError",
    "CanaryServiceResult",
]
