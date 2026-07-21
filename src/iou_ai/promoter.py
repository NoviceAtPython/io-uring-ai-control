"""Offline, artifact-bound publication into a static local sync inbox.

This module has no network client, provider adapter, shell-command support, or
model-visible path field.  A root-owned configuration supplies the only local
destination paths.  Every signed v2 approval and every immutable authority
object is independently rechecked immediately before one atomic publication.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import re
import stat
import time
from typing import Callable, Iterator, Literal, Mapping

from pydantic import ValidationError

from .artifacts import ArtifactStore
from .decisions import (
    DecisionArchive,
    DecisionError,
    ExecutionDecision,
    SignedDecision,
)
from .events import EventOutbox, ExecutionReadyEvent
from .execution import (
    ExecutionAuthorityStore,
    PromotionScope,
    WorkerSet,
    build_execution_candidate,
    build_validation_report,
    content_digest,
)
from .models import (
    HarnessContract,
    QuarantineEnvelope,
    StrictModel,
    TargetHashes,
    Timestamp,
)
from .quarantine import QuarantineStore, canonical_json


class PromotionError(RuntimeError):
    """A live-publication authority or integrity check failed closed."""


@dataclass(frozen=True, slots=True)
class DestinationSpec:
    destination_id: Literal["native_ai_sync", "kasan_ai_sync"]
    campaign_id: str
    worker_set: WorkerSet
    inbox: Path
    allowed_root: Path
    allowed_runner_hashes: frozenset[str]

    def __post_init__(self) -> None:
        expected = {
            WorkerSet.NATIVE_STABLE: "native_ai_sync",
            WorkerSet.KASAN_TRIAGE: "kasan_ai_sync",
        }[self.worker_set]
        if self.destination_id != expected:
            raise PromotionError("destination identifier differs from worker set")
        if not self.campaign_id or len(self.campaign_id) > 96:
            raise PromotionError("destination campaign identifier is invalid")
        if not self.inbox.is_absolute() or not self.allowed_root.is_absolute():
            raise PromotionError("promotion destination paths must be absolute")
        inbox = self.inbox.resolve(strict=False)
        root = self.allowed_root.resolve(strict=False)
        if inbox == root or root not in inbox.parents:
            raise PromotionError("promotion inbox escapes its static allowlist root")
        if not self.allowed_runner_hashes or any(
            re.fullmatch(r"sha256:[0-9a-f]{64}", value) is None
            for value in self.allowed_runner_hashes
        ):
            raise PromotionError("destination runner allowlist is invalid")


class PromotionReceipt(StrictModel):
    schema_version: Literal["promotion-receipt.v1"] = "promotion-receipt.v1"
    candidate_digest: str
    decision_digest: str
    event_digest: str
    envelope_digest: str
    artifact_manifest_digest: str
    artifact_digest: str
    validation_report_digest: str
    canary_report_digest: str
    target_hashes: TargetHashes
    destination_id: Literal["native_ai_sync", "kasan_ai_sync"]
    destination_entry_id: str
    promoted_at: Timestamp


def _signed_digest(signed: SignedDecision) -> str:
    return content_digest(canonical_json(signed.model_dump(mode="json")))


def _timestamp(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise PromotionError("promotion time must be timezone-aware")
    return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace(
        "+00:00", "Z"
    )


def _read_regular(path: Path, *, max_bytes: int) -> bytes:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise PromotionError("promotion object is unavailable") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > max_bytes:
            raise PromotionError("promotion object is not a bounded regular file")
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = -1
            payload = handle.read(max_bytes + 1)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if len(payload) > max_bytes:
        raise PromotionError("promotion object exceeds its size bound")
    return payload


def _require_plain_directory(path: Path) -> None:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise PromotionError("promotion directory is unavailable") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise PromotionError("promotion directory is not a plain directory")


class Promoter:
    """Verify one approved candidate and publish exactly one immutable seed."""

    def __init__(
        self,
        *,
        events: EventOutbox,
        decisions: DecisionArchive,
        quarantine: QuarantineStore,
        artifacts: ArtifactStore,
        authority: ExecutionAuthorityStore,
        receipts: str | Path,
        destinations: Mapping[str, DestinationSpec],
        current_target_probe: Callable[[], TargetHashes],
    ) -> None:
        self.events = events
        self.decisions = decisions
        self.quarantine = quarantine
        self.artifacts = artifacts
        self.authority = authority
        self.receipts = Path(receipts)
        self.destinations = dict(destinations)
        self.current_target_probe = current_target_probe
        if set(self.destinations) != {
            spec.destination_id for spec in self.destinations.values()
        }:
            raise PromotionError("promotion destination allowlist is inconsistent")

    @contextmanager
    def _lock(self) -> Iterator[None]:
        self.receipts.mkdir(parents=True, exist_ok=True)
        _require_plain_directory(self.receipts)
        path = self.receipts / ".promotion.lock"
        for attempt in range(2):
            try:
                descriptor = os.open(
                    path,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                    0o600,
                )
            except FileExistsError as exc:
                try:
                    stale = time.time() - path.stat().st_mtime > 10 * 60
                except OSError:
                    stale = False
                if attempt == 0 and stale:
                    try:
                        path.unlink()
                    except OSError:
                        pass
                    continue
                raise PromotionError("another promoter holds the publication lock") from exc
            else:
                with os.fdopen(descriptor, "w", encoding="ascii") as handle:
                    handle.write(str(os.getpid()))
                    handle.flush()
                    os.fsync(handle.fileno())
                break
        try:
            yield
        finally:
            try:
                path.unlink()
            except FileNotFoundError:
                pass

    def _receipts(self) -> tuple[PromotionReceipt, ...]:
        if not self.receipts.exists():
            return ()
        _require_plain_directory(self.receipts)
        result: list[PromotionReceipt] = []
        for path in sorted(self.receipts.iterdir(), key=lambda item: item.name):
            if re.fullmatch(r"[0-9a-f]{64}\.json", path.name) is None:
                continue
            payload = _read_regular(path, max_bytes=64 * 1024)
            try:
                receipt = PromotionReceipt.model_validate_json(payload, strict=True)
            except ValidationError as exc:
                raise PromotionError("promotion receipt is invalid") from exc
            if canonical_json(receipt.model_dump(mode="json")) != payload:
                raise PromotionError("promotion receipt is not canonical")
            if path.stem != receipt.candidate_digest.removeprefix("sha256:"):
                raise PromotionError("promotion receipt filename is not candidate-bound")
            result.append(receipt)
        return tuple(result)

    @staticmethod
    def _decision_for_candidate(
        decisions: tuple[SignedDecision, ...],
        candidate_digest: str,
    ) -> SignedDecision:
        matching = [
            signed
            for signed in decisions
            if isinstance(signed.decision, ExecutionDecision)
            and signed.decision.candidate_digest == candidate_digest
        ]
        if len(matching) != 1:
            raise PromotionError("candidate does not have one signed execution decision")
        return matching[0]

    @staticmethod
    def _candidate_matches_decision(candidate, decision: ExecutionDecision) -> bool:
        return (
            candidate.envelope_digest == decision.envelope_digest
            and candidate.artifact_manifest_digest
            == decision.artifact_manifest_digest
            and candidate.artifact_digest == decision.artifact_digest
            and candidate.artifact_size_bytes == decision.artifact_size_bytes
            and candidate.validation_report_digest
            == decision.validation_report_digest
            and candidate.canary_report_digest == decision.canary_report_digest
            and candidate.target_hashes == decision.target_hashes
            and candidate.promotion_scope == decision.promotion_scope
        )

    def _publish(self, spec: DestinationSpec, payload: bytes, digest: str) -> str:
        _require_plain_directory(spec.allowed_root)
        _require_plain_directory(spec.inbox)
        entry_id = "seed-" + digest.removeprefix("sha256:")[:24]
        visible = spec.inbox / (
            "artifact-" + digest.removeprefix("sha256:") + ".seed"
        )
        temporary = spec.inbox / (
            "." + digest.removeprefix("sha256:") + f".{os.getpid()}.tmp"
        )
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(temporary, flags, 0o440)
            try:
                with os.fdopen(descriptor, "wb") as handle:
                    descriptor = -1
                    handle.write(payload)
                    handle.flush()
                    os.fsync(handle.fileno())
            finally:
                if descriptor >= 0:
                    os.close(descriptor)
            try:
                os.link(temporary, visible, follow_symlinks=False)
            except FileExistsError:
                if _read_regular(visible, max_bytes=2048) != payload:
                    raise PromotionError("promotion destination contains wrong bytes")
            if _read_regular(visible, max_bytes=2048) != payload:
                raise PromotionError("published artifact verification failed")
        finally:
            try:
                temporary.unlink()
            except PermissionError:
                # Windows maps the mode used for the temporary artifact to its
                # read-only attribute.  Linux permits unlinking it through the
                # writable directory (the deployment target), but making this
                # best-effort cleanup portable keeps the authority logic
                # testable without weakening its Linux publication semantics.
                try:
                    temporary.chmod(0o600)
                    temporary.unlink()
                except FileNotFoundError:
                    pass
            except FileNotFoundError:
                pass
        try:
            directory = os.open(
                spec.inbox,
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
            )
        except OSError:
            directory = -1
        if directory >= 0:
            try:
                os.fsync(directory)
            except OSError:
                pass
            finally:
                os.close(directory)
        return entry_id

    def promote(
        self,
        candidate_digest: str,
        *,
        now: datetime | None = None,
    ) -> PromotionReceipt:
        current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        signed = self._decision_for_candidate(
            self.decisions.verified_decisions(),
            candidate_digest,
        )
        try:
            # Re-run event binding, signature, terminal-decision, and expiry
            # verification at execution time.
            self.decisions.import_signed(signed, now=current)
        except DecisionError as exc:
            raise PromotionError("execution decision is not currently valid") from exc
        decision = signed.decision
        if not isinstance(decision, ExecutionDecision):
            raise PromotionError("offline decision cannot authorize promotion")
        if (
            decision.action != "approve_for_live_execution"
            or decision.reason_code != "operator_approved_live_execution"
        ):
            raise PromotionError("execution candidate was not approved")
        event = self.decisions.find_event(decision.event_digest)
        if not isinstance(event, ExecutionReadyEvent):
            raise PromotionError("execution decision references the wrong event version")

        candidate = self.authority.get_candidate(candidate_digest)
        if not self._candidate_matches_decision(candidate, decision):
            raise PromotionError("candidate differs from the signed execution decision")
        validation = self.authority.get_validation(
            candidate.validation_report_digest
        )
        canary = self.authority.get_report(candidate.canary_report_digest)
        manifest = self.artifacts.get_manifest(candidate.artifact_manifest_digest)
        payload = self.artifacts.get_payload(manifest)
        try:
            # Validate from canonical JSON bytes: the strict model config only
            # coerces string enum values through the JSON validator, not a dict.
            envelope = QuarantineEnvelope.model_validate_json(
                canonical_json(
                    self.quarantine.get(
                        candidate.envelope_digest.removeprefix("sha256:")
                    )
                )
            )
        except Exception as exc:
            raise PromotionError("quarantine envelope is invalid") from exc

        rebuilt_validation = build_validation_report(
            envelope_digest=candidate.envelope_digest,
            envelope=envelope,
            artifact_manifest_digest=candidate.artifact_manifest_digest,
            manifest=manifest,
            payload=payload,
            created_at=validation.created_at,
        )
        if rebuilt_validation != validation:
            raise PromotionError("stored deterministic validation cannot be reproduced")

        spec = self.destinations.get(candidate.promotion_scope.destination_id)
        if spec is None:
            raise PromotionError("promotion destination is not allowlisted")
        expected_scope = PromotionScope(
            campaign_id=spec.campaign_id,
            destination_id=spec.destination_id,
            worker_set=spec.worker_set,
        )
        if candidate.promotion_scope != expected_scope:
            raise PromotionError("signed scope differs from root-owned destination policy")
        rebuilt_candidate = build_execution_candidate(
            validation_report_digest=candidate.validation_report_digest,
            validation=validation,
            canary_report_digest=candidate.canary_report_digest,
            canary=canary,
            artifact_manifest_digest=candidate.artifact_manifest_digest,
            manifest=manifest,
            promotion_scope=expected_scope,
            ready_at=candidate.ready_at,
            allowed_runner_hashes=spec.allowed_runner_hashes,
        )
        if rebuilt_candidate != candidate:
            raise PromotionError("stored execution candidate cannot be reproduced")
        if self.current_target_probe() != candidate.target_hashes:
            raise PromotionError("current target authority has drifted")

        with self._lock():
            existing = self._receipts()
            for receipt in existing:
                if receipt.candidate_digest == candidate_digest:
                    return receipt
                if (
                    receipt.destination_id == spec.destination_id
                    and receipt.artifact_digest == candidate.artifact_digest
                ):
                    raise PromotionError(
                        "artifact was already published under another candidate"
                    )
            # Target authority is checked again while the publication lock is
            # held, immediately before the filesystem mutation.
            if self.current_target_probe() != candidate.target_hashes:
                raise PromotionError("current target authority drifted during promotion")
            entry_id = self._publish(spec, payload, candidate.artifact_digest)
            receipt = PromotionReceipt(
                candidate_digest=candidate_digest,
                decision_digest=_signed_digest(signed),
                event_digest=decision.event_digest,
                envelope_digest=candidate.envelope_digest,
                artifact_manifest_digest=candidate.artifact_manifest_digest,
                artifact_digest=candidate.artifact_digest,
                validation_report_digest=candidate.validation_report_digest,
                canary_report_digest=candidate.canary_report_digest,
                target_hashes=candidate.target_hashes,
                destination_id=spec.destination_id,
                destination_entry_id=entry_id,
                promoted_at=_timestamp(current),
            )
            receipt_payload = canonical_json(receipt.model_dump(mode="json"))
            destination = self.receipts / (
                candidate_digest.removeprefix("sha256:") + ".json"
            )
            try:
                descriptor = os.open(
                    destination,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                    0o440,
                )
            except FileExistsError:
                existing_payload = _read_regular(destination, max_bytes=64 * 1024)
                if existing_payload != receipt_payload:
                    raise PromotionError("promotion receipt collision")
            else:
                with os.fdopen(descriptor, "wb") as handle:
                    handle.write(receipt_payload)
                    handle.flush()
                    os.fsync(handle.fileno())
            return receipt


def load_current_target_contract(path: str | Path) -> TargetHashes:
    """Read a root-refreshed contract used as the final target-drift probe."""

    payload = _read_regular(Path(path), max_bytes=2 * 1024 * 1024)
    try:
        contract = HarnessContract.model_validate_json(payload, strict=True)
    except ValidationError as exc:
        raise PromotionError("current target contract is invalid") from exc
    if canonical_json(contract.model_dump(mode="json")) != payload:
        raise PromotionError("current target contract is not canonical")
    return contract.target_hashes


__all__ = [
    "DestinationSpec",
    "Promoter",
    "PromotionError",
    "PromotionReceipt",
    "load_current_target_contract",
]
