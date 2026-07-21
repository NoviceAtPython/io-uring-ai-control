"""Signed, append-only human decisions for redacted proposal events.

The importer has deliberately inert authority.  An approval means only that an
exact quarantined envelope may proceed to offline validation.  Nothing in this
module can compile, execute, enqueue, promote, or modify the AFL/Nyx fleet.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import os
from pathlib import Path
import re
import stat
from typing import Annotated, Literal, TypeAlias

from pydantic import Field

from .events import (
    EventOutbox,
    EventProjectionError,
    ExecutionReadyEvent,
    HumanCode,
    Nonce256,
    ProposalQuarantinedEvent,
)
from .execution import PromotionScope
from .models import Digest, Identifier, StrictModel, TargetHashes, Timestamp
from .quarantine import canonical_json


class DecisionError(RuntimeError):
    """A signed decision failed authority, binding, freshness, or replay checks."""


Signature = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]


class HumanDecision(StrictModel):
    schema_version: Literal["human-decision.v1"] = "human-decision.v1"
    signer_id: Literal[
        "relay:sms-v1", "relay:telegram-v1", "operator:local-v1"
    ] = "relay:sms-v1"
    channel: Literal["sms", "telegram", "operator"] = "sms"
    event_digest: Digest
    envelope_digest: Digest
    target_hashes: TargetHashes
    approval_binding_digest: Digest
    decision_nonce: Nonce256
    human_code: HumanCode
    sender_binding: Digest
    action: Literal["approve_for_offline_validation", "deny"]
    reason_code: Literal["operator_approved", "operator_denied"]
    issued_at: Timestamp
    expires_at: Timestamp


class ExecutionDecision(StrictModel):
    schema_version: Literal["human-decision.v2"] = "human-decision.v2"
    # ``operator:auto-v1`` is the unattended auto-promote signer. It is deliberately
    # a DISTINCT identity from ``operator:local-v1``: once the host signs its own
    # approvals, the signature attests "the auto policy accepted this", NOT "a human
    # approved this", and the archive must never conflate the two.
    signer_id: Literal[
        "relay:sms-v1", "relay:telegram-v1", "operator:local-v1", "operator:auto-v1"
    ] = "relay:sms-v1"
    channel: Literal["sms", "telegram", "operator"] = "sms"
    event_digest: Digest
    candidate_digest: Digest
    envelope_digest: Digest
    artifact_manifest_digest: Digest
    artifact_digest: Digest
    artifact_size_bytes: Annotated[int, Field(ge=1, le=2048)]
    validation_report_digest: Digest
    canary_report_digest: Digest
    target_hashes: TargetHashes
    promotion_scope: PromotionScope
    approval_binding_digest: Digest
    decision_nonce: Nonce256
    human_code: HumanCode
    sender_binding: Digest
    action: Literal["approve_for_live_execution", "deny"]
    reason_code: Literal[
        "operator_approved_live_execution",
        "operator_denied",
    ]
    issued_at: Timestamp
    expires_at: Timestamp


DecisionPayload: TypeAlias = Annotated[
    HumanDecision | ExecutionDecision,
    Field(discriminator="schema_version"),
]


class SignedDecision(StrictModel):
    decision: DecisionPayload
    signature_hmac_sha256: Signature


def _key(secret: bytes) -> bytes:
    if not isinstance(secret, bytes) or len(secret) < 32:
        raise DecisionError("decision verification key must contain at least 32 bytes")
    return secret


def _signature(decision: HumanDecision | ExecutionDecision, secret: bytes) -> str:
    return hmac.new(
        _key(secret),
        canonical_json(decision.model_dump(mode="json")),
        hashlib.sha256,
    ).hexdigest()


def sign_decision(
    decision: HumanDecision | ExecutionDecision,
    secret: bytes,
) -> SignedDecision:
    """Relay-side helper; the secret is never retained or represented."""

    return SignedDecision(
        decision=decision,
        signature_hmac_sha256=_signature(decision, secret),
    )


def verify_signature(signed: SignedDecision, secret: bytes) -> None:
    expected = _signature(signed.decision, secret)
    if not hmac.compare_digest(expected, signed.signature_hmac_sha256):
        raise DecisionError("decision signature is invalid")


def _parse_time(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise DecisionError("decision timestamp is invalid") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise DecisionError("decision timestamp must be timezone-aware")
    return parsed.astimezone(timezone.utc)


def _event_digest(event: ProposalQuarantinedEvent | ExecutionReadyEvent) -> str:
    return "sha256:" + hashlib.sha256(
        canonical_json(event.model_dump(mode="json"))
    ).hexdigest()


def _decision_file_digest(signed: SignedDecision) -> str:
    return hashlib.sha256(canonical_json(signed.model_dump(mode="json"))).hexdigest()


class DecisionArchive:
    """Verify decisions against an event outbox and store one terminal result."""

    def __init__(
        self,
        root: str | Path,
        *,
        events: EventOutbox,
        verification_key: bytes,
    ) -> None:
        self.root = Path(root)
        self.events = events
        self._verification_key = _key(verification_key)

    def _find_event(
        self, digest: str
    ) -> ProposalQuarantinedEvent | ExecutionReadyEvent:
        for event in self.events.events():
            if isinstance(
                event, (ProposalQuarantinedEvent, ExecutionReadyEvent)
            ) and _event_digest(event) == digest:
                return event
        raise DecisionError("decision references an unknown approval event")

    def find_event(
        self, digest: str
    ) -> ProposalQuarantinedEvent | ExecutionReadyEvent:
        """Return one event only after its content digest has been verified."""

        return self._find_event(digest)

    @staticmethod
    def _read_regular(path: Path, *, max_bytes: int = 64 * 1024) -> bytes:
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(path, flags)
        except OSError as exc:
            raise DecisionError("decision archive item is unavailable") from exc
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > max_bytes:
                raise DecisionError(
                    "decision archive item is not a bounded regular file"
                )
            with os.fdopen(descriptor, "rb") as handle:
                descriptor = -1
                payload = handle.read(max_bytes + 1)
        finally:
            if descriptor >= 0:
                os.close(descriptor)
        if len(payload) > max_bytes:
            raise DecisionError("decision archive item exceeds the size limit")
        return payload

    def _read_archive(self) -> tuple[tuple[SignedDecision, Path], ...]:
        if not self.root.exists():
            return ()
        records: list[tuple[SignedDecision, Path]] = []
        for path in sorted(self.root.iterdir(), key=lambda item: item.name):
            match = re.fullmatch(r"([0-9a-f]{64})\.json", path.name)
            if match is None:
                continue
            payload = self._read_regular(path)
            if hashlib.sha256(payload).hexdigest() != match.group(1):
                raise DecisionError("decision archive item digest mismatch")
            try:
                signed = SignedDecision.model_validate_json(payload, strict=True)
            except Exception as exc:
                raise DecisionError("decision archive item is invalid") from exc
            if canonical_json(signed.model_dump(mode="json")) != payload:
                raise DecisionError("decision archive item is not canonical")
            verify_signature(signed, self._verification_key)
            records.append((signed, path))
        return tuple(records)

    def verified_decisions(self) -> tuple[SignedDecision, ...]:
        """Expose a signature-verified, canonical snapshot for offline consumers."""

        return tuple(signed for signed, _ in self._read_archive())

    def import_signed(
        self,
        signed: SignedDecision,
        *,
        now: datetime | None = None,
    ) -> tuple[str, Path]:
        """Verify and append one decision, idempotently accepting exact redelivery."""

        verify_signature(signed, self._verification_key)
        decision = signed.decision
        payload = canonical_json(signed.model_dump(mode="json"))
        digest = _decision_file_digest(signed)
        # Resolve idempotency and terminal-decision conflicts BEFORE freshness. A
        # human approval that was recorded while valid remains a valid
        # authorization even after its response window elapses, so re-delivering
        # that exact decision (e.g. by a later poll) must be an idempotent success,
        # never an "expired" failure that wedges the importer. Only a genuinely new
        # decision proceeds to full event-binding and freshness verification.
        for existing, existing_path in self._read_archive():
            if existing.decision.event_digest != decision.event_digest:
                continue
            if canonical_json(existing.model_dump(mode="json")) == payload:
                return digest, existing_path
            raise DecisionError("proposal event already has a terminal decision")
        event = self._find_event(decision.event_digest)
        if isinstance(event, ProposalQuarantinedEvent) and not isinstance(
            decision, HumanDecision
        ):
            raise DecisionError("execution decision cannot authorize an offline event")
        if isinstance(event, ExecutionReadyEvent) and not isinstance(
            decision, ExecutionDecision
        ):
            raise DecisionError("offline decision cannot authorize an execution event")
        if decision.envelope_digest != event.envelope_digest:
            raise DecisionError("decision envelope digest does not match the event")
        if decision.target_hashes != event.target_hashes:
            raise DecisionError("decision target hashes do not match the event")
        if decision.approval_binding_digest != event.approval.binding_digest:
            raise DecisionError("decision approval binding does not match the event")
        if decision.decision_nonce != event.approval.nonce:
            raise DecisionError("decision nonce does not match the event")
        if decision.human_code != event.approval.human_code:
            raise DecisionError("decision code does not match the event")
        if decision.expires_at != event.approval.expires_at:
            raise DecisionError("decision expiration does not match the event")
        if isinstance(decision, ExecutionDecision):
            assert isinstance(event, ExecutionReadyEvent)
            execution_fields_match = (
                decision.candidate_digest == event.candidate_digest
                and decision.artifact_manifest_digest
                == event.artifact_manifest_digest
                and decision.artifact_digest == event.artifact_digest
                and decision.artifact_size_bytes == event.artifact_size_bytes
                and decision.validation_report_digest
                == event.validation_report_digest
                and decision.canary_report_digest == event.canary_report_digest
                and decision.promotion_scope == event.promotion_scope
            )
            if not execution_fields_match:
                raise DecisionError(
                    "execution decision differs from the exact canaried artifact"
                )
            expected_reason = (
                "operator_approved_live_execution"
                if decision.action == "approve_for_live_execution"
                else "operator_denied"
            )
        else:
            expected_reason = (
                "operator_approved"
                if decision.action == "approve_for_offline_validation"
                else "operator_denied"
            )
        if decision.reason_code != expected_reason:
            raise DecisionError("decision reason does not match its action")

        current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        issued = _parse_time(decision.issued_at)
        expires = _parse_time(decision.expires_at)
        created = _parse_time(event.created_at)
        if issued < created or issued > current + timedelta(minutes=5):
            raise DecisionError("decision issue time is outside the accepted window")
        if current > expires or issued > expires:
            raise DecisionError("decision has expired")

        self.root.mkdir(parents=True, exist_ok=True)
        destination = self.root / f"{digest}.json"
        try:
            descriptor = os.open(
                destination,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o440,
            )
        except FileExistsError:
            existing = self._read_regular(destination)
            if existing == payload:
                return digest, destination
            raise DecisionError("decision digest collision")
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
        except BaseException:
            destination.unlink(missing_ok=True)
            raise
        return digest, destination


__all__ = [
    "DecisionArchive",
    "DecisionError",
    "ExecutionDecision",
    "HumanDecision",
    "SignedDecision",
    "sign_decision",
    "verify_signature",
]
