from __future__ import annotations

from datetime import datetime, timezone
import hashlib
from pathlib import Path

import pytest
from pydantic import ValidationError

from iou_ai.decisions import (
    DecisionArchive,
    DecisionError,
    HumanDecision,
    sign_decision,
)
from iou_ai.events import (
    ApprovalChallenge,
    EventOutbox,
    ProposalQuarantinedEvent,
    approval_binding_digest,
)
from iou_ai.models import TargetHashes
from iou_ai.quarantine import canonical_json


SECRET = b"decision-test-secret-material-32bytes!!"
NOW = datetime(2026, 7, 16, 20, 10, tzinfo=timezone.utc)


def _hashes() -> TargetHashes:
    return TargetHashes(
        harness_hash="sha256:" + "a" * 64,
        compiler_hash="sha256:" + "b" * 64,
        op_table_hash="sha256:" + "c" * 64,
        fleet_config_hash="sha256:" + "d" * 64,
    )


def _event(outbox: EventOutbox) -> tuple[ProposalQuarantinedEvent, str]:
    hashes = _hashes()
    envelope = "sha256:" + "e" * 64
    nonce = "1" * 64
    code = "ABCDEFG2"
    expires = "2026-07-16T20:30:00Z"
    event = ProposalQuarantinedEvent(
        created_at="2026-07-16T20:00:00Z",
        envelope_digest=envelope,
        proposal_hash="sha256:" + "f" * 64,
        target_hashes=hashes,
        approval=ApprovalChallenge(
            nonce=nonce,
            human_code=code,
            expires_at=expires,
            binding_digest=approval_binding_digest(
                envelope_digest=envelope,
                target_hashes=hashes,
                nonce=nonce,
                human_code=code,
                expires_at=expires,
            ),
        ),
    )
    outbox.put(event)
    digest = "sha256:" + hashlib.sha256(
        canonical_json(event.model_dump(mode="json"))
    ).hexdigest()
    return event, digest


def _decision(
    event: ProposalQuarantinedEvent,
    event_digest: str,
    *,
    action: str = "approve_for_offline_validation",
) -> HumanDecision:
    return HumanDecision(
        event_digest=event_digest,
        envelope_digest=event.envelope_digest,
        target_hashes=event.target_hashes,
        approval_binding_digest=event.approval.binding_digest,
        decision_nonce=event.approval.nonce,
        human_code=event.approval.human_code,
        sender_binding="sha256:" + "9" * 64,
        action=action,
        reason_code=(
            "operator_approved"
            if action == "approve_for_offline_validation"
            else "operator_denied"
        ),
        issued_at="2026-07-16T20:09:00Z",
        expires_at=event.approval.expires_at,
    )


def test_valid_approval_is_append_only_and_exact_redelivery_is_idempotent(
    tmp_path: Path,
) -> None:
    outbox = EventOutbox(tmp_path / "events")
    event, digest = _event(outbox)
    signed = sign_decision(_decision(event, digest), SECRET)
    archive = DecisionArchive(
        tmp_path / "decisions", events=outbox, verification_key=SECRET
    )
    first = archive.import_signed(signed, now=NOW)
    second = archive.import_signed(signed, now=NOW)
    assert first == second
    assert len(list((tmp_path / "decisions").glob("*.json"))) == 1
    assert signed.decision.action == "approve_for_offline_validation"


def test_archived_approval_reimports_idempotently_after_its_window_closes(
    tmp_path: Path,
) -> None:
    # An approval recorded while valid must remain importable as an idempotent
    # no-op even after its response window elapses. Otherwise a stale-but-archived
    # bundle re-delivered by a later poll raises "decision has expired" and, since
    # the importer aborts on the first bad bundle, wedges every other decision.
    # Regression for the promotion stall where an archived EXECUTE approval could
    # not be re-imported once its 30-minute window closed.
    outbox = EventOutbox(tmp_path / "events")
    event, digest = _event(outbox)
    signed = sign_decision(_decision(event, digest), SECRET)
    archive = DecisionArchive(
        tmp_path / "decisions", events=outbox, verification_key=SECRET
    )
    first = archive.import_signed(signed, now=NOW)
    after_expiry = datetime(2026, 7, 16, 21, 0, tzinfo=timezone.utc)
    second = archive.import_signed(signed, now=after_expiry)
    assert first == second
    assert len(list((tmp_path / "decisions").glob("*.json"))) == 1


def test_telegram_approval_uses_the_same_signed_offline_only_contract(
    tmp_path: Path,
) -> None:
    outbox = EventOutbox(tmp_path / "events")
    event, digest = _event(outbox)
    telegram = _decision(event, digest).model_copy(
        update={"channel": "telegram", "signer_id": "relay:telegram-v1"}
    )
    archive = DecisionArchive(
        tmp_path / "decisions", events=outbox, verification_key=SECRET
    )

    archive.import_signed(sign_decision(telegram, SECRET), now=NOW)
    assert len(list((tmp_path / "decisions").glob("*.json"))) == 1


def test_deny_is_terminal_and_conflicting_approval_is_rejected(tmp_path: Path) -> None:
    outbox = EventOutbox(tmp_path / "events")
    event, digest = _event(outbox)
    archive = DecisionArchive(
        tmp_path / "decisions", events=outbox, verification_key=SECRET
    )
    archive.import_signed(
        sign_decision(_decision(event, digest, action="deny"), SECRET), now=NOW
    )
    with pytest.raises(DecisionError, match="terminal"):
        archive.import_signed(
            sign_decision(_decision(event, digest), SECRET), now=NOW
        )


def test_signature_and_every_authority_binding_fail_closed(tmp_path: Path) -> None:
    outbox = EventOutbox(tmp_path / "events")
    event, digest = _event(outbox)
    archive = DecisionArchive(
        tmp_path / "decisions", events=outbox, verification_key=SECRET
    )
    decision = _decision(event, digest)
    wrong_key = sign_decision(decision, b"z" * 32)
    with pytest.raises(DecisionError, match="signature"):
        archive.import_signed(wrong_key, now=NOW)

    mutations = {
        "event_digest": "sha256:" + "0" * 64,
        "envelope_digest": "sha256:" + "0" * 64,
        "approval_binding_digest": "sha256:" + "0" * 64,
        "decision_nonce": "0" * 64,
        "human_code": "ZZZZZZZ2",
        "expires_at": "2026-07-16T20:29:00Z",
    }
    for field, value in mutations.items():
        tampered = decision.model_copy(update={field: value})
        with pytest.raises(DecisionError):
            archive.import_signed(sign_decision(tampered, SECRET), now=NOW)


def test_expired_or_future_decision_is_rejected(tmp_path: Path) -> None:
    outbox = EventOutbox(tmp_path / "events")
    event, digest = _event(outbox)
    archive = DecisionArchive(
        tmp_path / "decisions", events=outbox, verification_key=SECRET
    )
    signed = sign_decision(_decision(event, digest), SECRET)
    with pytest.raises(DecisionError, match="expired"):
        archive.import_signed(
            signed,
            now=datetime(2026, 7, 16, 20, 31, tzinfo=timezone.utc),
        )
    future = _decision(event, digest).model_copy(
        update={"issued_at": "2026-07-16T20:20:00Z"}
    )
    with pytest.raises(DecisionError, match="issue time"):
        archive.import_signed(sign_decision(future, SECRET), now=NOW)


def test_decision_schema_cannot_carry_phone_or_model_prose(tmp_path: Path) -> None:
    outbox = EventOutbox(tmp_path / "events")
    event, digest = _event(outbox)
    data = _decision(event, digest).model_dump(mode="json")
    data["phone_number"] = "+10000000000"
    with pytest.raises(ValidationError):
        HumanDecision.model_validate(data, strict=True)
    wire = sign_decision(_decision(event, digest), SECRET).model_dump_json()
    assert "+1" not in wire
    assert "rationale" not in wire
