from __future__ import annotations

import hashlib
import hmac
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

from iou_ai.decisions import HumanDecision, SignedDecision, sign_decision
from iou_ai.events import CrashCounterIncreaseEvent, EventOutbox
from iou_ai.models import TargetHashes
from iou_ai.notifier import (
    DecisionInbox,
    DeliveryReceiptStore,
    NotificationError,
    NotificationRelayClient,
    RelayAcknowledgement,
    RelayCursorStore,
    RelayDecisionPage,
    RelaySubmission,
    deliver_pending,
    poll_decisions,
)
from iou_ai.notify_cli import (
    configure_telegram_webhook,
    pair_telegram,
    probe_readiness,
    run_once,
)
from iou_ai.quarantine import canonical_json


SECRET = b"relay-decision-test-key-material-32bytes"
TOKEN = "bounded-relay-token-material-32-bytes"


def _hashes() -> TargetHashes:
    return TargetHashes(
        harness_hash="sha256:" + "a" * 64,
        compiler_hash="sha256:" + "b" * 64,
        op_table_hash="sha256:" + "c" * 64,
        fleet_config_hash="sha256:" + "d" * 64,
    )


def _event() -> CrashCounterIncreaseEvent:
    return CrashCounterIncreaseEvent(
        created_at="2026-07-16T20:00:00Z",
        campaign_id="campaign:io-uring",
        telemetry_packet_digest="sha256:" + "1" * 64,
        target_hashes=_hashes(),
        previous_count=0,
        current_count=1,
        increase=1,
    )


def _signed_decision() -> SignedDecision:
    decision = HumanDecision(
        event_digest="sha256:" + "2" * 64,
        envelope_digest="sha256:" + "3" * 64,
        target_hashes=_hashes(),
        approval_binding_digest="sha256:" + "4" * 64,
        decision_nonce="5" * 64,
        human_code="ABCDEFG2",
        sender_binding="sha256:" + "6" * 64,
        action="approve_for_offline_validation",
        reason_code="operator_approved",
        issued_at="2026-07-16T20:01:00Z",
        expires_at="2026-07-16T20:30:00Z",
    )
    return sign_decision(decision, SECRET)


class RelayTransport:
    def __init__(self, signed: SignedDecision) -> None:
        self.signed = signed
        self.post_calls: list[tuple[str, str]] = []
        self.get_calls: list[tuple[str, str]] = []

    def post(self, url, *, authorization, payload, timeout_seconds):
        submission = RelaySubmission.model_validate_json(payload, strict=True)
        self.post_calls.append((url, authorization))
        acknowledgement = RelayAcknowledgement(
            event_digest=submission.event_digest,
            receipt_id="receipt:test-relay",
            status="accepted",
        )
        return 201, canonical_json(acknowledgement.model_dump(mode="json"))

    def get(self, url, *, authorization, timeout_seconds):
        self.get_calls.append((url, authorization))
        after = parse_qs(urlsplit(url).query, strict_parsing=True)["after"][0]
        page = (
            RelayDecisionPage(data=(self.signed,), next_cursor="1")
            if after == "0"
            else RelayDecisionPage(data=(), next_cursor=after)
        )
        return 200, canonical_json(page.model_dump(mode="json"))


class TelegramTransport:
    def __init__(self) -> None:
        self.calls: list[bytes] = []

    def post(self, url, *, payload, timeout_seconds):
        assert url.startswith("https://api.telegram.org/bot")
        assert timeout_seconds == 20.0
        self.calls.append(payload)
        return 200, b'{"ok":true,"result":{"message_id":17}}'


def test_one_run_delivers_events_and_persists_inert_decisions_and_cursor(
    tmp_path: Path,
) -> None:
    EventOutbox(tmp_path / "events").put(_event())
    (tmp_path / "endpoint").write_text(
        "https://notify.example.edu/v1/events\n", encoding="ascii"
    )
    token = TOKEN
    (tmp_path / "token").write_text(token + "\n", encoding="ascii")
    signed = _signed_decision()
    transport = RelayTransport(signed)

    result = run_once(
        events=tmp_path / "events",
        receipts=tmp_path / "receipts",
        decision_inbox=tmp_path / "inbox",
        state_dir=tmp_path / "state",
        endpoint_file=tmp_path / "endpoint",
        token_file=tmp_path / "token",
        transport=transport,
    )

    assert result == {
        "status": "relay_complete",
        "events_delivered": 1,
        "events_seen": 1,
        "events_already_delivered": 0,
        "events_already_rejected": 0,
        "events_already_expired": 0,
        "events_newly_expired": 0,
        "events_failed": 0,
        "decisions_received": 1,
        "decisions_stored": 1,
        "decision_cursor": "1",
    }
    assert transport.post_calls == [
        ("https://notify.example.edu/v1/events", f"Bearer {token}")
    ]
    assert transport.get_calls == [
        ("https://notify.example.edu/v1/decisions?after=0", f"Bearer {token}")
    ]
    payload = canonical_json(signed.model_dump(mode="json"))
    digest = hashlib.sha256(payload).hexdigest()
    assert (tmp_path / "inbox" / f"{digest}.json").read_bytes() == payload
    cursor_files = list((tmp_path / "state" / "decision-cursors").glob("*.json"))
    assert len(cursor_files) == 1

    result = run_once(
        events=tmp_path / "events",
        receipts=tmp_path / "receipts",
        decision_inbox=tmp_path / "inbox",
        state_dir=tmp_path / "state",
        endpoint_file=tmp_path / "endpoint",
        token_file=tmp_path / "token",
        transport=transport,
    )
    assert result["events_delivered"] == 0
    assert result["events_seen"] == 1
    assert result["events_already_delivered"] == 1
    assert result["decisions_received"] == 0
    assert result["decision_cursor"] == "1"
    assert transport.get_calls[-1][0].endswith("/v1/decisions?after=1")
    assert len(list((tmp_path / "state" / "decision-cursors").glob("*.json"))) == 1


def test_run_once_uses_host_telegram_credentials_only_for_fixed_delivery(
    tmp_path: Path,
) -> None:
    EventOutbox(tmp_path / "events").put(_event())
    (tmp_path / "endpoint").write_text(
        "https://notify.example.edu/v1/events\n", encoding="ascii"
    )
    (tmp_path / "token").write_text(TOKEN + "\n", encoding="ascii")
    bot_token = "1234567890:" + "A" * 35
    (tmp_path / "telegram-bot").write_text(bot_token, encoding="ascii")
    (tmp_path / "telegram-chat").write_text("123456789", encoding="ascii")
    relay_transport = RelayTransport(_signed_decision())
    telegram_transport = TelegramTransport()

    result = run_once(
        events=tmp_path / "events",
        receipts=tmp_path / "receipts",
        decision_inbox=tmp_path / "inbox",
        state_dir=tmp_path / "state",
        endpoint_file=tmp_path / "endpoint",
        token_file=tmp_path / "token",
        telegram_bot_token_file=tmp_path / "telegram-bot",
        telegram_chat_id_file=tmp_path / "telegram-chat",
        transport=relay_transport,
        telegram_transport=telegram_transport,
    )

    assert result["events_delivered"] == 1
    assert len(telegram_transport.calls) == 1
    assert b"CRASH COUNTER ALERT" in telegram_transport.calls[0]
    assert bot_token.encode("ascii") not in telegram_transport.calls[0]


def test_cursor_advances_only_after_every_bundle_is_durable(tmp_path: Path) -> None:
    transport = RelayTransport(_signed_decision())
    client = NotificationRelayClient(
        "https://notify.example.edu/v1/events",
        TOKEN,
        transport=transport,
    )
    cursors = RelayCursorStore(tmp_path / "cursors")

    class FailingInbox:
        def put(self, signed):
            raise NotificationError("simulated durable storage failure")

    with pytest.raises(NotificationError, match="durable storage"):
        poll_decisions(client, FailingInbox(), cursors)  # type: ignore[arg-type]
    assert cursors.current(client.endpoint_binding) == "0"
    assert not (tmp_path / "cursors").exists()


@pytest.mark.parametrize(
    ("data", "next_cursor", "message"),
    [
        ((), "1", "empty page"),
        ((_signed_decision(),), "0", "without advancing"),
        ((_signed_decision(),), "7", "skipped decision sequence"),
    ],
)
def test_decision_page_cannot_skip_or_reuse_a_cursor(
    data: tuple[SignedDecision, ...],
    next_cursor: str,
    message: str,
) -> None:
    class BadTransport:
        def get(self, url, *, authorization, timeout_seconds):
            page = RelayDecisionPage(data=data, next_cursor=next_cursor)
            return 200, canonical_json(page.model_dump(mode="json"))

        def post(self, url, *, authorization, payload, timeout_seconds):
            raise AssertionError("not used")

    client = NotificationRelayClient(
        "https://notify.example.edu/v1/events",
        TOKEN,
        transport=BadTransport(),
    )
    with pytest.raises(NotificationError, match=message):
        client.decisions("0")


def test_duplicate_signed_items_in_one_page_are_rejected() -> None:
    signed = _signed_decision()
    with pytest.raises(ValueError, match="duplicates"):
        RelayDecisionPage(data=(signed, signed), next_cursor="2")


def test_tampered_receipt_cannot_suppress_delivery(tmp_path: Path) -> None:
    outbox = EventOutbox(tmp_path / "events")
    outbox.put(_event())
    transport = RelayTransport(_signed_decision())
    client = NotificationRelayClient(
        "https://notify.example.edu/v1/events",
        TOKEN,
        transport=transport,
    )
    receipts = DeliveryReceiptStore(tmp_path / "receipts")
    assert deliver_pending(outbox, receipts, client) == 1
    receipt = next((tmp_path / "receipts").glob("*.json"))
    receipt.chmod(0o660)
    receipt.write_bytes(b"{}")
    with pytest.raises(NotificationError, match="invalid"):
        deliver_pending(outbox, receipts, client)
    assert len(transport.post_calls) == 1


def test_one_remote_delivery_failure_does_not_block_other_events_or_decisions(
    tmp_path: Path,
) -> None:
    first = _event()
    second = first.model_copy(
        update={
            "telemetry_packet_digest": "sha256:" + "9" * 64,
            "current_count": 2,
            "increase": 2,
        }
    )
    outbox = EventOutbox(tmp_path / "events")
    outbox.put(first)
    outbox.put(second)
    (tmp_path / "endpoint").write_text(
        "https://notify.example.edu/v1/events\n", encoding="ascii"
    )
    (tmp_path / "token").write_text(TOKEN + "\n", encoding="ascii")

    class PartialTransport(RelayTransport):
        def __init__(self, signed: SignedDecision) -> None:
            super().__init__(signed)
            self.attempts = 0

        def post(self, url, *, authorization, payload, timeout_seconds):
            self.attempts += 1
            if self.attempts == 1:
                raise NotificationError("simulated remote failure")
            return super().post(
                url,
                authorization=authorization,
                payload=payload,
                timeout_seconds=timeout_seconds,
            )

    transport = PartialTransport(_signed_decision())
    with pytest.raises(NotificationError, match="delivery_failures=1"):
        run_once(
            events=tmp_path / "events",
            receipts=tmp_path / "receipts",
            decision_inbox=tmp_path / "inbox",
            state_dir=tmp_path / "state",
            endpoint_file=tmp_path / "endpoint",
            token_file=tmp_path / "token",
            transport=transport,
        )
    assert transport.attempts == 2
    assert len(list((tmp_path / "receipts").glob("*.json"))) == 1
    assert len(list((tmp_path / "inbox").glob("*.json"))) == 1
    assert RelayCursorStore(tmp_path / "state" / "decision-cursors").current(
        NotificationRelayClient(
            "https://notify.example.edu/v1/events", TOKEN, transport=transport
        ).endpoint_binding
    ) == "1"


def test_relay_token_must_have_at_least_32_printable_ascii_bytes() -> None:
    with pytest.raises(NotificationError, match="credential is invalid"):
        NotificationRelayClient(
            "https://notify.example.edu/v1/events",
            "too-short",
            transport=RelayTransport(_signed_decision()),
        )


def test_authenticated_readiness_probe_uses_only_the_fixed_no_write_route(
    tmp_path: Path,
) -> None:
    (tmp_path / "endpoint").write_text(
        "https://notify.example.edu/v1/events\n", encoding="ascii"
    )
    (tmp_path / "token").write_text(TOKEN + "\n", encoding="ascii")
    (tmp_path / "decision.key").write_bytes(SECRET + b"\n")

    class ProbeTransport:
        def __init__(self) -> None:
            self.get_calls: list[tuple[str, str]] = []

        def get(self, url, *, authorization, timeout_seconds, extra_headers=None):
            self.get_calls.append((url, authorization))
            assert extra_headers is not None
            nonce = extra_headers["X-IOU-Relay-Nonce"]
            assert len(nonce) == 64
            assert extra_headers["X-IOU-Relay-Proof"] == hmac.new(
                SECRET,
                f"relay-ready.v1:{nonce}".encode("ascii"),
                hashlib.sha256,
            ).hexdigest()
            return 200, canonical_json(
                {"schema_version": "relay-ready.v1", "status": "ready"}
            )

        def post(self, url, *, authorization, payload, timeout_seconds):
            raise AssertionError("a readiness probe must never submit an event")

    transport = ProbeTransport()
    assert probe_readiness(
        endpoint_file=tmp_path / "endpoint",
        token_file=tmp_path / "token",
        decision_key_file=tmp_path / "decision.key",
        transport=transport,
    ) == {"status": "relay_ready"}
    assert transport.get_calls == [
        ("https://notify.example.edu/v1/ready", f"Bearer {TOKEN}")
    ]


def test_readiness_probe_rejects_a_noncanonical_or_wrong_response() -> None:
    class BadReadinessTransport:
        def get(self, url, *, authorization, timeout_seconds, extra_headers=None):
            return 200, b'{"status":"ready","schema_version":"relay-ready.v1"}'

        def post(self, url, *, authorization, payload, timeout_seconds):
            raise AssertionError("not used")

    client = NotificationRelayClient(
        "https://notify.example.edu/v1/events",
        TOKEN,
        transport=BadReadinessTransport(),
    )
    with pytest.raises(NotificationError, match="not canonical"):
        client.readiness(SECRET)

    with pytest.raises(NotificationError, match="decision credential is invalid"):
        client.readiness(b"too-short")


def test_telegram_setup_routes_are_hmac_bound_content_free_and_canonical(
    tmp_path: Path,
) -> None:
    (tmp_path / "endpoint").write_text(
        "https://notify.example.edu/v1/events\n", encoding="ascii"
    )
    (tmp_path / "token").write_text(TOKEN + "\n", encoding="ascii")
    (tmp_path / "decision.key").write_bytes(SECRET + b"\n")

    class TelegramSetupTransport:
        def __init__(self) -> None:
            self.post_calls: list[tuple[str, bytes, dict[str, str]]] = []

        def post(
            self,
            url,
            *,
            authorization,
            payload,
            timeout_seconds,
            extra_headers=None,
        ):
            assert authorization == f"Bearer {TOKEN}"
            assert payload == b""
            assert extra_headers is not None
            nonce = extra_headers["X-IOU-Relay-Nonce"]
            assert len(nonce) == 64
            if url.endswith("/pair"):
                label = "telegram-pair.v1"
                body = {"schema_version": "telegram-pair.v1", "status": "paired"}
            elif url.endswith("/configure-webhook"):
                label = "telegram-webhook.v1"
                body = {
                    "schema_version": "telegram-webhook.v1",
                    "status": "configured",
                }
            else:
                raise AssertionError("unexpected control route")
            assert extra_headers["X-IOU-Relay-Proof"] == hmac.new(
                SECRET,
                f"{label}:{nonce}".encode("ascii"),
                hashlib.sha256,
            ).hexdigest()
            self.post_calls.append((url, payload, dict(extra_headers)))
            return 200, canonical_json(body)

        def get(self, url, *, authorization, timeout_seconds, extra_headers=None):
            raise AssertionError("Telegram setup must not poll or deliver")

    transport = TelegramSetupTransport()
    assert pair_telegram(
        endpoint_file=tmp_path / "endpoint",
        token_file=tmp_path / "token",
        decision_key_file=tmp_path / "decision.key",
        transport=transport,
    ) == {"status": "telegram_paired"}
    assert configure_telegram_webhook(
        endpoint_file=tmp_path / "endpoint",
        token_file=tmp_path / "token",
        decision_key_file=tmp_path / "decision.key",
        transport=transport,
    ) == {"status": "telegram_webhook_configured"}
    assert [url for url, _, _ in transport.post_calls] == [
        "https://notify.example.edu/v1/telegram/pair",
        "https://notify.example.edu/v1/telegram/configure-webhook",
    ]
    assert all(not payload for _, payload, _ in transport.post_calls)


def test_telegram_setup_rejects_noncanonical_response() -> None:
    class BadTelegramTransport:
        def post(
            self,
            url,
            *,
            authorization,
            payload,
            timeout_seconds,
            extra_headers=None,
        ):
            return 200, b'{"status":"paired","schema_version":"telegram-pair.v1"}'

    client = NotificationRelayClient(
        "https://notify.example.edu/v1/events",
        TOKEN,
        transport=BadTelegramTransport(),
    )
    with pytest.raises(NotificationError, match="not canonical"):
        client.pair_telegram(SECRET)


def test_cli_credential_files_are_single_line_and_bounded(tmp_path: Path) -> None:
    (tmp_path / "endpoint").write_text(
        "https://notify.example.edu/v1/events\nextra\n", encoding="ascii"
    )
    (tmp_path / "token").write_text(TOKEN + "\n", encoding="ascii")
    with pytest.raises(NotificationError, match="exactly one line"):
        run_once(
            events=tmp_path / "events",
            receipts=tmp_path / "receipts",
            decision_inbox=tmp_path / "inbox",
            state_dir=tmp_path / "state",
            endpoint_file=tmp_path / "endpoint",
            token_file=tmp_path / "token",
            transport=RelayTransport(_signed_decision()),
        )

    (tmp_path / "endpoint").write_bytes(b"x" * 2049)
    with pytest.raises(NotificationError, match="size limit"):
        run_once(
            events=tmp_path / "events",
            receipts=tmp_path / "receipts",
            decision_inbox=tmp_path / "inbox",
            state_dir=tmp_path / "state",
            endpoint_file=tmp_path / "endpoint",
            token_file=tmp_path / "token",
            transport=RelayTransport(_signed_decision()),
        )
