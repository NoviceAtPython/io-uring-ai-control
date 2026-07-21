from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from urllib import request as urllib_request

import pytest

from iou_ai.events import (
    ApprovalChallenge,
    CrashCounterIncreaseEvent,
    CrashTriageEvent,
    EventOutbox,
    HangCounterIncreaseEvent,
    ProposalQuarantinedEvent,
    approval_binding_digest,
)
from iou_ai.models import TargetHashes
from iou_ai.notifier import (
    DeliveryAttemptStats,
    DeliveryReceipt,
    DeliveryReceiptStore,
    HostTelegramRelayClient,
    NotificationError,
    NotificationRelayClient,
    RELAY_USER_AGENT,
    RelayAcknowledgement,
    RelaySubmission,
    StdlibRelayTransport,
    deliver_pending,
)
from iou_ai.quarantine import canonical_json


def _event() -> CrashCounterIncreaseEvent:
    return CrashCounterIncreaseEvent(
        created_at="2026-07-16T20:00:00Z",
        campaign_id="campaign:io-uring",
        telemetry_packet_digest="sha256:" + "1" * 64,
        target_hashes=TargetHashes(
            harness_hash="sha256:" + "a" * 64,
            compiler_hash="sha256:" + "b" * 64,
            op_table_hash="sha256:" + "c" * 64,
            fleet_config_hash="sha256:" + "d" * 64,
        ),
        previous_count=0,
        current_count=1,
        increase=1,
    )


def _proposal(*, expires_at: str = "2026-07-16T20:30:00Z") -> ProposalQuarantinedEvent:
    envelope_digest = "sha256:" + "e" * 64
    nonce = "f" * 64
    human_code = "ABCDEFG2"
    target_hashes = _event().target_hashes
    return ProposalQuarantinedEvent(
        created_at="2026-07-16T20:00:00Z",
        envelope_digest=envelope_digest,
        proposal_hash="sha256:" + "9" * 64,
        target_hashes=target_hashes,
        approval=ApprovalChallenge(
            nonce=nonce,
            human_code=human_code,
            expires_at=expires_at,
            binding_digest=approval_binding_digest(
                envelope_digest=envelope_digest,
                target_hashes=target_hashes,
                nonce=nonce,
                human_code=human_code,
                expires_at=expires_at,
            ),
        ),
    )


def _high_value_triage() -> CrashTriageEvent:
    return CrashTriageEvent(
        created_at="2026-07-16T20:00:00Z",
        severity="urgent",
        campaign_id="campaign:io-uring",
        telemetry_packet_digest="sha256:" + "8" * 64,
        target_hashes=_event().target_hashes,
        stack_signature="sha256:" + "7" * 64,
        bug_class="kasan_use_after_free",
        reproductions=2,
        kernel_context_confirmed=True,
        potential_high_value=True,
    )


def _hang_event() -> HangCounterIncreaseEvent:
    return HangCounterIncreaseEvent(
        created_at="2026-07-16T20:00:00Z",
        campaign_id="campaign:io-uring",
        telemetry_packet_digest="sha256:" + "6" * 64,
        target_hashes=_event().target_hashes,
        previous_count=4,
        current_count=5,
        increase=1,
    )


class FakeTransport:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    def post(self, url, *, authorization, payload, timeout_seconds):
        self.calls.append(
            {
                "url": url,
                "authorization": authorization,
                "payload": payload,
                "timeout_seconds": timeout_seconds,
            }
        )
        submission = RelaySubmission.model_validate_json(payload, strict=True)
        acknowledgement = RelayAcknowledgement(
            event_digest=submission.event_digest,
            receipt_id="receipt:test-001",
            status="accepted",
        )
        return 201, canonical_json(acknowledgement.model_dump(mode="json"))


class OrderedTransport(FakeTransport):
    def __init__(self, *, status: str = "accepted") -> None:
        super().__init__()
        self.status = status
        self.event_kinds: list[str] = []

    def post(self, url, *, authorization, payload, timeout_seconds):
        submission = RelaySubmission.model_validate_json(payload, strict=True)
        self.event_kinds.append(submission.event.event_kind)
        acknowledgement = RelayAcknowledgement(
            event_digest=submission.event_digest,
            receipt_id=f"receipt:{len(self.event_kinds)}",
            status=self.status,
        )
        return 201, canonical_json(acknowledgement.model_dump(mode="json"))


class FakeTelegramTransport:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    def post(self, url, *, payload, timeout_seconds):
        self.calls.append(
            {"url": url, "payload": payload, "timeout_seconds": timeout_seconds}
        )
        return 200, b'{"ok":true,"result":{"message_id":41}}'


def test_delivery_sends_only_redacted_fixed_event_and_is_idempotent(
    tmp_path: Path,
) -> None:
    event = _event()
    outbox = EventOutbox(tmp_path / "events")
    outbox.put(event)
    transport = FakeTransport()
    token = "relay-secret-token-material-32-bytes"
    client = NotificationRelayClient(
        "https://notify.example.edu/v1/events",
        token,
        transport=transport,
    )
    receipts = DeliveryReceiptStore(tmp_path / "receipts")

    assert deliver_pending(outbox, receipts, client) == 1
    assert deliver_pending(outbox, receipts, client) == 0
    assert len(transport.calls) == 1
    call = transport.calls[0]
    assert call["url"] == "https://notify.example.edu/v1/events"
    assert call["authorization"] == f"Bearer {token}"
    wire = bytes(call["payload"])
    assert b"CRASH COUNTER ALERT" in wire
    assert b"untriaged" not in wire.lower() or b"Untriaged" in wire
    assert b"phone" not in wire.lower()
    assert b"proposal" not in wire.lower()
    assert token not in repr(client)
    assert len(list((tmp_path / "receipts").glob("*.json"))) == 1


def test_host_telegram_delivery_registers_then_sends_only_fixed_bound_message() -> None:
    relay_transport = FakeTransport()
    relay = NotificationRelayClient(
        "https://notify.example.edu/v1/events",
        "relay-secret-token-material-32-bytes",
        transport=relay_transport,
    )
    telegram_transport = FakeTelegramTransport()
    token = "1234567890:" + "A" * 35
    client = HostTelegramRelayClient(
        relay,
        token,
        "123456789",
        transport=telegram_transport,
    )

    acknowledgement = client.submit(_proposal())

    assert len(relay_transport.calls) == 1
    assert len(telegram_transport.calls) == 1
    assert acknowledgement.receipt_id == "telegram:41"
    assert token not in repr(client)
    call = telegram_transport.calls[0]
    assert call["url"] == f"https://api.telegram.org/bot{token}/sendMessage"
    payload = json.loads(bytes(call["payload"]))
    assert payload["chat_id"] == "123456789"
    assert payload["text"].startswith("IOU-AI APPROVAL:")
    assert payload["reply_markup"] == {
        "inline_keyboard": [
            [
                {
                    "text": "Approve (offline validation only)",
                    "callback_data": "iou-ai:approve:ABCDEFG2",
                }
            ],
            [{"text": "Deny", "callback_data": "iou-ai:deny:ABCDEFG2"}],
        ]
    }


def test_relay_submission_rejects_changed_text_or_digest() -> None:
    event = _event()
    digest = "sha256:" + hashlib.sha256(
        canonical_json(event.model_dump(mode="json"))
    ).hexdigest()
    with pytest.raises(ValueError):
        RelaySubmission(
            event_digest=digest,
            event=event,
            fixed_message="arbitrary model prose",
        )
    with pytest.raises(ValueError):
        RelaySubmission(
            event_digest="sha256:" + "0" * 64,
            event=event,
            fixed_message=(
                "IOU-AI CRASH COUNTER ALERT: campaign campaign:io-uring increased "
                "by 1 (0 to 1). Untriaged; impact and bounty status are not yet established."
            ),
        )


def test_expired_proposal_is_terminally_recorded_without_a_relay_request(
    tmp_path: Path,
) -> None:
    event = _proposal(expires_at="2026-07-16T20:00:00Z")
    outbox = EventOutbox(tmp_path / "events")
    outbox.put(event)
    transport = FakeTransport()
    client = NotificationRelayClient(
        "https://notify.example.edu/v1/events",
        "relay-secret-token-material-32-bytes",
        transport=transport,
    )
    receipts = DeliveryReceiptStore(tmp_path / "receipts")
    now = datetime(2026, 7, 16, 20, 0, tzinfo=timezone.utc)
    first_stats = DeliveryAttemptStats()
    second_stats = DeliveryAttemptStats()

    assert deliver_pending(outbox, receipts, client, now=now, stats=first_stats) == 0
    assert deliver_pending(outbox, receipts, client, now=now, stats=second_stats) == 0
    assert transport.calls == []
    assert first_stats.events_seen == 1
    assert first_stats.events_newly_expired == 1
    assert first_stats.events_already_expired == 0
    assert second_stats.events_seen == 1
    assert second_stats.events_newly_expired == 0
    assert second_stats.events_already_expired == 1

    receipt_path = next((tmp_path / "receipts").glob("*.json"))
    receipt = DeliveryReceipt.model_validate_json(receipt_path.read_bytes(), strict=True)
    assert receipt.event_digest == "sha256:" + hashlib.sha256(
        canonical_json(event.model_dump(mode="json"))
    ).hexdigest()
    assert receipt.receipt_id == "local:proposal-expired"
    assert receipt.relay_status == "expired"
    assert receipt.recorded_at == "2026-07-16T20:00:00Z"


def test_urgent_and_approval_events_precede_counter_and_hang_noise(
    tmp_path: Path,
) -> None:
    outbox = EventOutbox(tmp_path / "events")
    # Insert in an order deliberately unlike the desired delivery order; the
    # content-addressed filenames are also unrelated to severity.
    for event in (_hang_event(), _event(), _proposal(), _high_value_triage()):
        outbox.put(event)
    transport = OrderedTransport()
    client = NotificationRelayClient(
        "https://notify.example.edu/v1/events",
        "relay-secret-token-material-32-bytes",
        transport=transport,
    )

    assert deliver_pending(
        outbox,
        DeliveryReceiptStore(tmp_path / "receipts"),
        client,
        now=datetime(2026, 7, 16, 20, 0, tzinfo=timezone.utc),
    ) == 4
    assert transport.event_kinds == [
        "crash_triage",
        "proposal_quarantined",
        "crash_counter_increase",
        "hang_counter_increase",
    ]


def test_explicit_relay_rejection_is_terminal_and_not_retried(tmp_path: Path) -> None:
    outbox = EventOutbox(tmp_path / "events")
    outbox.put(_event())
    transport = OrderedTransport(status="rejected")
    client = NotificationRelayClient(
        "https://notify.example.edu/v1/events",
        "relay-secret-token-material-32-bytes",
        transport=transport,
    )
    receipts = DeliveryReceiptStore(tmp_path / "receipts")

    assert deliver_pending(outbox, receipts, client) == 1
    assert deliver_pending(outbox, receipts, client) == 0
    assert transport.event_kinds == ["crash_counter_increase"]
    receipt = DeliveryReceipt.model_validate_json(
        next((tmp_path / "receipts").glob("*.json")).read_bytes(), strict=True
    )
    assert receipt.relay_status == "rejected"


def test_stdlib_transport_disables_proxy_discovery_but_keeps_redirect_rejection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.invalid:8080")
    monkeypatch.setenv("HTTP_PROXY", "http://proxy.invalid:8080")
    monkeypatch.setattr(
        urllib_request,
        "getproxies",
        lambda: pytest.fail("relay transport must not discover proxy environment"),
    )
    transport = StdlibRelayTransport()
    proxy_handlers = [
        handler
        for handler in transport._opener.handlers  # noqa: SLF001 - transport invariant
        if isinstance(handler, urllib_request.ProxyHandler)
    ]
    assert not proxy_handlers or all(handler.proxies == {} for handler in proxy_handlers)
    redirect_handler = next(
        handler
        for handler in transport._opener.handlers  # noqa: SLF001 - transport invariant
        if type(handler).__name__ == "_RejectRedirects"
    )
    assert (
        redirect_handler.redirect_request(
            None,
            None,
            302,
            "Found",
            None,
            "https://other.example.edu/",
        )
        is None
    )


def test_stdlib_transport_uses_fixed_service_user_agent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Response:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self, _limit: int) -> bytes:
            return b"{}"

    requests: list[urllib_request.Request] = []
    transport = StdlibRelayTransport()

    def open_request(request: urllib_request.Request, *, timeout: float):
        assert timeout == 5.0
        requests.append(request)
        return Response()

    monkeypatch.setattr(transport._opener, "open", open_request)  # noqa: SLF001
    transport.post(
        "https://notify.example.edu/v1/events",
        authorization="Bearer relay-token",
        payload=b"{}",
        timeout_seconds=5.0,
    )
    transport.get(
        "https://notify.example.edu/v1/ready",
        authorization="Bearer relay-token",
        timeout_seconds=5.0,
    )

    assert [request.get_header("User-agent") for request in requests] == [
        RELAY_USER_AGENT,
        RELAY_USER_AGENT,
    ]
    with pytest.raises(NotificationError):
        transport.get(
            "https://notify.example.edu/v1/ready",
            authorization="Bearer relay-token",
            timeout_seconds=5.0,
            extra_headers={"User-Agent": "override"},
        )


@pytest.mark.parametrize(
    "endpoint",
    [
        "http://notify.example.edu/v1/events",
        "https://notify.example.edu/v1/other",
        "https://notify.example.edu/v1/events?redirect=x",
        "https://user:pass@notify.example.edu/v1/events",
    ],
)
def test_relay_endpoint_is_exact_https_without_credentials(endpoint: str) -> None:
    with pytest.raises(NotificationError):
        NotificationRelayClient(endpoint, "token")
