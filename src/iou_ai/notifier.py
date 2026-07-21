"""Exact-host HTTPS relay for already-redacted notification events.

The relay, not the Michigan host, owns the destination number and SMS-provider
credential.  This client can read only the redacted outbox and stores immutable
delivery receipts.  It cannot read quarantine, provider credentials, or fleet
state and it has no approval/execution authority.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
from typing import Annotated, Literal, Protocol
from urllib import error as urllib_error
from urllib import parse as urllib_parse
from urllib import request as urllib_request

from pydantic import Field, model_validator

from . import __version__
from .decisions import SignedDecision
from .events import (
    BudgetThresholdEvent,
    CrashCounterIncreaseEvent,
    CrashTriageEvent,
    EventOutbox,
    ExecutionReadyEvent,
    HangCounterIncreaseEvent,
    ProposalQuarantinedEvent,
    RedactedEvent,
    parse_event,
    render_fixed_message,
)
from .models import Digest, Identifier, StrictModel, Timestamp
from .quarantine import canonical_json


class NotificationError(RuntimeError):
    pass


class NotificationBatchError(NotificationError):
    """Some remote submissions failed after all pending events were attempted."""

    def __init__(self, *, delivered: int, failed: int) -> None:
        self.delivered = delivered
        self.failed = failed
        super().__init__(f"{failed} notification event deliveries failed")


@dataclass
class DeliveryAttemptStats:
    """Redacted counters explaining one idempotent delivery pass."""

    events_seen: int = 0
    events_delivered: int = 0
    events_already_delivered: int = 0
    events_already_rejected: int = 0
    events_already_expired: int = 0
    events_newly_expired: int = 0
    events_failed: int = 0


RELAY_USER_AGENT = f"iou-ai-notify/{__version__}"
TELEGRAM_USER_AGENT = f"iou-ai-telegram/{__version__}"


class RelaySubmission(StrictModel):
    schema_version: Literal["relay-submission.v1"] = "relay-submission.v1"
    event_digest: Digest
    event: RedactedEvent
    fixed_message: Annotated[str, Field(min_length=1, max_length=480)]

    @model_validator(mode="after")
    def bind_redacted_event_and_fixed_text(self) -> "RelaySubmission":
        expected_digest = "sha256:" + hashlib.sha256(
            canonical_json(self.event.model_dump(mode="json"))
        ).hexdigest()
        if self.event_digest != expected_digest:
            raise ValueError("relay submission event digest mismatch")
        if self.fixed_message != render_fixed_message(self.event):
            raise ValueError("relay submission text is not the local fixed template")
        return self


class RelayAcknowledgement(StrictModel):
    schema_version: Literal["relay-ack.v1"] = "relay-ack.v1"
    event_digest: Digest
    receipt_id: Identifier
    # ``rejected`` is a terminal, relay-authenticated disposition.  It is not
    # an approval decision and does not grant any fuzzer authority; recording
    # it simply prevents an explicitly rejected redacted alert from retrying
    # indefinitely.
    status: Literal["accepted", "duplicate", "rejected"]


class RelayReadiness(StrictModel):
    """Authenticated, side-effect-free relay readiness response.

    The activation path must never manufacture a redacted event merely to test
    the phone relay: posting an event can cause an SMS delivery and can create
    approval state.  This deliberately tiny response is accepted only from the
    separate ``GET /v1/ready`` route, which performs no writes at the relay.
    """

    schema_version: Literal["relay-ready.v1"] = "relay-ready.v1"
    status: Literal["ready"] = "ready"


class TelegramPairing(StrictModel):
    """A deliberately content-free acknowledgement of private-chat pairing."""

    schema_version: Literal["telegram-pair.v1"] = "telegram-pair.v1"
    status: Literal["paired"] = "paired"


class TelegramWebhookConfiguration(StrictModel):
    """A deliberately content-free acknowledgement of webhook installation."""

    schema_version: Literal["telegram-webhook.v1"] = "telegram-webhook.v1"
    status: Literal["configured"] = "configured"


class DeliveryReceipt(StrictModel):
    schema_version: Literal["delivery-receipt.v1"] = "delivery-receipt.v1"
    event_digest: Digest
    receipt_id: Identifier
    # ``expired`` is a host-local terminal disposition for an approval
    # challenge that can no longer be acted on.  It is deliberately distinct
    # from relay dispositions and is written without contacting the relay.
    relay_status: Literal["accepted", "duplicate", "rejected", "expired"]
    recorded_at: Timestamp


RelayCursor = Annotated[
    str,
    Field(pattern=r"^(?:0|[1-9][0-9]{0,17})$"),
]


class RelayDecisionPage(StrictModel):
    schema_version: Literal["relay-decisions.v1"] = "relay-decisions.v1"
    data: Annotated[tuple[SignedDecision, ...], Field(max_length=100)]
    next_cursor: RelayCursor

    @model_validator(mode="after")
    def reject_duplicate_decisions(self) -> "RelayDecisionPage":
        digests = {
            hashlib.sha256(
                canonical_json(item.model_dump(mode="json"))
            ).hexdigest()
            for item in self.data
        }
        if len(digests) != len(self.data):
            raise ValueError("relay decision page contains duplicates")
        return self


class RelayCursorCheckpoint(StrictModel):
    schema_version: Literal["relay-cursor.v1"] = "relay-cursor.v1"
    endpoint_binding: Digest
    next_cursor: RelayCursor


class RelayTransport(Protocol):
    def post(
        self,
        url: str,
        *,
        authorization: str,
        payload: bytes,
        timeout_seconds: float,
        extra_headers: Mapping[str, str] | None = None,
    ) -> tuple[int, bytes]: ...

    def get(
        self,
        url: str,
        *,
        authorization: str,
        timeout_seconds: float,
        extra_headers: Mapping[str, str] | None = None,
    ) -> tuple[int, bytes]: ...


class TelegramTransport(Protocol):
    def post(
        self,
        url: str,
        *,
        payload: bytes,
        timeout_seconds: float,
    ) -> tuple[int, bytes]: ...

class _RejectRedirects(urllib_request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class StdlibRelayTransport:
    def __init__(self, *, max_response_bytes: int = 256 * 1024) -> None:
        if max_response_bytes <= 0:
            raise ValueError("max_response_bytes must be positive")
        self._max_response_bytes = max_response_bytes
        # Supplying an explicit empty ProxyHandler prevents urllib from
        # discovering proxy settings through HTTP(S)_PROXY/NO_PROXY or other
        # process environment.  The notifier has one exact relay endpoint and
        # must make a direct connection to it; redirects remain explicitly
        # rejected below.
        self._opener = urllib_request.build_opener(
            urllib_request.ProxyHandler({}),
            _RejectRedirects(),
        )

    def _send(
        self,
        request: urllib_request.Request,
        *,
        timeout_seconds: float,
    ) -> tuple[int, bytes]:
        try:
            with self._opener.open(request, timeout=timeout_seconds) as response:
                body = response.read(self._max_response_bytes + 1)
                status = int(response.status)
        except urllib_error.HTTPError as exc:
            # Do not propagate a provider-controlled body or redirect location.
            raise NotificationError(f"notification relay HTTP {int(exc.code)}") from None
        except (urllib_error.URLError, TimeoutError, OSError):
            raise NotificationError("notification relay connection failed") from None
        if len(body) > self._max_response_bytes:
            raise NotificationError("notification relay response exceeded the size limit")
        return status, body

    def post(
        self,
        url: str,
        *,
        authorization: str,
        payload: bytes,
        timeout_seconds: float,
        extra_headers: Mapping[str, str] | None = None,
    ) -> tuple[int, bytes]:
        headers = {
            "Authorization": authorization,
            "Content-Type": "application/json",
            "User-Agent": RELAY_USER_AGENT,
        }
        headers.update(_validated_extra_headers(extra_headers))
        request = urllib_request.Request(
            url,
            data=payload,
            headers=headers,
            method="POST",
        )
        return self._send(request, timeout_seconds=timeout_seconds)

    def get(
        self,
        url: str,
        *,
        authorization: str,
        timeout_seconds: float,
        extra_headers: Mapping[str, str] | None = None,
    ) -> tuple[int, bytes]:
        headers = {
            "Authorization": authorization,
            "Accept": "application/json",
            "User-Agent": RELAY_USER_AGENT,
        }
        headers.update(_validated_extra_headers(extra_headers))
        request = urllib_request.Request(
            url,
            headers=headers,
            method="GET",
        )
        return self._send(request, timeout_seconds=timeout_seconds)


class StdlibTelegramTransport:
    """Exact Telegram HTTPS transport with no proxy or redirect discovery."""

    def __init__(self, *, max_response_bytes: int = 64 * 1024) -> None:
        if max_response_bytes <= 0:
            raise ValueError("max_response_bytes must be positive")
        self._max_response_bytes = max_response_bytes
        self._opener = urllib_request.build_opener(
            urllib_request.ProxyHandler({}),
            _RejectRedirects(),
        )

    def post(
        self,
        url: str,
        *,
        payload: bytes,
        timeout_seconds: float,
    ) -> tuple[int, bytes]:
        request = urllib_request.Request(
            url,
            data=payload,
            headers={
                "Content-Type": "application/json",
                "User-Agent": TELEGRAM_USER_AGENT,
            },
            method="POST",
        )
        try:
            with self._opener.open(request, timeout=timeout_seconds) as response:
                body = response.read(self._max_response_bytes + 1)
                status = int(response.status)
        except urllib_error.HTTPError as exc:
            if 400 <= int(exc.code) < 500 and int(exc.code) not in {408, 429}:
                raise NotificationError("Telegram rejected the redacted notification") from None
            raise NotificationError("Telegram notification acceptance is uncertain") from None
        except (urllib_error.URLError, TimeoutError, OSError):
            raise NotificationError("Telegram notification connection failed") from None
        if len(body) > self._max_response_bytes:
            raise NotificationError("Telegram notification response exceeded the size limit")
        return status, body

def _validated_extra_headers(
    extra_headers: Mapping[str, str] | None,
) -> dict[str, str]:
    """Allow a small, non-smuggling header set for HMAC setup/probe routes."""

    if not extra_headers:
        return {}
    blocked = {
        "authorization",
        "accept",
        "content-type",
        "host",
        "content-length",
        "user-agent",
    }
    result: dict[str, str] = {}
    for name, value in extra_headers.items():
        if (
            not re.fullmatch(r"[A-Za-z0-9-]{1,64}", name)
            or name.casefold() in blocked
            or not value
            or len(value) > 512
            or "\r" in value
            or "\n" in value
        ):
            raise NotificationError("notification relay control headers are invalid")
        result[name] = value
    return result


def _validate_endpoint(endpoint: str) -> str:
    parsed = urllib_parse.urlsplit(endpoint)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path != "/v1/events"
    ):
        raise NotificationError("notification endpoint must be an exact HTTPS /v1/events URL")
    return endpoint


def _decision_url(endpoint: str, after_cursor: RelayCursor) -> str:
    parsed = urllib_parse.urlsplit(_validate_endpoint(endpoint))
    return urllib_parse.urlunsplit(
        (
            parsed.scheme,
            parsed.netloc,
            "/v1/decisions",
            urllib_parse.urlencode({"after": after_cursor}),
            "",
        )
    )


def _readiness_url(endpoint: str) -> str:
    """Derive the one exact, authenticated, no-write readiness route."""

    parsed = urllib_parse.urlsplit(_validate_endpoint(endpoint))
    return urllib_parse.urlunsplit(
        (
            parsed.scheme,
            parsed.netloc,
            "/v1/ready",
            "",
            "",
        )
    )


def _telegram_control_url(endpoint: str, control: str) -> str:
    """Derive an exact Telegram control route from the event-only endpoint."""

    if control not in {"pair", "configure-webhook"}:
        raise NotificationError("notification relay Telegram control is invalid")
    parsed = urllib_parse.urlsplit(_validate_endpoint(endpoint))
    return urllib_parse.urlunsplit(
        (
            parsed.scheme,
            parsed.netloc,
            f"/v1/telegram/{control}",
            "",
            "",
        )
    )


def _endpoint_binding(endpoint: str) -> str:
    decision_endpoint = _decision_url(endpoint, "0").partition("?")[0]
    return "sha256:" + hashlib.sha256(decision_endpoint.encode("utf-8")).hexdigest()


def _readiness_decision_key(value: bytes) -> bytes:
    """Validate the exact HMAC material shared with the decision importer."""

    if not isinstance(value, bytes) or len(value) < 32 or len(value) > 4096:
        raise NotificationError("notification relay decision credential is invalid")
    try:
        text = value.decode("ascii")
    except UnicodeDecodeError as exc:
        raise NotificationError("notification relay decision credential is invalid") from exc
    if any(ord(character) < 0x21 or ord(character) > 0x7E for character in text):
        raise NotificationError("notification relay decision credential is invalid")
    return value


class NotificationRelayClient:
    def __init__(
        self,
        endpoint: str,
        bearer_token: str,
        *,
        transport: RelayTransport | None = None,
        timeout_seconds: float = 20.0,
    ) -> None:
        if (
            not bearer_token
            or bearer_token != bearer_token.strip()
            or len(bearer_token) < 32
            or len(bearer_token) > 4096
            or any(ord(character) < 0x21 or ord(character) > 0x7E for character in bearer_token)
        ):
            raise NotificationError("notification credential is invalid")
        if timeout_seconds <= 0 or timeout_seconds > 60:
            raise NotificationError("notification timeout must be in (0, 60] seconds")
        self.endpoint = _validate_endpoint(endpoint)
        self._bearer_token = bearer_token
        self._transport = transport or StdlibRelayTransport()
        self._timeout_seconds = timeout_seconds

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}(endpoint={self.endpoint!r}, "
            f"timeout_seconds={self._timeout_seconds!r})"
        )

    def submit(self, event: RedactedEvent) -> RelayAcknowledgement:
        submission = RelaySubmission(
            event_digest="sha256:" + hashlib.sha256(
                canonical_json(event.model_dump(mode="json"))
            ).hexdigest(),
            event=event,
            fixed_message=render_fixed_message(event),
        )
        status, body = self._transport.post(
            self.endpoint,
            authorization=f"Bearer {self._bearer_token}",
            payload=canonical_json(submission.model_dump(mode="json")),
            timeout_seconds=self._timeout_seconds,
        )
        if status not in {200, 201}:
            raise NotificationError(f"notification relay HTTP {status}")
        try:
            acknowledgement = RelayAcknowledgement.model_validate_json(body, strict=True)
        except Exception as exc:
            raise NotificationError("notification relay acknowledgement is invalid") from exc
        if acknowledgement.event_digest != submission.event_digest:
            raise NotificationError("notification relay acknowledged the wrong event")
        return acknowledgement

    @property
    def endpoint_binding(self) -> str:
        return _endpoint_binding(self.endpoint)

    def readiness(self, decision_key: bytes) -> RelayReadiness:
        """Check relay configuration with one authenticated read-only GET.

        This method intentionally has no event, decision, receipt, cursor, or
        filesystem arguments.  A caller cannot accidentally turn the readiness
        check into a delivery or approval operation.  It proves the local
        decision-import key matches the relay's HMAC secret using a fresh
        challenge; the key itself is never transmitted.
        """

        key = _readiness_decision_key(decision_key)
        nonce = secrets.token_hex(32)
        proof = hmac.new(
            key,
            f"relay-ready.v1:{nonce}".encode("ascii"),
            hashlib.sha256,
        ).hexdigest()
        status, body = self._transport.get(
            _readiness_url(self.endpoint),
            authorization=f"Bearer {self._bearer_token}",
            timeout_seconds=self._timeout_seconds,
            extra_headers={
                "X-IOU-Relay-Nonce": nonce,
                "X-IOU-Relay-Proof": proof,
            },
        )
        if status != 200:
            raise NotificationError("notification relay readiness check failed")
        try:
            readiness = RelayReadiness.model_validate_json(body, strict=True)
        except Exception as exc:
            raise NotificationError("notification relay readiness response is invalid") from exc
        if canonical_json(readiness.model_dump(mode="json")) != body:
            raise NotificationError("notification relay readiness response is not canonical")
        return readiness

    def _telegram_setup(self, decision_key: bytes, *, control: str, proof_label: str) -> bytes:
        """Call one narrow, HMAC-bound Telegram setup route.

        These routes have no event payload and never return a recipient or bot
        identifier. Pairing performs at most one private-chat binding; webhook
        configuration performs Telegram's callback-only registration. Neither
        route has fuzzer, compiler, or approval authority.
        """

        key = _readiness_decision_key(decision_key)
        nonce = secrets.token_hex(32)
        proof = hmac.new(
            key,
            f"{proof_label}:{nonce}".encode("ascii"),
            hashlib.sha256,
        ).hexdigest()
        status, body = self._transport.post(
            _telegram_control_url(self.endpoint, control),
            authorization=f"Bearer {self._bearer_token}",
            payload=b"",
            timeout_seconds=self._timeout_seconds,
            extra_headers={
                "X-IOU-Relay-Nonce": nonce,
                "X-IOU-Relay-Proof": proof,
            },
        )
        if status != 200:
            raise NotificationError("notification relay Telegram setup failed")
        return body

    def pair_telegram(self, decision_key: bytes) -> TelegramPairing:
        """Bind the sole private Telegram `/start` sender without exposing it."""

        body = self._telegram_setup(
            decision_key,
            control="pair",
            proof_label="telegram-pair.v1",
        )
        try:
            pairing = TelegramPairing.model_validate_json(body, strict=True)
        except Exception as exc:
            raise NotificationError(
                "notification relay Telegram pairing response is invalid"
            ) from exc
        if canonical_json(pairing.model_dump(mode="json")) != body:
            raise NotificationError(
                "notification relay Telegram pairing response is not canonical"
            )
        return pairing

    def configure_telegram_webhook(
        self,
        decision_key: bytes,
    ) -> TelegramWebhookConfiguration:
        """Install Telegram's callback-only webhook after private pairing."""

        body = self._telegram_setup(
            decision_key,
            control="configure-webhook",
            proof_label="telegram-webhook.v1",
        )
        try:
            configured = TelegramWebhookConfiguration.model_validate_json(
                body,
                strict=True,
            )
        except Exception as exc:
            raise NotificationError(
                "notification relay Telegram webhook response is invalid"
            ) from exc
        if canonical_json(configured.model_dump(mode="json")) != body:
            raise NotificationError(
                "notification relay Telegram webhook response is not canonical"
            )
        return configured

    def decisions(self, after_cursor: RelayCursor) -> RelayDecisionPage:
        if re.fullmatch(r"(?:0|[1-9][0-9]{0,17})", after_cursor) is None:
            raise NotificationError("notification relay cursor is invalid")
        status, body = self._transport.get(
            _decision_url(self.endpoint, after_cursor),
            authorization=f"Bearer {self._bearer_token}",
            timeout_seconds=self._timeout_seconds,
        )
        if status != 200:
            raise NotificationError(f"notification relay HTTP {status}")
        try:
            page = RelayDecisionPage.model_validate_json(body, strict=True)
        except Exception as exc:
            raise NotificationError("notification relay decision page is invalid") from exc
        current = int(after_cursor)
        following = int(page.next_cursor)
        if following < current:
            raise NotificationError("notification relay cursor regressed")
        if page.data and following <= current:
            raise NotificationError("notification relay returned decisions without advancing")
        if page.data and following != current + len(page.data):
            raise NotificationError("notification relay cursor skipped decision sequence")
        if not page.data and following != current:
            raise NotificationError("notification relay advanced past an empty page")
        return page


class HostTelegramRelayClient:
    """Register an event at the relay, then send its fixed text from Michigan."""

    def __init__(
        self,
        relay: NotificationRelayClient,
        bot_token: str,
        chat_id: str,
        *,
        transport: TelegramTransport | None = None,
        timeout_seconds: float = 20.0,
    ) -> None:
        if re.fullmatch(r"[0-9]{6,20}:[A-Za-z0-9_-]{30,}", bot_token) is None:
            raise NotificationError("Telegram bot credential is invalid")
        if re.fullmatch(r"[1-9][0-9]{0,18}", chat_id) is None:
            raise NotificationError("Telegram recipient binding is invalid")
        if timeout_seconds <= 0 or timeout_seconds > 60:
            raise NotificationError("Telegram timeout must be in (0, 60] seconds")
        self._relay = relay
        self._bot_token = bot_token
        self._chat_id = chat_id
        self._transport = transport or StdlibTelegramTransport()
        self._timeout_seconds = timeout_seconds

    def __repr__(self) -> str:
        return f"{type(self).__name__}(relay={self._relay!r})"

    @property
    def endpoint_binding(self) -> str:
        return self._relay.endpoint_binding

    def decisions(self, after_cursor: RelayCursor) -> RelayDecisionPage:
        return self._relay.decisions(after_cursor)

    def submit(self, event: RedactedEvent) -> RelayAcknowledgement:
        registration = self._relay.submit(event)
        if registration.status == "rejected":
            return registration

        payload: dict[str, object] = {
            "chat_id": self._chat_id,
            "disable_web_page_preview": True,
            "text": render_fixed_message(event),
        }
        if isinstance(event, ProposalQuarantinedEvent):
            code = event.approval.human_code
            payload["reply_markup"] = {
                "inline_keyboard": [
                    [
                        {
                            "text": "Approve (offline validation only)",
                            "callback_data": f"iou-ai:approve:{code}",
                        }
                    ],
                    [{"text": "Deny", "callback_data": f"iou-ai:deny:{code}"}],
                ]
            }
        elif isinstance(event, ExecutionReadyEvent):
            code = event.approval.human_code
            payload["reply_markup"] = {
                "inline_keyboard": [
                    [
                        {
                            "text": "Execute exact canaried artifact",
                            "callback_data": f"iou-ai:execute:{code}",
                        }
                    ],
                    [{"text": "Deny", "callback_data": f"iou-ai:deny:{code}"}],
                ]
            }

        status, body = self._transport.post(
            f"https://api.telegram.org/bot{self._bot_token}/sendMessage",
            payload=canonical_json(payload),
            timeout_seconds=self._timeout_seconds,
        )
        if status != 200:
            raise NotificationError("Telegram notification was not accepted")
        try:
            decoded = json.loads(body)
            message_id = decoded["result"]["message_id"]
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise NotificationError("Telegram notification response is invalid") from exc
        if decoded.get("ok") is not True or not isinstance(message_id, int) or message_id <= 0:
            raise NotificationError("Telegram notification response is invalid")
        return RelayAcknowledgement(
            event_digest=registration.event_digest,
            receipt_id=f"telegram:{message_id}",
            status=registration.status,
        )


class DeliveryReceiptStore:
    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)

    def _path(self, event_digest: str) -> Path:
        if re.fullmatch(r"sha256:[0-9a-f]{64}", event_digest) is None:
            raise NotificationError("invalid receipt event digest")
        return self.root / f"{event_digest.removeprefix('sha256:')}.json"

    def get(self, event_digest: str) -> DeliveryReceipt | None:
        destination = self._path(event_digest)
        if destination.is_symlink():
            raise NotificationError("delivery receipt is not a regular file")
        if not destination.exists():
            return None
        if not destination.is_file():
            raise NotificationError("delivery receipt is not a regular file")
        try:
            payload = _read_limited(destination, 64 * 1024, "delivery receipt")
            receipt = DeliveryReceipt.model_validate_json(payload, strict=True)
        except NotificationError:
            raise
        except Exception as exc:
            raise NotificationError("delivery receipt is invalid") from exc
        if canonical_json(receipt.model_dump(mode="json")) != payload:
            raise NotificationError("delivery receipt is not canonical")
        if receipt.event_digest != event_digest:
            raise NotificationError("delivery receipt event binding changed")
        return receipt

    def has(self, event_digest: str) -> bool:
        return self.get(event_digest) is not None

    def put(self, acknowledgement: RelayAcknowledgement) -> Path:
        now = datetime.now(timezone.utc).isoformat(timespec="seconds").replace(
            "+00:00", "Z"
        )
        receipt = DeliveryReceipt(
            event_digest=acknowledgement.event_digest,
            receipt_id=acknowledgement.receipt_id,
            relay_status=acknowledgement.status,
            recorded_at=now,
        )
        return self._put_receipt(receipt)

    def put_expired(
        self,
        event_digest: str,
        *,
        recorded_at: datetime | None = None,
    ) -> Path:
        """Record a proposal whose approval window has closed locally.

        No relay request is made for this terminal disposition.  The stable
        local receipt identifier makes repeated timer runs idempotent while
        preserving a clear audit trail that the event was never delivered.
        """

        current = _utc_datetime(recorded_at)
        receipt = DeliveryReceipt(
            event_digest=event_digest,
            receipt_id="local:proposal-expired",
            relay_status="expired",
            recorded_at=_timestamp(current),
        )
        return self._put_receipt(receipt)

    def _put_receipt(self, receipt: DeliveryReceipt) -> Path:
        payload = canonical_json(receipt.model_dump(mode="json"))
        destination = self._path(receipt.event_digest)
        self.root.mkdir(parents=True, exist_ok=True)
        try:
            descriptor = os.open(
                destination,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o440,
            )
        except FileExistsError:
            try:
                if destination.is_symlink() or not destination.is_file():
                    raise NotificationError("delivery receipt is not a regular file")
                existing_payload = _read_limited(
                    destination, 64 * 1024, "delivery receipt"
                )
                existing = DeliveryReceipt.model_validate_json(existing_payload, strict=True)
            except Exception as exc:
                raise NotificationError("delivery receipt is invalid") from exc
            if canonical_json(existing.model_dump(mode="json")) != existing_payload:
                raise NotificationError("delivery receipt is not canonical")
            if existing.event_digest != receipt.event_digest:
                raise NotificationError("delivery receipt event binding changed")
            if existing.receipt_id != receipt.receipt_id:
                raise NotificationError("delivery receipt relay binding changed")
            if (
                "expired" in {existing.relay_status, receipt.relay_status}
                and existing.relay_status != receipt.relay_status
            ):
                raise NotificationError("delivery receipt terminal status changed")
            return destination
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
        except BaseException:
            destination.unlink(missing_ok=True)
            raise
        return destination


def _read_limited(path: Path, limit: int, label: str) -> bytes:
    try:
        with path.open("rb") as handle:
            payload = handle.read(limit + 1)
    except OSError as exc:
        raise NotificationError(f"{label} is unavailable") from exc
    if len(payload) > limit:
        raise NotificationError(f"{label} exceeded the size limit")
    return payload


def _utc_datetime(value: datetime | None) -> datetime:
    current = value or datetime.now(timezone.utc)
    if current.tzinfo is None or current.utcoffset() is None:
        raise NotificationError("notification time must be timezone-aware")
    return current.astimezone(timezone.utc)


def _timestamp(value: datetime) -> str:
    return value.isoformat(timespec="seconds").replace("+00:00", "Z")


def _timestamp_as_utc(value: str, *, label: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise NotificationError(f"{label} is invalid") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise NotificationError(f"{label} is not timezone-aware")
    return parsed.astimezone(timezone.utc)


def _event_digest(event: RedactedEvent) -> str:
    return "sha256:" + hashlib.sha256(
        canonical_json(event.model_dump(mode="json"))
    ).hexdigest()


def _approval_expired(
    event: ProposalQuarantinedEvent | ExecutionReadyEvent,
    *,
    now: datetime,
) -> bool:
    return _timestamp_as_utc(event.approval.expires_at, label="approval expiration") <= now


def _delivery_sort_key(
    event: RedactedEvent,
    *,
    now: datetime,
) -> tuple[int, str, str]:
    """Return a deterministic, safety-oriented relay attempt order.

    Time-sensitive human approvals are ordered by their deadline, and the
    locally evidenced urgent/high-value triage class precedes everything that
    is merely observational.  Counter and hang deltas remain last because they
    are noisy, untriaged telemetry rather than a decision or safety signal.
    """

    digest = _event_digest(event)
    if isinstance(event, CrashTriageEvent):
        if event.severity == "urgent" or event.potential_high_value:
            return (0, event.created_at, digest)
        return (3, event.created_at, digest)
    if isinstance(event, (ProposalQuarantinedEvent, ExecutionReadyEvent)):
        if _approval_expired(event, now=now):
            # The event is terminally recorded without a network request, but
            # it is still processed in this run after actionable alerts.
            return (7, event.approval.expires_at, digest)
        return (1, event.approval.expires_at, digest)
    if isinstance(event, BudgetThresholdEvent):
        return (2 if event.severity == "critical" else 4, event.created_at, digest)
    if isinstance(event, CrashCounterIncreaseEvent):
        return (5, event.created_at, digest)
    if isinstance(event, HangCounterIncreaseEvent):
        return (6, event.created_at, digest)
    raise NotificationError("unsupported redacted event for delivery")


class DecisionInbox:
    """Create-only content-addressed storage for untrusted signed bundles."""

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)

    def put(self, signed: SignedDecision) -> tuple[str, Path, bool]:
        # Structural validation happens here; signature/authority verification stays
        # in the separate no-network importer.
        payload = canonical_json(signed.model_dump(mode="json"))
        try:
            SignedDecision.model_validate_json(payload, strict=True)
        except Exception as exc:
            raise NotificationError("relay decision bundle is invalid") from exc
        digest = hashlib.sha256(payload).hexdigest()
        destination = self.root / f"{digest}.json"
        self.root.mkdir(parents=True, exist_ok=True)
        try:
            descriptor = os.open(
                destination,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o440,
            )
        except FileExistsError:
            if destination.is_symlink() or not destination.is_file():
                raise NotificationError("decision inbox item is not a regular file")
            if _read_limited(destination, 64 * 1024, "decision inbox item") != payload:
                raise NotificationError("decision inbox digest collision")
            return digest, destination, False
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
        except BaseException:
            destination.unlink(missing_ok=True)
            raise
        return digest, destination, True


class RelayCursorStore:
    """Append-only, content-addressed relay cursor checkpoints."""

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)

    def _checkpoints(self, endpoint_binding: str) -> tuple[RelayCursorCheckpoint, ...]:
        if not self.root.exists():
            return ()
        result: list[RelayCursorCheckpoint] = []
        for path in sorted(self.root.iterdir(), key=lambda item: item.name):
            match = re.fullmatch(r"([0-9a-f]{64})\.json", path.name)
            if match is None:
                continue
            if path.is_symlink() or not path.is_file():
                raise NotificationError("relay cursor checkpoint is not a regular file")
            payload = _read_limited(path, 16 * 1024, "relay cursor checkpoint")
            if hashlib.sha256(payload).hexdigest() != match.group(1):
                raise NotificationError("relay cursor checkpoint digest mismatch")
            try:
                checkpoint = RelayCursorCheckpoint.model_validate_json(
                    payload, strict=True
                )
            except Exception as exc:
                raise NotificationError("relay cursor checkpoint is invalid") from exc
            if canonical_json(checkpoint.model_dump(mode="json")) != payload:
                raise NotificationError("relay cursor checkpoint is not canonical")
            if checkpoint.endpoint_binding != endpoint_binding:
                raise NotificationError("relay cursor endpoint binding changed")
            result.append(checkpoint)
        return tuple(result)

    def current(self, endpoint_binding: str) -> RelayCursor:
        checkpoints = self._checkpoints(endpoint_binding)
        if not checkpoints:
            return "0"
        return max(checkpoints, key=lambda item: int(item.next_cursor)).next_cursor

    def advance(self, endpoint_binding: str, next_cursor: RelayCursor) -> Path | None:
        current = self.current(endpoint_binding)
        if int(next_cursor) < int(current):
            raise NotificationError("relay cursor checkpoint regressed")
        if next_cursor == current:
            return None
        checkpoint = RelayCursorCheckpoint(
            endpoint_binding=endpoint_binding,
            next_cursor=next_cursor,
        )
        payload = canonical_json(checkpoint.model_dump(mode="json"))
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
            if destination.is_symlink() or not destination.is_file():
                raise NotificationError("relay cursor checkpoint is not a regular file")
            if _read_limited(destination, 16 * 1024, "relay cursor checkpoint") != payload:
                raise NotificationError("relay cursor checkpoint digest collision")
            return destination
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
        except BaseException:
            destination.unlink(missing_ok=True)
            raise
        return destination


def deliver_pending(
    outbox: EventOutbox,
    receipts: DeliveryReceiptStore,
    client: NotificationRelayClient | HostTelegramRelayClient,
    *,
    now: datetime | None = None,
    stats: DeliveryAttemptStats | None = None,
) -> int:
    current = _utc_datetime(now)
    attempt = stats if stats is not None else DeliveryAttemptStats()
    delivered = 0
    failed = 0
    for event in sorted(
        outbox.events(),
        key=lambda item: _delivery_sort_key(item, now=current),
    ):
        attempt.events_seen += 1
        # Reparse the wire form at the least-privilege network boundary.
        event = parse_event(canonical_json(event.model_dump(mode="json")))
        digest = _event_digest(event)
        receipt = receipts.get(digest)
        if receipt is not None:
            if receipt.relay_status == "expired":
                attempt.events_already_expired += 1
            elif receipt.relay_status == "rejected":
                attempt.events_already_rejected += 1
            else:
                attempt.events_already_delivered += 1
            continue
        if isinstance(
            event, (ProposalQuarantinedEvent, ExecutionReadyEvent)
        ) and _approval_expired(
            event, now=current
        ):
            receipts.put_expired(digest, recorded_at=current)
            attempt.events_newly_expired += 1
            continue
        try:
            acknowledgement = client.submit(event)
        except NotificationError:
            failed += 1
            attempt.events_failed += 1
            continue
        receipts.put(acknowledgement)
        delivered += 1
        attempt.events_delivered += 1
    if failed:
        raise NotificationBatchError(delivered=delivered, failed=failed)
    return delivered


def poll_decisions(
    client: NotificationRelayClient,
    inbox: DecisionInbox,
    cursors: RelayCursorStore,
) -> tuple[int, int, RelayCursor]:
    """Persist one bounded decision page, then and only then advance its cursor."""

    current = cursors.current(client.endpoint_binding)
    page = client.decisions(current)
    stored = 0
    for signed in page.data:
        _, _, created = inbox.put(signed)
        stored += int(created)
    cursors.advance(client.endpoint_binding, page.next_cursor)
    return len(page.data), stored, page.next_cursor


__all__ = [
    "DeliveryReceipt",
    "DeliveryReceiptStore",
    "DecisionInbox",
    "NotificationError",
    "NotificationBatchError",
    "NotificationRelayClient",
    "HostTelegramRelayClient",
    "RelayAcknowledgement",
    "RelayReadiness",
    "TelegramPairing",
    "TelegramWebhookConfiguration",
    "RelayCursorCheckpoint",
    "RelayCursorStore",
    "RelayDecisionPage",
    "RelaySubmission",
    "StdlibRelayTransport",
    "StdlibTelegramTransport",
    "TelegramTransport",
    "deliver_pending",
    "poll_decisions",
]
