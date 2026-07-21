"""Least-privilege notification relay runner.

This process can read only redacted events and a relay bearer credential.  It
delivers fixed notification envelopes and downloads structurally valid signed
decision bundles into a content-addressed inbox.  Signature verification and
all decision authority remain in the separate no-network importer.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from .events import EventOutbox, EventProjectionError
from .notifier import (
    DecisionInbox,
    DeliveryAttemptStats,
    DeliveryReceiptStore,
    HostTelegramRelayClient,
    NotificationBatchError,
    NotificationError,
    NotificationRelayClient,
    RelayCursorStore,
    RelayTransport,
    TelegramTransport,
    deliver_pending,
    poll_decisions,
)


def _read_single_line(path: Path, *, limit: int, label: str) -> str:
    try:
        with path.open("rb") as handle:
            payload = handle.read(limit + 1)
    except OSError as exc:
        raise NotificationError(f"{label} file is unavailable") from exc
    if len(payload) > limit:
        raise NotificationError(f"{label} file exceeded the size limit")
    try:
        value = payload.decode("ascii")
    except UnicodeDecodeError as exc:
        raise NotificationError(f"{label} file is not ASCII") from exc
    if value.endswith("\r\n"):
        value = value[:-2]
    elif value.endswith("\n"):
        value = value[:-1]
    if not value or "\r" in value or "\n" in value:
        raise NotificationError(f"{label} file must contain exactly one line")
    return value


def run_once(
    *,
    events: Path,
    receipts: Path,
    decision_inbox: Path,
    state_dir: Path,
    endpoint_file: Path,
    token_file: Path,
    telegram_bot_token_file: Path | None = None,
    telegram_chat_id_file: Path | None = None,
    transport: RelayTransport | None = None,
    telegram_transport: TelegramTransport | None = None,
) -> dict[str, int | str]:
    endpoint = _read_single_line(
        endpoint_file,
        limit=2048,
        label="notification endpoint",
    )
    token = _read_single_line(
        token_file,
        limit=4096,
        label="notification credential",
    )
    relay_client = NotificationRelayClient(endpoint, token, transport=transport)
    if (telegram_bot_token_file is None) != (telegram_chat_id_file is None):
        raise NotificationError("Telegram host delivery requires both credential files")
    delivery_client: NotificationRelayClient | HostTelegramRelayClient = relay_client
    if telegram_bot_token_file is not None and telegram_chat_id_file is not None:
        delivery_client = HostTelegramRelayClient(
            relay_client,
            _read_single_line(
                telegram_bot_token_file,
                limit=256,
                label="Telegram bot credential",
            ),
            _read_single_line(
                telegram_chat_id_file,
                limit=32,
                label="Telegram recipient binding",
            ),
            transport=telegram_transport,
        )
    delivery_failure: NotificationBatchError | None = None
    delivery_stats = DeliveryAttemptStats()
    try:
        delivered = deliver_pending(
            EventOutbox(events),
            DeliveryReceiptStore(receipts),
            delivery_client,
            stats=delivery_stats,
        )
    except NotificationBatchError as exc:
        delivered = exc.delivered
        delivery_failure = exc

    decision_failure: NotificationError | None = None
    try:
        received, stored, cursor = poll_decisions(
            relay_client,
            DecisionInbox(decision_inbox),
            RelayCursorStore(state_dir / "decision-cursors"),
        )
    except NotificationError as exc:
        received, stored, cursor = 0, 0, "0"
        decision_failure = exc

    if delivery_failure is not None or decision_failure is not None:
        delivery_count = delivery_failure.failed if delivery_failure else 0
        poll_failed = int(decision_failure is not None)
        raise NotificationError(
            "relay exchange incomplete: "
            f"delivery_failures={delivery_count}; decision_poll_failed={poll_failed}"
        )
    return {
        "status": "relay_complete",
        "events_delivered": delivered,
        "events_seen": delivery_stats.events_seen,
        "events_already_delivered": delivery_stats.events_already_delivered,
        "events_already_rejected": delivery_stats.events_already_rejected,
        "events_already_expired": delivery_stats.events_already_expired,
        "events_newly_expired": delivery_stats.events_newly_expired,
        "events_failed": delivery_stats.events_failed,
        "decisions_received": received,
        "decisions_stored": stored,
        "decision_cursor": cursor,
    }


def probe_readiness(
    *,
    endpoint_file: Path,
    token_file: Path,
    decision_key_file: Path,
    transport: RelayTransport | None = None,
) -> dict[str, str]:
    """Perform the authenticated no-write relay readiness check.

    This is intentionally separate from :func:`run_once`: it has no access to
    the event outbox, delivery receipts, decision inbox, or cursor state.  The
    activation script uses it before enabling any notification timer.
    """

    endpoint = _read_single_line(
        endpoint_file,
        limit=2048,
        label="notification endpoint",
    )
    token = _read_single_line(
        token_file,
        limit=4096,
        label="notification credential",
    )
    decision_key = _read_single_line(
        decision_key_file,
        limit=4096,
        label="relay decision credential",
    ).encode("ascii")
    NotificationRelayClient(endpoint, token, transport=transport).readiness(decision_key)
    return {"status": "relay_ready"}


def pair_telegram(
    *,
    endpoint_file: Path,
    token_file: Path,
    decision_key_file: Path,
    transport: RelayTransport | None = None,
) -> dict[str, str]:
    """Bind exactly one user-initiated private Telegram chat, without printing it."""

    endpoint = _read_single_line(endpoint_file, limit=2048, label="notification endpoint")
    token = _read_single_line(token_file, limit=4096, label="notification credential")
    decision_key = _read_single_line(
        decision_key_file,
        limit=4096,
        label="relay decision credential",
    ).encode("ascii")
    NotificationRelayClient(endpoint, token, transport=transport).pair_telegram(decision_key)
    return {"status": "telegram_paired"}


def configure_telegram_webhook(
    *,
    endpoint_file: Path,
    token_file: Path,
    decision_key_file: Path,
    transport: RelayTransport | None = None,
) -> dict[str, str]:
    """Install Telegram's callback-only webhook, emitting no recipient data."""

    endpoint = _read_single_line(endpoint_file, limit=2048, label="notification endpoint")
    token = _read_single_line(token_file, limit=4096, label="notification credential")
    decision_key = _read_single_line(
        decision_key_file,
        limit=4096,
        label="relay decision credential",
    ).encode("ascii")
    NotificationRelayClient(
        endpoint,
        token,
        transport=transport,
    ).configure_telegram_webhook(decision_key)
    return {"status": "telegram_webhook_configured"}


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="iou-ai-notify",
        description="Deliver redacted events and fetch inert signed decision bundles",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser("run", help="perform one bounded relay exchange")
    run.add_argument("--events", type=Path, required=True)
    run.add_argument("--receipts", type=Path, required=True)
    run.add_argument("--decision-inbox", type=Path, required=True)
    run.add_argument("--state-dir", type=Path, required=True)
    run.add_argument("--endpoint-file", type=Path, required=True)
    run.add_argument("--token-file", type=Path, required=True)
    run.add_argument("--telegram-bot-token-file", type=Path)
    run.add_argument("--telegram-chat-id-file", type=Path)
    probe = commands.add_parser(
        "probe",
        help="perform one authenticated read-only relay readiness check",
    )
    probe.add_argument("--endpoint-file", type=Path, required=True)
    probe.add_argument("--token-file", type=Path, required=True)
    probe.add_argument("--decision-key-file", type=Path, required=True)
    for command, help_text in (
        ("telegram-pair", "bind one private Telegram /start chat"),
        ("telegram-webhook", "install Telegram's callback-only webhook"),
    ):
        setup = commands.add_parser(command, help=help_text)
        setup.add_argument("--endpoint-file", type=Path, required=True)
        setup.add_argument("--token-file", type=Path, required=True)
        setup.add_argument("--decision-key-file", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "run":
            result = run_once(
                events=args.events,
                receipts=args.receipts,
                decision_inbox=args.decision_inbox,
                state_dir=args.state_dir,
                endpoint_file=args.endpoint_file,
                token_file=args.token_file,
                telegram_bot_token_file=args.telegram_bot_token_file,
                telegram_chat_id_file=args.telegram_chat_id_file,
            )
        elif args.command == "probe":
            result = probe_readiness(
                endpoint_file=args.endpoint_file,
                token_file=args.token_file,
                decision_key_file=args.decision_key_file,
            )
        elif args.command == "telegram-pair":
            result = pair_telegram(
                endpoint_file=args.endpoint_file,
                token_file=args.token_file,
                decision_key_file=args.decision_key_file,
            )
        elif args.command == "telegram-webhook":
            result = configure_telegram_webhook(
                endpoint_file=args.endpoint_file,
                token_file=args.token_file,
                decision_key_file=args.decision_key_file,
            )
        else:  # argparse enforces this; retain a fail-closed guard.
            return 2
    except (NotificationError, EventProjectionError, OSError) as exc:
        print(f"blocked: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
