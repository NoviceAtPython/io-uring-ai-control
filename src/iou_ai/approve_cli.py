"""Root operator approval CLI: approve one canaried execution candidate locally.

This is the on-box equivalent of a Telegram approval, for the operator who holds
root on the fuzzing host. It mints the SAME signed ExecutionDecision the relay
would, but with an honest ``operator:local-v1`` signer identity, and archives it
through the normal verifying path so the separate promoter can proceed. It can
approve only an existing, canaried ``execution_ready`` event that is still within
its approval window -- it cannot fabricate a candidate, an approval challenge, or
a target binding. Root, because the archive and the HMAC key are root-held.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import hmac
import json
from pathlib import Path
import sys

from .config import ConfigError, load_config
from .decisions import (
    DecisionArchive,
    DecisionError,
    ExecutionDecision,
    sign_decision,
)
from .events import EventOutbox, EventProjectionError, ExecutionReadyEvent
from .quarantine import canonical_json


def _now_iso() -> str:
    return (
        datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    )


def _event_digest(event: ExecutionReadyEvent) -> str:
    return "sha256:" + hashlib.sha256(
        canonical_json(event.model_dump(mode="json"))
    ).hexdigest()


def _pending_execution_events(outbox: EventOutbox) -> list[ExecutionReadyEvent]:
    return [e for e in outbox.events() if isinstance(e, ExecutionReadyEvent)]


def _operator_decision(
    event: ExecutionReadyEvent, key: bytes, issued_at: str, *, auto: bool = False
) -> ExecutionDecision:
    # Unattended approvals sign as a distinct identity so the archive always shows
    # whether a promotion was authorised by a human at the console or by the auto
    # policy. Same key, different attestation -- never relabel one as the other.
    sender_binding = "sha256:" + hmac.new(
        key,
        b"sender:operator:auto" if auto else b"sender:operator:local",
        hashlib.sha256,
    ).hexdigest()
    return ExecutionDecision(
        signer_id="operator:auto-v1" if auto else "operator:local-v1",
        channel="operator",
        event_digest=_event_digest(event),
        candidate_digest=event.candidate_digest,
        envelope_digest=event.envelope_digest,
        artifact_manifest_digest=event.artifact_manifest_digest,
        artifact_digest=event.artifact_digest,
        artifact_size_bytes=event.artifact_size_bytes,
        validation_report_digest=event.validation_report_digest,
        canary_report_digest=event.canary_report_digest,
        target_hashes=event.target_hashes,
        promotion_scope=event.promotion_scope,
        approval_binding_digest=event.approval.binding_digest,
        decision_nonce=event.approval.nonce,
        human_code=event.approval.human_code,
        sender_binding=sender_binding,
        action="approve_for_live_execution",
        reason_code="operator_approved_live_execution",
        issued_at=issued_at,
        expires_at=event.approval.expires_at,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="iou-ai-approve",
        description="Approve one canaried execution candidate as the local root operator",
    )
    parser.add_argument("--config", type=Path, default=Path("/etc/iou-ai/config.toml"))
    parser.add_argument(
        "--key-file",
        type=Path,
        default=Path("/etc/iou-ai/credentials/decision.key"),
        help="the relay HMAC key (same key the decision importer verifies with)",
    )
    parser.add_argument(
        "--candidate",
        default=None,
        help="candidate digest to approve (sha256:...); omit with --scan",
    )
    parser.add_argument(
        "--code",
        default=None,
        help="approve the pending event carrying this human code instead",
    )
    parser.add_argument(
        "--scan",
        action="store_true",
        help="approve every pending canaried execution_ready event",
    )
    parser.add_argument(
        "--auto",
        action="store_true",
        help=(
            "unattended auto-promote: sign as operator:auto-v1 instead of "
            "operator:local-v1. The archive then records that the auto policy "
            "approved this, not that a human did."
        ),
    )
    args = parser.parse_args(argv)

    try:
        config = load_config(args.config)
        key = args.key_file.read_bytes().strip()
    except (ConfigError, OSError) as exc:
        print(f"blocked: {exc}", file=sys.stderr)
        return 2
    if len(key) < 32:
        print("blocked: decision key is too short", file=sys.stderr)
        return 2

    outbox = EventOutbox(config.events.outbox_dir)
    archive = DecisionArchive(
        config.events.decision_archive_dir, events=outbox, verification_key=key
    )
    try:
        events = _pending_execution_events(outbox)
    except EventProjectionError as exc:
        print(f"blocked: {exc}", file=sys.stderr)
        return 2

    selected: list[ExecutionReadyEvent] = []
    for event in events:
        if args.scan:
            selected.append(event)
        elif args.candidate and event.candidate_digest == args.candidate:
            selected.append(event)
        elif args.code and event.approval.human_code == args.code:
            selected.append(event)
    if not selected:
        print(
            json.dumps({"status": "no_matching_pending_execution_event", "approved": 0})
        )
        return 4

    results: list[dict[str, object]] = []
    approved = 0
    now = _now_iso()
    for event in selected:
        try:
            signed = sign_decision(
                _operator_decision(event, key, now, auto=args.auto), key
            )
            digest, _ = archive.import_signed(signed)
            approved += 1
            results.append(
                {
                    "candidate": event.candidate_digest,
                    "human_code": event.approval.human_code,
                    "outcome": "approved",
                    "signer": "operator:auto-v1" if args.auto else "operator:local-v1",
                    "decision_digest": digest,
                }
            )
        except DecisionError as exc:
            results.append(
                {
                    "candidate": event.candidate_digest,
                    "outcome": "rejected",
                    "detail": str(exc),
                }
            )

    print(
        json.dumps(
            {
                "status": "approved" if approved else "nothing_approved",
                "approved": approved,
                "results": results,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0 if approved else 4


if __name__ == "__main__":
    raise SystemExit(main())
