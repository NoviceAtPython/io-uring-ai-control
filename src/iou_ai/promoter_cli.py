"""Root CLI: publish an approved execution candidate into a static AFL foreign-sync inbox.

Runs as root because it writes exactly one immutable seed into the fleet's
foreign-sync directory. Before that single atomic publication it independently
re-verifies the relay-signed human decision, the full immutable authority chain
(envelope, artifact, validation, canary, candidate), and that the live target
authority has not drifted. It has no network client, no model adapter, no shell
capability, and can only ever write inside the allowlisted sync root.

Exit codes: 0 = at least one candidate was published (or already had a receipt);
4 = nothing was promotable yet (no valid approved decision) -- safe to retry in a
poll loop; 2 = a configuration or setup error.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys

from .artifacts import ArtifactStore
from .config import ConfigError, load_config
from .decisions import DecisionArchive, DecisionError, ExecutionDecision
from .events import EventOutbox
from .execution import ExecutionAuthorityStore, WorkerSet
from .promoter import (
    DestinationSpec,
    Promoter,
    PromotionError,
    load_current_target_contract,
)
from .quarantine import QuarantineStore


def _runner_hash(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _build_promoter(
    config,
    *,
    key_file: Path,
    runner: Path,
    campaign: str,
    allowed_root: Path,
    native_inbox: Path,
    kasan_inbox: Path,
    receipts: Path,
    contract_file: Path,
) -> Promoter:
    key = key_file.read_bytes().strip()
    events = EventOutbox(config.events.outbox_dir)
    decisions = DecisionArchive(
        config.events.decision_archive_dir,
        events=events,
        verification_key=key,
    )
    runner_hashes = frozenset({_runner_hash(runner)})
    destinations = {
        "native_ai_sync": DestinationSpec(
            destination_id="native_ai_sync",
            campaign_id=campaign,
            worker_set=WorkerSet.NATIVE_STABLE,
            inbox=native_inbox,
            allowed_root=allowed_root,
            allowed_runner_hashes=runner_hashes,
        ),
        "kasan_ai_sync": DestinationSpec(
            destination_id="kasan_ai_sync",
            campaign_id=campaign,
            worker_set=WorkerSet.KASAN_TRIAGE,
            inbox=kasan_inbox,
            allowed_root=allowed_root,
            allowed_runner_hashes=runner_hashes,
        ),
    }
    authority_root = config.events.execution_candidate_dir.parent
    return Promoter(
        events=events,
        decisions=decisions,
        quarantine=QuarantineStore(config.runtime.quarantine_dir),
        artifacts=ArtifactStore(config.runtime.artifact_dir),
        authority=ExecutionAuthorityStore(authority_root),
        receipts=receipts,
        destinations=destinations,
        current_target_probe=lambda: load_current_target_contract(contract_file),
    )


def _approved_candidate_digests(decisions: DecisionArchive) -> list[str]:
    """Candidate digests with a verified live-execution approval (dedup, ordered)."""

    digests: list[str] = []
    for signed in decisions.verified_decisions():
        decision = signed.decision
        if (
            isinstance(decision, ExecutionDecision)
            and decision.action == "approve_for_live_execution"
        ):
            digests.append(decision.candidate_digest)
    return list(dict.fromkeys(digests))


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="iou-ai-promoter",
        description="Publish an approved execution candidate into a static AFL foreign-sync inbox (root)",
    )
    parser.add_argument("--config", type=Path, default=Path("/etc/iou-ai/config.toml"))
    parser.add_argument(
        "--key-file",
        type=Path,
        default=Path("/etc/iou-ai/credentials/decision.key"),
        help="relay HMAC verification key (same key the decision importer uses)",
    )
    parser.add_argument(
        "--runner", type=Path, required=True, help="path to nyx_canary_oneshot.sh"
    )
    parser.add_argument(
        "--campaign", default="io-uring-coverage-2026-07", help="promotion campaign id"
    )
    parser.add_argument(
        "--allowed-root",
        type=Path,
        default=Path("/var/lib/iou-ai-execution/sync"),
        help="static allowlist root that must contain every inbox",
    )
    parser.add_argument(
        "--native-inbox",
        type=Path,
        default=Path("/var/lib/iou-ai-execution/sync/native_ai_sync"),
    )
    parser.add_argument(
        "--kasan-inbox",
        type=Path,
        default=Path("/var/lib/iou-ai-execution/sync/kasan_ai_sync"),
    )
    parser.add_argument(
        "--receipts",
        type=Path,
        default=Path("/var/lib/iou-ai-execution/promotion-receipts"),
    )
    parser.add_argument(
        "--contract",
        type=Path,
        default=None,
        help="current target contract for the final drift probe (default: runtime contract)",
    )
    parser.add_argument(
        "--candidate",
        action="append",
        default=[],
        metavar="SHA256",
        help="specific candidate digest to promote (sha256:...; repeatable)",
    )
    parser.add_argument(
        "--scan",
        action="store_true",
        help="promote every candidate that carries a verified live-execution approval",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        config = load_config(args.config)
    except (ConfigError, OSError) as exc:
        print(f"blocked: {exc}", file=sys.stderr)
        return 2
    if not args.runner.is_file():
        print(f"blocked: canary runner not found: {args.runner}", file=sys.stderr)
        return 2
    if not args.key_file.is_file():
        print(f"blocked: decision key not found: {args.key_file}", file=sys.stderr)
        return 2

    contract_file = args.contract or config.runtime.harness_contract_file
    try:
        promoter = _build_promoter(
            config,
            key_file=args.key_file,
            runner=args.runner,
            campaign=args.campaign,
            allowed_root=args.allowed_root,
            native_inbox=args.native_inbox,
            kasan_inbox=args.kasan_inbox,
            receipts=args.receipts,
            contract_file=contract_file,
        )
    except (PromotionError, ConfigError, OSError, ValueError) as exc:
        print(f"blocked: {exc}", file=sys.stderr)
        return 2

    targets: list[str] = list(args.candidate)
    if args.scan:
        targets.extend(_approved_candidate_digests(promoter.decisions))
    targets = list(dict.fromkeys(targets))

    results: list[dict[str, object]] = []
    promoted = 0
    for candidate_digest in targets:
        try:
            receipt = promoter.promote(candidate_digest)
            promoted += 1
            results.append(
                {
                    "candidate": candidate_digest,
                    "outcome": "promoted",
                    "destination_id": receipt.destination_id,
                    "destination_entry_id": receipt.destination_entry_id,
                    "artifact_digest": receipt.artifact_digest,
                    "promoted_at": receipt.promoted_at,
                }
            )
        except (PromotionError, DecisionError) as exc:
            # One unpromotable candidate must never abort the whole pass. A stale
            # archived decision whose proposal event has been rotated away raises
            # DecisionError from find_event; unattended timer runs would otherwise
            # wedge here and silently stop publishing.
            results.append(
                {
                    "candidate": candidate_digest,
                    "outcome": "not_promoted",
                    "detail": str(exc),
                }
            )

    print(
        json.dumps(
            {
                "status": "promoted" if promoted else "nothing_promoted",
                "promoted": promoted,
                "results": results,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0 if promoted else 4


if __name__ == "__main__":
    raise SystemExit(main())
