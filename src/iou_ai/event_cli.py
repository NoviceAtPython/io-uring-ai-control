"""No-network projector from verified local state to a redacted event outbox."""

from __future__ import annotations

import argparse
from datetime import timedelta
import json
import os
from pathlib import Path
import sys

from pydantic import ValidationError

from .config import ConfigError, load_config
from .events import (
    CounterSnapshot,
    EventOutbox,
    EventProjectionError,
    project_budget_status,
    project_counter_snapshot,
    project_execution_ready,
    project_quarantine,
)
from .models import TelemetryPacket
from .pipeline import build_ledger
from .quarantine import canonical_json


def _load_snapshot(path: Path) -> CounterSnapshot | None:
    if not path.exists():
        return None
    payload = path.read_bytes()
    try:
        snapshot = CounterSnapshot.model_validate_json(payload, strict=True)
    except ValidationError as exc:
        raise EventProjectionError("counter baseline is invalid") from exc
    if canonical_json(snapshot.model_dump(mode="json")) != payload:
        raise EventProjectionError("counter baseline is not canonical")
    return snapshot


def _write_atomic(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
    except FileExistsError as exc:
        raise EventProjectionError("stale projector state temporary exists") from exc
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def _counter(packet: TelemetryPacket, name: str) -> int:
    values = [item.count for item in packet.outcome_classes if item.outcome_class == name]
    if len(values) > 1:
        raise EventProjectionError(f"telemetry contains duplicate {name} counters")
    # Older/test packets may omit a zero-valued class.  Absence establishes a
    # zero baseline; an actual increase still requires an explicit later class.
    return values[0] if values else 0


def project(config_path: Path) -> dict[str, int | str]:
    config = load_config(config_path)
    if not config.events.enabled:
        return {
            "status": "disabled",
            "proposals": 0,
            "executions": 0,
            "budgets": 0,
            "counters": 0,
        }

    try:
        packet_payload = config.runtime.telemetry_file.read_bytes()
        packet = TelemetryPacket.model_validate_json(packet_payload, strict=True)
    except (OSError, ValidationError) as exc:
        raise EventProjectionError("sanitized telemetry is unavailable or invalid") from exc

    outbox = EventOutbox(config.events.outbox_dir)
    proposals = project_quarantine(
        config.runtime.quarantine_dir,
        outbox,
        decision_ttl=timedelta(minutes=config.events.decision_ttl_minutes),
    )
    executions = project_execution_ready(
        config.events.execution_candidate_dir,
        outbox,
        decision_ttl=timedelta(minutes=config.events.decision_ttl_minutes),
    )
    budgets = project_budget_status(build_ledger(config).status(), outbox)

    current = CounterSnapshot(
        campaign_id=packet.campaign_id,
        telemetry_packet_digest=packet.packet_hash,
        target_hashes=packet.target_hashes,
        crash_count=_counter(packet, "saved_crash"),
        hang_count=_counter(packet, "saved_hang"),
    )
    previous = _load_snapshot(config.events.projector_state_file)
    counters = project_counter_snapshot(previous, current, outbox)
    _write_atomic(
        config.events.projector_state_file,
        canonical_json(current.model_dump(mode="json")),
    )
    return {
        "status": "projected",
        "proposals": len(proposals),
        "executions": len(executions),
        "budgets": len(budgets),
        "counters": len(counters),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="iou-ai-events",
        description="Project verified local state into redacted inert events",
    )
    parser.add_argument(
        "--config", type=Path, default=Path("/etc/iou-ai/config.toml")
    )
    args = parser.parse_args(argv)
    try:
        result = project(args.config)
    except (ConfigError, EventProjectionError, OSError) as exc:
        print(f"blocked: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
