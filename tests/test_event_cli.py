from __future__ import annotations

from pathlib import Path

from iou_ai.config import load_config
from iou_ai.event_cli import project
from iou_ai.events import EventOutbox, ProposalQuarantinedEvent
from iou_ai.pipeline import ShadowPipeline, build_ledger, load_inputs
from iou_ai.providers import MockAdapter


ROOT = Path(__file__).resolve().parents[1]


def _config(tmp_path: Path) -> Path:
    for name in (
        "telemetry.sample.json",
        "harness-contract.mock.json",
        "proposal.mock.json",
        "reviewer.mock.json",
    ):
        (tmp_path / name).write_bytes((ROOT / "examples" / name).read_bytes())
    source = (ROOT / "examples" / "config.mock.toml").read_text(encoding="utf-8")
    replacements = {
        'database = "../state/budget.sqlite3"': 'database = "budget.sqlite3"',
        'kill_switch = "../state/AI_CALLS_DISABLED"': 'kill_switch = "AI_CALLS_DISABLED"',
        'state_dir = "../state"': 'state_dir = "."',
        'quarantine_dir = "../state/quarantine"': 'quarantine_dir = "quarantine"',
    }
    for old, new in replacements.items():
        source = source.replace(old, new)
    source += """

[events]
enabled = true
outbox_dir = "events"
projector_state_file = "event-state.json"
decision_archive_dir = "decisions"
decision_ttl_minutes = 30
"""
    path = tmp_path / "config.toml"
    path.write_text(source, encoding="utf-8")
    return path


def test_projector_cli_core_is_idempotent_and_never_calls_a_provider(
    tmp_path: Path,
) -> None:
    config_path = _config(tmp_path)
    config = load_config(config_path)
    telemetry, contract = load_inputs(
        config.runtime.telemetry_file,
        config.runtime.harness_contract_file,
    )
    ShadowPipeline(
        config,
        ledger=build_ledger(config),
        planner=MockAdapter((tmp_path / "proposal.mock.json").read_text(encoding="utf-8")),
        reviewer=MockAdapter((tmp_path / "reviewer.mock.json").read_text(encoding="utf-8")),
    ).run(telemetry, contract)

    first = project(config_path)
    second = project(config_path)

    assert first == {
        "status": "projected",
        "proposals": 1,
        "executions": 0,
        "budgets": 0,
        "counters": 0,
    }
    assert second == {
        "status": "projected",
        "proposals": 0,
        "executions": 0,
        "budgets": 0,
        "counters": 0,
    }
    events = EventOutbox(tmp_path / "events").events()
    assert len(events) == 1
    assert isinstance(events[0], ProposalQuarantinedEvent)
    assert (tmp_path / "event-state.json").is_file()
