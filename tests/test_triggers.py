from dataclasses import replace
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from iou_ai.config import load_config
from iou_ai.models import EvidenceKind, HarnessContract, TelemetryPacket
from iou_ai.triggers import (
    TriggerError,
    TriggerStateStore,
    material_digest,
)


NOW = datetime(2026, 7, 17, 12, 0, tzinfo=timezone.utc)


def _fixtures() -> tuple[TelemetryPacket, HarnessContract]:
    telemetry = TelemetryPacket.model_validate_json(
        (ROOT / "examples" / "telemetry.sample.json").read_text(encoding="utf-8")
    )
    contract = HarnessContract.model_validate_json(
        (ROOT / "examples" / "harness-contract.mock.json").read_text(encoding="utf-8")
    )
    return telemetry, contract


def test_volatile_packet_fields_do_not_trigger_a_paid_run() -> None:
    telemetry, contract = _fixtures()
    updated = telemetry.model_copy(
        update={
            "packet_id": "packet:mock-next",
            "generated_at": "2026-07-16T07:00:00Z",
            "window": telemetry.window.model_copy(
                update={
                    "start_at": "2026-07-16T06:00:00Z",
                    "end_at": "2026-07-16T07:00:00Z",
                    "duration_seconds": 3600,
                }
            ),
            "fleet": telemetry.fleet.model_copy(
                update={
                    "executions_total": telemetry.fleet.executions_total + 9_000_000,
                    "executions_per_second_milli": 1,
                }
            ),
        }
    )
    assert material_digest(updated, contract) == material_digest(telemetry, contract)


def test_routine_coverage_growth_does_not_trigger_but_anomalies_do() -> None:
    # Regression: fresh kernel code finds new edges/paths constantly. Keying the
    # trigger on that made the planner fire ~hourly and burn its monthly call
    # quota on evidence with nothing new to target. Routine coverage growth and
    # instability jitter must NOT change the scheduling material; a novel outcome
    # (a potential bug) still must.
    telemetry, contract = _fixtures()
    baseline = material_digest(telemetry, contract)

    grew = telemetry.model_copy(
        update={
            "coverage": telemetry.coverage.model_copy(
                update={
                    "edges_total": telemetry.coverage.edges_total + 5000,
                    "edges_new_in_window": telemetry.coverage.edges_new_in_window + 137,
                    "paths_new_in_window": telemetry.coverage.paths_new_in_window + 40,
                }
            ),
            "lane_summaries": [
                telemetry.lane_summaries[0].model_copy(
                    update={
                        "paths_new_in_window": telemetry.lane_summaries[0].paths_new_in_window + 99,
                        "instability_ppm": telemetry.lane_summaries[0].instability_ppm + 250_000,
                    }
                ),
                *telemetry.lane_summaries[1:],
            ],
        }
    )
    assert material_digest(grew, contract) == baseline, "routine coverage growth must not trigger a paid run"

    anomaly = telemetry.model_copy(
        update={
            "lane_summaries": [
                telemetry.lane_summaries[0].model_copy(
                    update={"novel_outcomes_in_window": telemetry.lane_summaries[0].novel_outcomes_in_window + 1}
                ),
                *telemetry.lane_summaries[1:],
            ],
        }
    )
    assert material_digest(anomaly, contract) != baseline, "a novel outcome (potential bug) must still trigger"


def test_new_kernel_mail_and_target_drift_change_material() -> None:
    telemetry, contract = _fixtures()
    baseline = material_digest(telemetry, contract)
    evidence = telemetry.evidence[0].model_copy(
        update={
            "evidence_ref": "evidence:lkml-new-message",
            "kind": EvidenceKind.KERNEL_PATCH,
            "summary": "A new public io_uring patch changed a reviewed operation boundary.",
        }
    )
    updated = telemetry.model_copy(update={"evidence": [*telemetry.evidence, evidence]})
    assert material_digest(updated, contract) != baseline
    changed_contract = contract.model_copy(
        update={
            "contract_id": "contract:changed",
        }
    )
    assert material_digest(telemetry, changed_contract) != baseline


def test_provider_model_authority_is_part_of_the_scheduled_material() -> None:
    telemetry, contract = _fixtures()
    config = load_config(ROOT / "examples" / "config.mock.toml")
    baseline = material_digest(telemetry, contract, config=config)
    changed = replace(
        config,
        planner=replace(config.planner, reasoning_effort="medium"),
    )
    assert material_digest(telemetry, contract, config=changed) != baseline


def test_state_skips_unchanged_then_refreshes(tmp_path: Path) -> None:
    telemetry, contract = _fixtures()
    digest = material_digest(telemetry, contract)
    store = TriggerStateStore(
        tmp_path / "trigger.json",
        refresh_seconds=48 * 60 * 60,
        retry_seconds=6 * 60 * 60,
    )
    with store.lease():
        first = store.assess(digest, now=NOW)
        assert first.should_run and first.reason == "initial"
        store.mark_attempt(digest, now=NOW)
        store.mark_completed(digest, now=NOW)
    with store.lease():
        unchanged = store.assess(digest, now=NOW + timedelta(hours=47))
        assert not unchanged.should_run and unchanged.reason == "unchanged"
        refresh = store.assess(digest, now=NOW + timedelta(hours=48))
        assert refresh.should_run and refresh.reason == "periodic_refresh"


def test_failure_has_bounded_retry_and_changed_material_is_not_lost(
    tmp_path: Path,
) -> None:
    telemetry, contract = _fixtures()
    digest = material_digest(telemetry, contract)
    changed = "sha256:" + "f" * 64
    store = TriggerStateStore(
        tmp_path / "trigger.json",
        refresh_seconds=48 * 60 * 60,
        retry_seconds=6 * 60 * 60,
    )
    with store.lease():
        store.mark_attempt(digest, now=NOW)
        store.mark_failed(digest, now=NOW)
    with store.lease():
        cooldown = store.assess(digest, now=NOW + timedelta(hours=1))
        assert not cooldown.should_run and cooldown.reason == "retry_cooldown"
        assert store.assess(
            digest, now=NOW + timedelta(hours=6)
        ).reason == "retry_due"
        assert store.assess(changed, now=NOW + timedelta(hours=1)).reason == "material_changed"


def test_state_mutation_and_concurrent_lease_fail_closed(tmp_path: Path) -> None:
    path = tmp_path / "trigger.json"
    store = TriggerStateStore(path, refresh_seconds=3600, retry_seconds=900)
    with pytest.raises(TriggerError):
        store.mark_attempt("sha256:" + "0" * 64, now=NOW)
    with store.lease():
        store.mark_completed("sha256:" + "0" * 64, now=NOW)
        with pytest.raises(TriggerError):
            with TriggerStateStore(
                path, refresh_seconds=3600, retry_seconds=900
            ).lease():
                pass
    data = json.loads(path.read_text(encoding="utf-8"))
    data["unexpected"] = True
    path.write_text(json.dumps(data), encoding="utf-8")
    with store.lease():
        with pytest.raises(TriggerError):
            store.assess("sha256:" + "0" * 64, now=NOW)
