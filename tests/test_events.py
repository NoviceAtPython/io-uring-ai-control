from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

from pydantic import ValidationError


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from iou_ai.budget import BudgetStatus  # noqa: E402
from iou_ai.config import load_config  # noqa: E402
from iou_ai.events import (  # noqa: E402
    ApprovalChallenge,
    BudgetThresholdEvent,
    CounterSnapshot,
    CrashTriageEvent,
    EventOutbox,
    EventProjectionError,
    ProposalQuarantinedEvent,
    approval_binding_digest,
    parse_event,
    project_budget_status,
    project_counter_snapshot,
    project_quarantine,
    render_fixed_message,
)
from iou_ai.models import TargetHashes  # noqa: E402
from iou_ai.pipeline import ShadowPipeline, build_ledger, load_inputs  # noqa: E402
from iou_ai.providers import MockAdapter  # noqa: E402
from iou_ai.quarantine import QuarantineStore, canonical_json  # noqa: E402


NOW = datetime(2026, 7, 16, 20, 0, tzinfo=timezone.utc)


def target_hashes(seed: str = "a") -> TargetHashes:
    values = [seed, "b", "c", "d"]
    return TargetHashes(
        harness_hash="sha256:" + values[0] * 64,
        compiler_hash="sha256:" + values[1] * 64,
        op_table_hash="sha256:" + values[2] * 64,
        fleet_config_hash="sha256:" + values[3] * 64,
    )


class EventProjectorTests(unittest.TestCase):
    def _run_mock_pipeline(self, temp: Path) -> Path:
        config = load_config(ROOT / "examples" / "config.mock.toml")
        config = replace(
            config,
            budget=replace(
                config.budget,
                database=temp / "budget.sqlite3",
                kill_switch=temp / "AI_CALLS_DISABLED",
            ),
            runtime=replace(
                config.runtime,
                state_dir=temp,
                quarantine_dir=temp / "quarantine",
            ),
            auditor=replace(config.auditor, enabled=False),
        )
        telemetry, contract = load_inputs(
            ROOT / "examples" / "telemetry.sample.json",
            ROOT / "examples" / "harness-contract.mock.json",
        )
        outcome = ShadowPipeline(
            config,
            ledger=build_ledger(config),
            planner=MockAdapter(
                (ROOT / "examples" / "proposal.mock.json").read_text(encoding="utf-8")
            ),
            reviewer=MockAdapter(
                (ROOT / "examples" / "reviewer.mock.json").read_text(encoding="utf-8")
            ),
            quarantine=QuarantineStore(temp / "quarantine"),
        ).run(telemetry, contract)
        assert outcome.envelope_path is not None
        return outcome.envelope_path

    def test_quarantine_projection_is_verified_redacted_and_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory)
            envelope_path = self._run_mock_pipeline(temp)
            outbox = EventOutbox(temp / "outbox")
            nonce_calls: list[int] = []

            def nonce_source(length: int) -> bytes:
                nonce_calls.append(length)
                return bytes(range(32))

            first = project_quarantine(
                temp / "quarantine",
                outbox,
                created_at=NOW,
                nonce_source=nonce_source,
            )
            second = project_quarantine(
                temp / "quarantine",
                outbox,
                created_at=NOW,
                nonce_source=nonce_source,
            )

            self.assertEqual(len(first), 1)
            self.assertEqual(second, ())
            self.assertEqual(nonce_calls, [32])
            self.assertEqual(len(list((temp / "outbox").glob("*.json"))), 1)
            event = first[0]
            envelope_digest = "sha256:" + hashlib.sha256(
                envelope_path.read_bytes()
            ).hexdigest()
            self.assertEqual(event.envelope_digest, envelope_digest)
            self.assertEqual(
                event.approval.binding_digest,
                approval_binding_digest(
                    envelope_digest=envelope_digest,
                    target_hashes=event.target_hashes,
                    nonce=event.approval.nonce,
                    human_code=event.approval.human_code,
                    expires_at=event.approval.expires_at,
                ),
            )
            wire = next((temp / "outbox").glob("*.json")).read_text(encoding="utf-8")
            self.assertNotIn('"proposal":', wire)
            self.assertNotIn('"reviewer_verdict":', wire)
            self.assertNotIn("rationale", wire)
            self.assertNotIn("programs", wire)
            message = render_fixed_message(event)
            self.assertIn("Reply APPROVE", message)
            self.assertIn("Offline validation only", message)

    def test_expired_single_challenge_is_reissued_once(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory)
            self._run_mock_pipeline(temp)
            outbox = EventOutbox(temp / "outbox")
            nonces = iter((bytes(range(32)), bytes(range(31, -1, -1))))

            first = project_quarantine(
                temp / "quarantine",
                outbox,
                created_at=NOW,
                nonce_source=lambda length: next(nonces),
            )
            second = project_quarantine(
                temp / "quarantine",
                outbox,
                created_at=NOW + timedelta(minutes=31),
                nonce_source=lambda length: next(nonces),
            )
            third = project_quarantine(
                temp / "quarantine",
                outbox,
                created_at=NOW + timedelta(minutes=62),
            )

            self.assertEqual(len(first), 1)
            self.assertEqual(len(second), 1)
            self.assertEqual(third, ())
            self.assertNotEqual(first[0].approval.nonce, second[0].approval.nonce)
            self.assertNotEqual(first[0].approval.human_code, second[0].approval.human_code)
            self.assertEqual(len(outbox.events()), 2)

    def test_quarantine_filename_digest_mismatch_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory)
            source = self._run_mock_pipeline(temp)
            forged = temp / "quarantine" / ("0" * 64 + ".json")
            forged.write_bytes(source.read_bytes())
            with self.assertRaisesRegex(EventProjectionError, "content digest mismatch"):
                project_quarantine(temp / "quarantine", EventOutbox(temp / "outbox"))

    def test_weak_nonce_source_fails_before_outbox_write(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory)
            self._run_mock_pipeline(temp)
            outbox = EventOutbox(temp / "outbox")
            with self.assertRaisesRegex(EventProjectionError, "exactly 32"):
                project_quarantine(
                    temp / "quarantine",
                    outbox,
                    created_at=NOW,
                    nonce_source=lambda _: b"short",
                )
            self.assertEqual(outbox.events(), ())

    def test_event_contract_rejects_free_form_fields_and_unbound_challenge(self) -> None:
        hashes = target_hashes()
        envelope_digest = "sha256:" + "e" * 64
        nonce = "1" * 64
        challenge = ApprovalChallenge(
            nonce=nonce,
            human_code="ABCDEFG2",
            expires_at="2026-07-16T20:30:00Z",
            binding_digest=approval_binding_digest(
                envelope_digest=envelope_digest,
                target_hashes=hashes,
                nonce=nonce,
                human_code="ABCDEFG2",
                expires_at="2026-07-16T20:30:00Z",
            ),
        )
        valid = {
            "created_at": "2026-07-16T20:00:00Z",
            "envelope_digest": envelope_digest,
            "proposal_hash": "sha256:" + "f" * 64,
            "target_hashes": hashes,
            "approval": challenge,
        }
        with self.assertRaises(ValidationError):
            ProposalQuarantinedEvent(**valid, model_text="untrusted prose")
        with self.assertRaises(ValidationError):
            ProposalQuarantinedEvent(
                **{
                    **valid,
                    "approval": challenge.model_copy(
                        update={"binding_digest": "sha256:" + "0" * 64}
                    ),
                }
            )
        with self.assertRaises(ValidationError):
            ApprovalChallenge.model_validate(
                {
                    "nonce": nonce,
                    "binding_digest": challenge.binding_digest,
                    "allowed_actions": ("approve_live_fleet", "deny"),
                },
                strict=True,
            )

    def test_outbox_is_content_addressed_create_only_and_strict(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            hashes = target_hashes()
            envelope_digest = "sha256:" + "e" * 64
            nonce = "1" * 64
            event = ProposalQuarantinedEvent(
                created_at="2026-07-16T20:00:00Z",
                envelope_digest=envelope_digest,
                proposal_hash="sha256:" + "f" * 64,
                target_hashes=hashes,
                approval=ApprovalChallenge(
                    nonce=nonce,
                    human_code="ABCDEFG2",
                    expires_at="2026-07-16T20:30:00Z",
                    binding_digest=approval_binding_digest(
                        envelope_digest=envelope_digest,
                        target_hashes=hashes,
                        nonce=nonce,
                        human_code="ABCDEFG2",
                        expires_at="2026-07-16T20:30:00Z",
                    ),
                ),
            )
            outbox = EventOutbox(root)
            first_digest, first_path = outbox.put(event)
            second_digest, second_path = outbox.put(event)
            self.assertEqual((first_digest, first_path), (second_digest, second_path))
            self.assertEqual(first_digest, hashlib.sha256(first_path.read_bytes()).hexdigest())

            invalid = event.model_dump(mode="json")
            invalid["raw_artifact"] = "forbidden"
            invalid_payload = canonical_json(invalid)
            with self.assertRaises(EventProjectionError):
                parse_event(invalid_payload)

    def test_unavailable_outbox_is_not_silently_treated_as_empty(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with mock.patch(
                "iou_ai.events.os.listdir",
                side_effect=PermissionError("simulated traversal denial"),
            ):
                with self.assertRaisesRegex(
                    EventProjectionError, "event outbox is unavailable"
                ):
                    EventOutbox(root).events()

    def test_budget_thresholds_project_once_per_month_and_threshold(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            outbox = EventOutbox(directory)
            status = BudgetStatus(
                month="2026-07",
                hard_limit_microdollars=7_500_000,
                charged_microdollars=2_126_635,
                active_reserved_microdollars=0,
                effective_spend_microdollars=2_126_635,
                remaining_microdollars=5_373_365,
                warning_level="warning",
                crossed_warning_thresholds_microdollars=(2_000_000,),
                call_counts=(),
            )
            first = project_budget_status(status, outbox, created_at=NOW)
            second = project_budget_status(status, outbox, created_at=NOW)
            self.assertEqual(len(first), 1)
            self.assertEqual(second, ())
            self.assertIn("$5.37 remains", render_fixed_message(first[0]))

    def test_budget_message_uses_integer_half_up_cents(self) -> None:
        event = BudgetThresholdEvent(
            created_at="2026-07-16T20:00:00Z",
            severity="warning",
            month="2026-07",
            threshold_microdollars=125_000,
            effective_spend_microdollars=125_000,
            hard_limit_microdollars=1_005_000,
            remaining_microdollars=880_000,
        )
        self.assertEqual(
            render_fixed_message(event),
            "IOU-AI BUDGET: monthly spend crossed $0.13; "
            "$0.88 remains of $1.01.",
        )
        vector = json.loads(
            (ROOT / "relay" / "cloudflare" / "test-vectors.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(
            render_fixed_message(parse_event(json.dumps(vector["event"]))),
            vector["fixed_message"],
        )

    def test_counter_projection_has_baseline_delta_idempotence_and_reset_rules(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            outbox = EventOutbox(directory)
            hashes = target_hashes()
            previous = CounterSnapshot(
                campaign_id="iou-campaign",
                telemetry_packet_digest="sha256:" + "1" * 64,
                target_hashes=hashes,
                crash_count=0,
                hang_count=1,
            )
            current = CounterSnapshot(
                campaign_id="iou-campaign",
                telemetry_packet_digest="sha256:" + "2" * 64,
                target_hashes=hashes,
                crash_count=2,
                hang_count=3,
            )
            self.assertEqual(
                project_counter_snapshot(None, previous, outbox, created_at=NOW), ()
            )
            projected = project_counter_snapshot(
                previous, current, outbox, created_at=NOW
            )
            self.assertEqual(
                [event.event_kind for event in projected],
                ["crash_counter_increase", "hang_counter_increase"],
            )
            self.assertEqual([event.increase for event in projected], [2, 2])
            self.assertEqual(
                project_counter_snapshot(previous, current, outbox, created_at=NOW), ()
            )
            reset = current.model_copy(
                update={
                    "telemetry_packet_digest": "sha256:" + "3" * 64,
                    "crash_count": 0,
                }
            )
            self.assertEqual(
                project_counter_snapshot(current, reset, outbox, created_at=NOW), ()
            )
            self.assertIn("bounty status are not yet established", render_fixed_message(projected[0]))

    def test_high_value_wording_requires_reproduced_kernel_memory_safety(self) -> None:
        event = CrashTriageEvent(
            created_at="2026-07-16T20:00:00Z",
            severity="urgent",
            campaign_id="iou-campaign",
            telemetry_packet_digest="sha256:" + "1" * 64,
            target_hashes=target_hashes(),
            stack_signature="sha256:" + "8" * 64,
            bug_class="kasan_use_after_free",
            reproductions=2,
            kernel_context_confirmed=True,
            potential_high_value=True,
        )
        message = render_fixed_message(event)
        self.assertIn("POTENTIAL HIGH-VALUE SECURITY IMPACT", message)
        self.assertIn("Not a confirmed bounty", message)
        invalid = event.model_dump(mode="json")
        invalid["reproductions"] = 1
        with self.assertRaises(ValidationError):
            CrashTriageEvent.model_validate(invalid, strict=True)


if __name__ == "__main__":
    unittest.main()
