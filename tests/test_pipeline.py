from dataclasses import replace
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from iou_ai.config import load_config
from iou_ai.models import ProviderRole, ProviderTrace
from iou_ai.pipeline import PipelineRejected, ShadowPipeline, build_ledger, load_inputs
from iou_ai.providers import (
    MockAdapter,
    ProviderHTTPError,
    ProviderResult,
    ProviderTimeoutError,
    TokenUsage,
)
from iou_ai.quarantine import QuarantineStore
from iou_ai.validator import SemanticValidationError


class PipelineTests(unittest.TestCase):
    def _analysis_proposal_text(self) -> str:
        data = json.loads(
            (ROOT / "examples" / "proposal.mock.json").read_text(encoding="utf-8")
        )
        data.update(
            {
                "analysis_only": True,
                "research_priorities": [
                    {
                        "priority_id": "read_frontier",
                        "rationale": "The cited stable frontier warrants human review of the read operation family.",
                        "evidence_refs": ["evidence:coverage-read-link-plateau"],
                        "operation_families": ["read"],
                        "ring_profile_ids": ["default"],
                        "preferred_lanes": ["stable_coverage"],
                        "expected_signal": "Human analysis identifies whether the stable read frontier deserves a bounded template.",
                        "safety_notes": ["This priority contains no ordering, operands, resources, grammar, or seed."],
                    }
                ],
                "programs": [],
            }
        )
        return json.dumps(data)

    def test_mock_pipeline_quarantines_ir_without_compiling_or_touching_afl(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory)
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
            pipeline = ShadowPipeline(
                config,
                ledger=build_ledger(config),
                planner=MockAdapter(
                    (ROOT / "examples" / "proposal.mock.json").read_text(encoding="utf-8")
                ),
                reviewer=MockAdapter(
                    (ROOT / "examples" / "reviewer.mock.json").read_text(encoding="utf-8")
                ),
                quarantine=QuarantineStore(temp / "quarantine"),
            )
            outcome = pipeline.run(telemetry, contract)
            self.assertEqual(outcome.status, "quarantined")
            self.assertIsNotNone(outcome.envelope_path)
            self.assertTrue(outcome.envelope_path.is_file())
            self.assertEqual(list((temp / "quarantine").glob("*.json")), [outcome.envelope_path])

    def test_sampled_auditor_verdict_is_retained_in_envelope(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory)
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
                auditor=replace(config.auditor, enabled=True, sample_every=1),
            )
            telemetry, contract = load_inputs(
                ROOT / "examples" / "telemetry.sample.json",
                ROOT / "examples" / "harness-contract.mock.json",
            )
            proposal_text = (ROOT / "examples" / "proposal.mock.json").read_text(
                encoding="utf-8"
            )
            review_text = (ROOT / "examples" / "reviewer.mock.json").read_text(
                encoding="utf-8"
            )
            outcome = ShadowPipeline(
                config,
                ledger=build_ledger(config),
                planner=MockAdapter(proposal_text),
                reviewer=MockAdapter(review_text),
                auditor=MockAdapter(review_text),
                quarantine=QuarantineStore(temp / "quarantine"),
            ).run(telemetry, contract)
            envelope = json.loads(outcome.envelope_path.read_text(encoding="utf-8"))
            self.assertIsNotNone(envelope["auditor_verdict"])
            self.assertIsNotNone(envelope["auditor_verdict_hash"])
            self.assertEqual(len(envelope["validations"]), 3)
            self.assertEqual(
                {trace["role"] for trace in envelope["provider_traces"]},
                {"planner", "reviewer", "auditor"},
            )

    def test_analysis_only_priority_reaches_independent_review_and_quarantine(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory)
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
            contract = contract.model_copy(
                update={
                    "deterministic_compiler": False,
                    "decode_round_trip_verified": False,
                }
            )
            reviewer = MockAdapter(
                (ROOT / "examples" / "reviewer.mock.json").read_text(encoding="utf-8")
            )
            outcome = ShadowPipeline(
                config,
                ledger=build_ledger(config),
                planner=MockAdapter(self._analysis_proposal_text()),
                reviewer=reviewer,
                quarantine=QuarantineStore(temp / "quarantine"),
            ).run(telemetry, contract)
            self.assertEqual(outcome.status, "quarantined")
            self.assertEqual(len(reviewer.requests), 1)
            envelope = json.loads(outcome.envelope_path.read_text(encoding="utf-8"))
            self.assertTrue(envelope["proposal"]["analysis_only"])
            self.assertEqual(envelope["proposal"]["programs"], [])
            self.assertEqual(
                envelope["proposal"]["research_priorities"][0]["operation_families"],
                ["read"],
            )

    def test_timeout_is_conservatively_charged_without_retrying_or_review(self) -> None:
        class TimeoutAdapter:
            def __init__(self) -> None:
                self.requests = []

            def generate(self, request):
                self.requests.append(request)
                raise ProviderTimeoutError("provider request timed out")

        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory)
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
            planner = TimeoutAdapter()
            reviewer = MockAdapter(
                (ROOT / "examples" / "reviewer.mock.json").read_text(encoding="utf-8")
            )
            ledger = build_ledger(config)
            pipeline = ShadowPipeline(
                config,
                ledger=ledger,
                planner=planner,
                reviewer=reviewer,
                quarantine=QuarantineStore(temp / "quarantine"),
            )

            with self.assertRaises(ProviderTimeoutError):
                pipeline.run(telemetry, contract)

            self.assertEqual(len(planner.requests), 1)
            self.assertEqual(reviewer.requests, [])
            status = ledger.status()
            self.assertEqual(status.active_reserved_microdollars, 0)
            self.assertGreater(status.charged_microdollars, 0)

    def test_clean_provider_decline_settles_at_zero_not_worst_case(self) -> None:
        # A non-retryable provider decline (cyber_policy 400 / safety refusal)
        # generates nothing billable, so it must settle at zero rather than
        # conservatively charging the full reservation and starving the budget.
        class DecliningAdapter:
            def __init__(self) -> None:
                self.requests: list[object] = []

            def generate(self, request):
                self.requests.append(request)
                raise ProviderHTTPError("openai", 400)

        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory)
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
            planner = DecliningAdapter()
            ledger = build_ledger(config)
            pipeline = ShadowPipeline(
                config,
                ledger=ledger,
                planner=planner,
                reviewer=MockAdapter(
                    (ROOT / "examples" / "reviewer.mock.json").read_text(encoding="utf-8")
                ),
                quarantine=QuarantineStore(temp / "quarantine"),
            )

            with self.assertRaises(ProviderHTTPError):
                pipeline.run(telemetry, contract)

            self.assertEqual(len(planner.requests), 1)
            status = ledger.status()
            self.assertEqual(status.active_reserved_microdollars, 0)
            self.assertEqual(status.charged_microdollars, 0)  # zero, not worst-case

    def test_planner_fails_over_to_fallback_when_primary_declines(self) -> None:
        # A provider policy block (e.g. OpenAI cyber_policy HTTP 400) on the
        # primary planner must fail over to the approved fallback provider, and
        # the run must complete through the same downstream gates.
        class RefusingAdapter:
            def __init__(self) -> None:
                self.requests: list[object] = []

            def generate(self, request):
                self.requests.append(request)
                raise ProviderHTTPError("openai", 400)  # cyber_policy-style decline

        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory)
            config = load_config(ROOT / "examples" / "config.mock.toml")
            fallback_provider = replace(
                config.planner,
                name="anthropic",
                endpoint="https://api.anthropic.com/v1/messages",
                model="claude-opus-4-8",
            )
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
                planner_fallbacks=(fallback_provider,),
            )
            telemetry, contract = load_inputs(
                ROOT / "examples" / "telemetry.sample.json",
                ROOT / "examples" / "harness-contract.mock.json",
            )
            primary = RefusingAdapter()
            fallback = MockAdapter(
                (ROOT / "examples" / "proposal.mock.json").read_text(encoding="utf-8")
            )
            pipeline = ShadowPipeline(
                config,
                ledger=build_ledger(config),
                planner=primary,
                reviewer=MockAdapter(
                    (ROOT / "examples" / "reviewer.mock.json").read_text(encoding="utf-8")
                ),
                planner_fallbacks=((fallback, fallback_provider),),
                quarantine=QuarantineStore(temp / "quarantine"),
            )

            outcome = pipeline.run(telemetry, contract)
            self.assertEqual(outcome.status, "quarantined")
            self.assertEqual(len(primary.requests), 1)  # primary tried exactly once

    def test_reviewer_validation_diagnostic_never_echoes_provider_values(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory)
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
            marker = "PROVIDER_CONTROLLED_SECRET_VALUE"
            pipeline = ShadowPipeline(
                config,
                ledger=build_ledger(config),
                planner=MockAdapter(
                    (ROOT / "examples" / "proposal.mock.json").read_text(
                        encoding="utf-8"
                    )
                ),
                reviewer=MockAdapter(json.dumps({"unexpected": marker})),
                quarantine=QuarantineStore(temp / "quarantine"),
            )

            with self.assertRaises(PipelineRejected) as caught:
                pipeline.run(telemetry, contract)

            diagnostic = str(caught.exception)
            self.assertIn("reviewer verdict failed strict local validation", diagnostic)
            self.assertNotIn(marker, diagnostic)
            self.assertNotIn("unexpected", diagnostic)

    def test_mixed_case_anthropic_response_id_is_valid_audit_metadata(self) -> None:
        trace = ProviderTrace(
            role=ProviderRole.REVIEWER,
            provider="anthropic",
            model="claude-sonnet-5",
            response_id="msg_011Cd6r7D766Jtkdq1MRUezi",
            client_request_id="reviewer-0123456789abcdef",
            input_tokens=1,
            output_tokens=1,
            reasoning_tokens=0,
            cost_microusd=1,
        )
        self.assertEqual(trace.response_id, "msg_011Cd6r7D766Jtkdq1MRUezi")

    def test_invalid_provider_trace_never_echoes_metadata_in_a_traceback(self) -> None:
        class InvalidMetadataReviewer:
            def generate(self, request):
                return ProviderResult(
                    provider="anthropic",
                    model="claude-sonnet-5",
                    text=(ROOT / "examples" / "reviewer.mock.json").read_text(
                        encoding="utf-8"
                    ),
                    response_id="PROVIDER_CONTROLLED SECRET VALUE",
                    provider_request_id=None,
                    client_request_id=request.client_request_id,
                    status="end_turn",
                    usage=TokenUsage(
                        input_tokens=1,
                        output_tokens=1,
                        total_tokens=2,
                    ),
                )

        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory)
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
            pipeline = ShadowPipeline(
                config,
                ledger=build_ledger(config),
                planner=MockAdapter(
                    (ROOT / "examples" / "proposal.mock.json").read_text(
                        encoding="utf-8"
                    )
                ),
                reviewer=InvalidMetadataReviewer(),
                quarantine=QuarantineStore(temp / "quarantine"),
            )

            with self.assertRaises(PipelineRejected) as caught:
                pipeline.run(telemetry, contract)

            diagnostic = str(caught.exception)
            self.assertEqual(
                diagnostic,
                "provider trace failed strict local validation",
            )
            self.assertNotIn("PROVIDER_CONTROLLED", diagnostic)

    def test_reviewer_reject_is_sanitized_for_feedback_but_never_quarantined(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory)
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
            review = json.loads(
                (ROOT / "examples" / "reviewer.mock.json").read_text(
                    encoding="utf-8"
                )
            )
            review.update(
                {
                    "verdict": "reject",
                    "summary": "Do not persist reviewer prose or /root/private material.",
                    "residual_risk": "high",
                    "safe_for_quarantine": False,
                    "required_changes": ["A provider-authored change request."],
                    "findings": [
                        {
                            "finding_id": "finding:bounded-reject",
                            "severity": "high",
                            "category": "safety",
                            "message": "Do not retain candidate bytes or crash material.",
                            "evidence_refs": [
                                "evidence:coverage-read-link-plateau"
                            ],
                            "program_id": "",
                            "step_id": "",
                        }
                    ],
                }
            )
            pipeline = ShadowPipeline(
                config,
                ledger=build_ledger(config),
                planner=MockAdapter(
                    (ROOT / "examples" / "proposal.mock.json").read_text(
                        encoding="utf-8"
                    )
                ),
                reviewer=MockAdapter(json.dumps(review)),
                quarantine=QuarantineStore(temp / "quarantine"),
            )

            with self.assertRaises(SemanticValidationError):
                pipeline.run(telemetry, contract)

            self.assertFalse((temp / "quarantine").exists())
            feedback_files = list((temp / "review-feedback").glob("*.json"))
            self.assertEqual(len(feedback_files), 1)
            feedback_wire = feedback_files[0].read_text(encoding="utf-8")
            self.assertIn('"verdict":"reject"', feedback_wire)
            self.assertNotIn("reviewer prose", feedback_wire)
            self.assertNotIn("/root/", feedback_wire)
            self.assertNotIn("candidate bytes", feedback_wire)


if __name__ == "__main__":
    unittest.main()
