from pathlib import Path
import json
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from iou_ai.models import (
    HarnessContract,
    LinkMode,
    PlannerProposal,
    ResidualRisk,
    ReviewerVerdict,
    TelemetryPacket,
)
from iou_ai.validator import (
    validate_proposal,
    validate_reviewer,
    validate_run_inputs,
)


@unittest.skipUnless(
    (ROOT / "examples" / "telemetry.sample.json").exists()
    and (ROOT / "examples" / "harness-contract.mock.json").exists(),
    "contract fixtures are generated alongside the strict models",
)
class ValidatorTests(unittest.TestCase):
    def _fixtures(self):
        telemetry = TelemetryPacket.model_validate_json(
            (ROOT / "examples" / "telemetry.sample.json").read_text(encoding="utf-8")
        )
        contract = HarnessContract.model_validate_json(
            (ROOT / "examples" / "harness-contract.mock.json").read_text(encoding="utf-8")
        )
        proposal_path = ROOT / "examples" / "proposal.mock.json"
        if not proposal_path.exists():
            self.skipTest("proposal fixture not present")
        proposal = PlannerProposal.model_validate_json(
            proposal_path.read_text(encoding="utf-8")
        )
        return telemetry, contract, proposal

    def _analysis_proposal(self, proposal: PlannerProposal) -> PlannerProposal:
        data = proposal.model_dump(mode="json")
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
        return PlannerProposal.model_validate_json(json.dumps(data))

    def test_mock_proposal_matches_mock_contract(self) -> None:
        telemetry, contract, proposal = self._fixtures()
        report = validate_proposal(telemetry, proposal, contract, runtime_mode="mock")
        self.assertTrue(report.valid, report.issues)

    def test_mock_contract_cannot_authorize_external_shadow(self) -> None:
        telemetry, contract, proposal = self._fixtures()
        report = validate_proposal(telemetry, proposal, contract, runtime_mode="shadow")
        self.assertFalse(report.valid)
        self.assertIn("contract.mode", report.failed_check_ids)

    def test_analysis_only_priority_is_valid_with_closed_compiler(self) -> None:
        telemetry, contract, proposal = self._fixtures()
        contract = contract.model_copy(
            update={
                "deterministic_compiler": False,
                "decode_round_trip_verified": False,
            }
        )
        proposal = self._analysis_proposal(proposal)
        report = validate_proposal(telemetry, proposal, contract, runtime_mode="mock")
        self.assertTrue(report.valid, report.issues)
        self.assertIn("analysis.read_frontier.operations", report.passed_check_ids)

    def test_program_proposal_is_blocked_when_compiler_is_closed(self) -> None:
        telemetry, contract, proposal = self._fixtures()
        contract = contract.model_copy(
            update={
                "deterministic_compiler": False,
                "decode_round_trip_verified": False,
            }
        )
        report = validate_proposal(telemetry, proposal, contract, runtime_mode="mock")
        self.assertFalse(report.valid)
        self.assertIn("contract.program-gate", report.failed_check_ids)

    def test_analysis_only_priority_rejects_unknown_operation_family(self) -> None:
        telemetry, contract, proposal = self._fixtures()
        proposal = self._analysis_proposal(proposal)
        data = proposal.model_dump(mode="json")
        data["research_priorities"][0]["operation_families"] = ["unknown_op"]
        proposal = PlannerProposal.model_validate_json(json.dumps(data))
        report = validate_proposal(telemetry, proposal, contract, runtime_mode="mock")
        self.assertFalse(report.valid)
        self.assertIn("analysis.read_frontier.operations", report.failed_check_ids)

    def test_preflight_rejects_tampered_packet_hash(self) -> None:
        telemetry, contract, _ = self._fixtures()
        telemetry = telemetry.model_copy(
            update={"packet_hash": "sha256:" + "0" * 64}
        )
        report = validate_run_inputs(telemetry, contract, runtime_mode="mock")
        self.assertFalse(report.valid)
        self.assertIn("preflight.packet-hash", report.failed_check_ids)

    def test_step_ring_reference_must_match_program_profile(self) -> None:
        telemetry, contract, proposal = self._fixtures()
        program = proposal.programs[0]
        step = program.steps[0].model_copy(update={"ring_ref": "defer_taskrun"})
        program = program.model_copy(update={"steps": [step]})
        proposal = proposal.model_copy(update={"programs": [program]})
        report = validate_proposal(telemetry, proposal, contract, runtime_mode="mock")
        self.assertFalse(report.valid)
        self.assertIn(
            "program.read_link_probe.step.read_a.ring-ref",
            report.failed_check_ids,
        )

    def test_link_mode_must_match_link_flags(self) -> None:
        telemetry, contract, proposal = self._fixtures()
        program = proposal.programs[0]
        step = program.steps[0].model_copy(update={"link_mode": LinkMode.NONE})
        program = program.model_copy(update={"steps": [step]})
        proposal = proposal.model_copy(update={"programs": [program]})
        report = validate_proposal(telemetry, proposal, contract, runtime_mode="mock")
        self.assertFalse(report.valid)
        self.assertIn(
            "program.read_link_probe.step.read_a.link-mode",
            report.failed_check_ids,
        )

    def test_accept_review_rejects_high_residual_risk(self) -> None:
        telemetry, _, proposal = self._fixtures()
        verdict = ReviewerVerdict.model_validate_json(
            (ROOT / "examples" / "reviewer.mock.json").read_text(encoding="utf-8")
        ).model_copy(update={"residual_risk": ResidualRisk.HIGH})
        report = validate_reviewer(telemetry, proposal, verdict)
        self.assertFalse(report.valid)
        self.assertIn("review.acceptance", report.failed_check_ids)

    def test_review_finding_must_reference_evidence_the_reviewer_checked(self) -> None:
        telemetry, _, proposal = self._fixtures()
        data = json.loads(
            (ROOT / "examples" / "reviewer.mock.json").read_text(encoding="utf-8")
        )
        data.update(
            {
                "verdict": "reject",
                "residual_risk": "high",
                "safe_for_quarantine": False,
                "required_changes": ["Resolve the evidence gap."],
                "findings": [
                    {
                        "finding_id": "finding:unchecked-evidence",
                        "severity": "high",
                        "category": "evidence_gap",
                        "message": "A cited signal was not included in checked evidence.",
                        "evidence_refs": [
                            "evidence:race-timeout-cancel-signal"
                        ],
                        "program_id": "",
                        "step_id": "",
                    }
                ],
            }
        )
        verdict = ReviewerVerdict.model_validate_json(json.dumps(data))
        report = validate_reviewer(telemetry, proposal, verdict)

        self.assertFalse(report.valid)
        self.assertIn("review.evidence", report.failed_check_ids)


if __name__ == "__main__":
    unittest.main()
