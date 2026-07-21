from iou_ai.prompts import PLANNER_INSTRUCTIONS, REVIEWER_SYSTEM


def _one_line(value: str) -> str:
    return " ".join(value.split())


def test_gate_a_planner_emits_only_unordered_research_priorities() -> None:
    prompt = _one_line(PLANNER_INSTRUCTIONS)
    assert "may either abstain or return an analysis-only proposal" in prompt
    assert "must set analysis_only=true, programs=[]" in prompt
    assert "must not describe operation order" in prompt
    assert "cannot be compiled, promoted, or sent to a fuzzing queue" in prompt


def test_gate_a_reviewer_preserves_non_executable_boundary() -> None:
    prompt = _one_line(REVIEWER_SYSTEM)
    assert "require programs=[]" in prompt
    assert "Reject any operation ordering" in prompt
    assert "Retain independent discretion" in prompt
    assert "only for immutable quarantine" in prompt
    assert "Copy proposal_id and packet_id exactly" in prompt
    assert "set safe_for_quarantine=true" in prompt
    assert "For reject or escalate, set safe_for_quarantine=false" in prompt
    assert 'program_id="" and step_id=""' in prompt
