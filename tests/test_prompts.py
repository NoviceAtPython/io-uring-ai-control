from iou_ai.prompts import PLANNER_INSTRUCTIONS, REVIEWER_SYSTEM


def _one_line(value: str) -> str:
    return " ".join(value.split())


def test_planner_is_steered_toward_async_lifecycle_bug_classes() -> None:
    # io_uring memory-safety defects concentrate in async completion ordering and
    # resource lifecycles (free/remove/re-register while a request is in flight).
    # The planner must be steered toward those shapes and toward diversity, while
    # still deferring to the contract and validator.
    prompt = _one_line(PLANNER_INSTRUCTIONS)
    assert "asynchronous completion ordering and resource lifecycles" in prompt
    assert "use-after-free" in prompt
    assert "cancelled or times out while a successor" in prompt
    assert "deliberately vary the operation families" in prompt
    # Diversity/steering never overrides the contract or the ordering rules.
    assert "abstain rather than approximate it" in prompt


def test_planner_is_taught_the_rules_that_actually_rejected_a_live_run() -> None:
    # 2026-07-21: the first unattended planner run was rejected by the validator
    # for (a) step ring_ref not matching the program ring_profile_id -- a rule the
    # prompt never stated at all -- and (b) a BUFFER_SELECT step whose buffer group
    # had no matching prior provide_buffers, because the prompt never said HOW the
    # group is derived. Both are guidance-only; the validator still enforces them
    # independently. Without this the lane fails every cycle and produces nothing.
    prompt = _one_line(PLANNER_INSTRUCTIONS)
    assert "ring_ref to exactly its own program's ring_profile_id" in prompt
    assert "buffer_group = sum(flag bit_values) >> 4" in prompt


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
