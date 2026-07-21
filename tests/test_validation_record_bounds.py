from iou_ai.models import ValidationRecord


def test_validation_record_accepts_a_complete_bounded_rule_set() -> None:
    record = ValidationRecord(
        validator_version="validator:test",
        validator_hash="sha256:" + "a" * 64,
        passed_check_ids=[f"check_{index:03d}" for index in range(72)],
        failed_check_ids=[],
    )
    assert len(record.passed_check_ids) == 72
