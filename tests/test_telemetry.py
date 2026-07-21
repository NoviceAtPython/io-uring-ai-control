from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path

import pytest

from iou_ai.feedback import FeedbackStore, build_review_feedback
from iou_ai.models import HarnessContract, PlannerProposal, ReviewerVerdict, TelemetryPacket
from iou_ai.telemetry import TelemetryError, build_packet, load_lkml_evidence, parse_fuzzer_stats
from iou_ai.validator import validate_reviewer


def _contract() -> HarnessContract:
    return HarnessContract.model_validate_json(
        Path("examples/harness-contract.mock.json").read_text(encoding="utf-8")
    )


def _write_stats(path: Path, *, updated: int, executions: int, corpus: int, edges: int) -> None:
    path.parent.mkdir(parents=True)
    path.write_text(
        "\n".join(
            (
                f"last_update : {updated}",
                f"execs_done : {executions}",
                "execs_per_sec : 123.5",
                f"corpus_count : {corpus}",
                f"edges_found : {edges}",
                "stability : 95.0%",
                "bitmap_cvg : 12.5%",
                "saved_crashes : 0",
                "saved_hangs : 1",
                "command_line : /root/private --token should-never-leave-host",
            )
        ),
        encoding="utf-8",
    )


def test_packet_aggregates_without_summing_synchronized_corpora(tmp_path: Path) -> None:
    now = datetime(2026, 7, 16, 12, 0, tzinfo=timezone.utc)
    epoch = int(now.timestamp())
    stats = tmp_path / "stats"
    _write_stats(stats / "0" / "fuzzer_stats", updated=epoch, executions=100, corpus=40, edges=12)
    _write_stats(stats / "1" / "fuzzer_stats", updated=epoch, executions=200, corpus=50, edges=14)

    packet = build_packet(
        stats_dir=stats,
        contract=_contract(),
        state_file=tmp_path / "state.json",
        kernel_release="6.12-test",
        expected_workers=2,
        native_workers=1,
        now=now,
    )

    assert packet.fleet.workers_running == 2
    assert packet.fleet.executions_total == 300
    assert packet.fleet.queue_entries == 50
    assert packet.coverage.edges_total == 14
    serialized = packet.model_dump_json()
    assert "command_line" not in serialized
    assert "private" not in serialized
    assert packet.externalization.contains_raw_logs is False


def test_parser_fails_closed_when_required_numeric_stat_is_missing(tmp_path: Path) -> None:
    path = tmp_path / "fuzzer_stats"
    path.write_text("last_update : 1\nexecs_done : 2\n", encoding="utf-8")
    with pytest.raises(TelemetryError, match="execs_per_sec"):
        parse_fuzzer_stats(path)


def test_lkml_evidence_requires_explicit_untrusted_label(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence" / "sha256" / "aa" / "message.json"
    evidence.parent.mkdir(parents=True)
    evidence.write_text(
        json.dumps(
            {
                "schema_version": "lkml-evidence.v1",
                "message_id_sha256": "a" * 64,
                "subject": "[PATCH] io_uring: bounded test",
                "structural_summary": "one file and one hunk",
                "public_url": "https://lore.kernel.org/io-uring/example/",
                "diff_file_paths": ["io_uring/test.c"],
                "diff_counts": {"files": 1, "hunks": 1},
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(TelemetryError, match="trust label"):
        load_lkml_evidence(tmp_path)


def test_next_packet_includes_only_verified_bounded_reviewer_feedback(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 7, 16, 12, 0, tzinfo=timezone.utc)
    epoch = int(now.timestamp())
    stats = tmp_path / "stats"
    _write_stats(
        stats / "0" / "fuzzer_stats",
        updated=epoch,
        executions=100,
        corpus=40,
        edges=12,
    )
    telemetry = TelemetryPacket.model_validate_json(
        Path("examples/telemetry.sample.json").read_text(encoding="utf-8")
    )
    proposal = PlannerProposal.model_validate_json(
        Path("examples/proposal.mock.json").read_text(encoding="utf-8")
    )
    verdict = ReviewerVerdict.model_validate_json(
        Path("examples/reviewer.mock.json").read_text(encoding="utf-8")
    )
    FeedbackStore(tmp_path / "feedback").put(
        build_review_feedback(
            telemetry,
            proposal,
            verdict,
            validate_reviewer(telemetry, proposal, verdict),
            now=now,
        )
    )

    packet = build_packet(
        stats_dir=stats,
        contract=_contract(),
        state_file=tmp_path / "state.json",
        kernel_release="6.12-test",
        expected_workers=1,
        native_workers=1,
        now=now,
        feedback_dir=tmp_path / "feedback",
    )

    assert len(packet.prior_proposal_outcomes) == 1
    prior = packet.prior_proposal_outcomes[0]
    assert prior.proposal_id == proposal.proposal_id
    assert prior.outcome.value == "not_run"
    assert "verdict=accept" in prior.summary
    assert verdict.summary not in packet.model_dump_json()
