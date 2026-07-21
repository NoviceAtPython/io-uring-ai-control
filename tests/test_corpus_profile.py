from __future__ import annotations

from pathlib import Path

from iou_ai.corpus_profile import build_operation_profile
from iou_ai.harness_codec import NativeOperation, NativeProgram, encode_program
from iou_ai.quarantine import canonical_json
from iou_ai.telemetry import build_packet, load_corpus_operation_evidence

from test_validation_authority import _contract


def _seed(selector: int, operands: tuple[int, ...] = ()) -> bytes:
    contract = _contract()
    return encode_program(
        NativeProgram(
            ring_selector=0,
            operations=(
                NativeOperation(selector=selector, operands=operands, sqe_control=0),
            ),
        ),
        harness_hash=contract.target_hashes.harness_hash,
    )


def test_profile_exports_only_bounded_aggregate_operation_evidence(
    tmp_path: Path,
) -> None:
    contract = _contract()
    queue = tmp_path / "corpus" / "0" / "queue"
    queue.mkdir(parents=True)
    (queue / "id_000001").write_bytes(_seed(0))
    (queue / "id_000002").write_bytes(_seed(1, (7,)))
    (queue / "id_000003").write_bytes(bytes((255, 255)))
    profile = build_operation_profile(corpus_dir=tmp_path / "corpus", contract=contract)

    assert profile.status == "available"
    assert profile.sampled_files == 3
    assert profile.canonical_inputs == 2
    assert profile.decoded_operations == 2
    assert len(profile.least_observed_operations) == 12
    assert "id_000001" not in canonical_json(profile.document()).decode("ascii")

    profile_path = tmp_path / "operation-profile.json"
    profile_path.write_bytes(canonical_json(profile.document()))
    evidence = load_corpus_operation_evidence(profile_path, contract=contract)
    assert evidence is not None
    assert evidence["evidence_ref"] == "evidence:fleet-corpus-operation-profile"
    assert "operation-frequency evidence" in str(evidence["summary"])


def test_unavailable_codec_profile_is_not_sent_as_coverage_evidence(tmp_path: Path) -> None:
    contract = _contract()
    mismatched = contract.model_copy(
        update={
            "target_hashes": contract.target_hashes.model_copy(
                update={"harness_hash": "sha256:" + "e" * 64}
            )
        }
    )
    profile = build_operation_profile(corpus_dir=tmp_path, contract=mismatched)
    profile_path = tmp_path / "operation-profile.json"
    profile_path.write_bytes(canonical_json(profile.document()))
    assert load_corpus_operation_evidence(profile_path, contract=mismatched) is None


def test_packet_accepts_profile_without_exposing_a_raw_seed(tmp_path: Path) -> None:
    contract = _contract()
    stats = tmp_path / "stats"
    now_epoch = 1_784_260_800
    for worker in ("0", "1"):
        stat_path = stats / worker / "fuzzer_stats"
        stat_path.parent.mkdir(parents=True)
        stat_path.write_text(
            "\n".join(
                (
                    f"last_update : {now_epoch}",
                    "execs_done : 10",
                    "execs_per_sec : 1.0",
                    "corpus_count : 2",
                    "edges_found : 3",
                    "cycles_wo_finds : 4",
                )
            ),
            encoding="utf-8",
        )
    queue = tmp_path / "corpus" / "0" / "queue"
    queue.mkdir(parents=True)
    queue.joinpath("id_raw_secret").write_bytes(_seed(0))
    profile = build_operation_profile(corpus_dir=tmp_path / "corpus", contract=contract)
    profile_path = tmp_path / "profile.json"
    profile_path.write_bytes(canonical_json(profile.document()))

    packet = build_packet(
        stats_dir=stats,
        contract=contract,
        state_file=tmp_path / "state.json",
        kernel_release="5.10.73",
        expected_workers=2,
        native_workers=1,
        corpus_profile_path=profile_path,
    )
    serialized = packet.model_dump_json()
    assert "evidence:fleet-corpus-operation-profile" in serialized
    assert "id_raw_secret" not in serialized
