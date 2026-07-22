"""Crash-safe, bounded scheduling decisions for paid shadow runs.

The telemetry builder emits a fresh packet every hour, but timestamps and
execution counters alone are not reasons to spend money.  This module projects
each packet into a stable, security-relevant material digest.  A run is due
only when that digest changes, when a failed attempt's retry delay has elapsed,
or when a slow refresh interval has elapsed.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import time
from typing import Iterator, Literal

from .compiler import COMPILER_VERSION, compiler_hash
from .config import AppConfig
from .models import (
    EvidenceKind,
    HarnessContract,
    PlannerProposal,
    ReviewerVerdict,
    TelemetryPacket,
)
from .prompts import AUDITOR_SYSTEM, PLANNER_INSTRUCTIONS, REVIEWER_SYSTEM
from .quarantine import canonical_json
from .schemas import strict_json_schema
from .validator import VALIDATOR_HASH, VALIDATOR_VERSION


class TriggerError(RuntimeError):
    """The scheduling state is unavailable, invalid, or concurrently leased."""


TRIGGER_POLICY_VERSION = "meaningful-trigger.v2"
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_STATE_KEYS = {
    "schema_version",
    "last_attempt_at",
    "last_attempt_digest",
    "last_attempt_status",
    "last_success_at",
    "last_success_digest",
}
_EXTERNAL_EVIDENCE_KINDS = {
    EvidenceKind.KERNEL_PATCH,
    EvidenceKind.MAIL_THREAD,
    EvidenceKind.OUTCOME_CLASS,
    EvidenceKind.PRIOR_PROPOSAL,
    EvidenceKind.RACE_SIGNAL,
}


@dataclass(frozen=True, slots=True)
class TriggerDecision:
    should_run: bool
    material_digest: str
    reason: Literal[
        "initial",
        "material_changed",
        "periodic_refresh",
        "retry_due",
        "unchanged",
        "retry_cooldown",
    ]


def _utc(value: datetime | None = None) -> datetime:
    current = value or datetime.now(timezone.utc)
    if current.tzinfo is None:
        raise TriggerError("trigger time must be timezone-aware")
    return current.astimezone(timezone.utc)


def _timestamp(value: datetime) -> str:
    return _utc(value).isoformat().replace("+00:00", "Z")


def _parse_timestamp(value: object, field: str) -> datetime | None:
    if value is None:
        return None
    if not isinstance(value, str) or len(value) > 35:
        raise TriggerError(f"trigger state {field} is invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise TriggerError(f"trigger state {field} is invalid") from exc
    if parsed.tzinfo is None:
        raise TriggerError(f"trigger state {field} is invalid")
    return parsed.astimezone(timezone.utc)


def _digest(payload: object) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(payload)).hexdigest()


def meaningful_material(
    telemetry: TelemetryPacket,
    contract: HarnessContract,
    *,
    config: AppConfig | None = None,
) -> dict[str, object]:
    """Return the bounded material that is allowed to trigger paid calls.

    Volatile timestamps, raw execution totals, throughput jitter, and packet
    identifiers are intentionally excluded.  New public kernel-mail evidence,
    target drift, fleet-health transitions, non-normal outcomes, and prior
    proposal results are retained.
    """

    external_evidence = sorted(
        (
            {
                "evidence_ref": item.evidence_ref,
                "kind": item.kind.value,
                "summary": item.summary,
            }
            for item in telemetry.evidence
            if item.kind in _EXTERNAL_EVIDENCE_KINDS
        ),
        key=lambda item: (item["kind"], item["evidence_ref"]),
    )
    non_normal_outcomes = sorted(
        (
            {
                "outcome_class": item.outcome_class,
                "count": item.count,
                "reproducible_count": item.reproducible_count,
            }
            for item in telemetry.outcome_classes
            if item.outcome_class != "normal_completion"
        ),
        key=lambda item: item["outcome_class"],
    )
    # Routine coverage growth is deliberately NOT a trigger. On fresh kernel code
    # the fuzzer finds new edges/paths constantly, so keying on "found a new edge"
    # made every run fire and burned the monthly call quota in ~a day, on evidence
    # with nothing new to target. Only a NOVEL outcome (an anomaly / potential bug)
    # per lane remains -- new paths and instability jitter are excluded. Coverage
    # plateaus are still handled, but only by the slow periodic refresh, not as an
    # instant trigger. New kernel-mail patches, target drift, crashes, and fleet
    # transitions remain instant triggers (below), which is what "quick to the
    # chase" actually needs.
    lane_states = sorted(
        (
            {
                "lane": item.lane.value,
                "has_novel_outcome": item.novel_outcomes_in_window > 0,
            }
            for item in telemetry.lane_summaries
        ),
        key=lambda item: item["lane"],
    )
    software_authority = {
        "compiler_version": COMPILER_VERSION,
        "compiler_hash": compiler_hash(),
        "contract_digest": _digest(contract.model_dump(mode="json")),
        "planner_prompt_digest": _digest(PLANNER_INSTRUCTIONS),
        "reviewer_prompt_digest": _digest(REVIEWER_SYSTEM),
        "auditor_prompt_digest": _digest(AUDITOR_SYSTEM),
        "proposal_schema_digest": _digest(strict_json_schema(PlannerProposal)),
        "review_schema_digest": _digest(strict_json_schema(ReviewerVerdict)),
        "validator_hash": VALIDATOR_HASH,
        "validator_version": VALIDATOR_VERSION,
    }
    provider_authority: dict[str, object] | None = None
    if config is not None:
        provider_authority = {
            "planner": {
                "provider": config.planner.name,
                "model": config.planner.model,
                "reasoning_effort": config.planner.reasoning_effort,
                "max_input_tokens": config.planner.max_input_tokens,
                "max_output_tokens": config.planner.max_output_tokens,
            },
            "reviewer": {
                "provider": config.reviewer.name,
                "model": config.reviewer.model,
                "reasoning_effort": config.reviewer.reasoning_effort,
                "max_input_tokens": config.reviewer.max_input_tokens,
                "max_output_tokens": config.reviewer.max_output_tokens,
            },
            "auditor": {
                "enabled": config.auditor.enabled,
                "sample_every": config.auditor.sample_every,
                "provider": config.auditor.provider.name,
                "model": config.auditor.provider.model,
                "reasoning_effort": config.auditor.provider.reasoning_effort,
            },
        }
    return {
        "schema_version": TRIGGER_POLICY_VERSION,
        "campaign_id": telemetry.campaign_id,
        "fleet_id": telemetry.fleet_id,
        "kernel_release": telemetry.kernel_release,
        "target_hashes": telemetry.target_hashes.model_dump(mode="json"),
        "fleet_health": {
            "workers_expected": telemetry.fleet.workers_expected,
            "workers_running": telemetry.fleet.workers_running,
            "workers_stalled": telemetry.fleet.workers_stalled,
        },
        # NOTE: routine coverage growth (edges/paths new in window) is intentionally
        # omitted here -- see the lane_states comment above. It is not a trigger.
        "lane_states": lane_states,
        "non_normal_outcomes": non_normal_outcomes,
        "external_evidence": external_evidence,
        # Reviewer feedback is deliberately available to the next periodic or
        # externally-triggered run, but is not itself a trigger.  Otherwise
        # every run would write feedback that immediately schedules another.
        "software_authority": software_authority,
        "provider_authority": provider_authority,
    }


def material_digest(
    telemetry: TelemetryPacket,
    contract: HarnessContract,
    *,
    config: AppConfig | None = None,
) -> str:
    return _digest(meaningful_material(telemetry, contract, config=config))


class TriggerStateStore:
    """Atomic scheduling state with a single-host exclusive lease."""

    def __init__(
        self,
        path: str | Path,
        *,
        refresh_seconds: int,
        retry_seconds: int,
        lease_seconds: int = 30 * 60,
    ) -> None:
        self.path = Path(path)
        self.lock_path = self.path.with_name(self.path.name + ".lock")
        if refresh_seconds < 3600:
            raise TriggerError("refresh interval must be at least one hour")
        if retry_seconds < 900:
            raise TriggerError("retry interval must be at least fifteen minutes")
        if lease_seconds < 60:
            raise TriggerError("lease interval must be at least one minute")
        self.refresh = timedelta(seconds=refresh_seconds)
        self.retry = timedelta(seconds=retry_seconds)
        self.lease_seconds = lease_seconds
        self._leased = False

    @contextmanager
    def lease(self) -> Iterator["TriggerStateStore"]:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        for attempt in range(2):
            try:
                descriptor = os.open(
                    self.lock_path,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                    0o600,
                )
            except FileExistsError as exc:
                try:
                    age = time.time() - self.lock_path.stat().st_mtime
                except OSError:
                    age = 0
                if attempt == 0 and age > self.lease_seconds:
                    try:
                        self.lock_path.unlink()
                    except OSError:
                        pass
                    continue
                raise TriggerError("another scheduling run holds the trigger lease") from exc
            else:
                with os.fdopen(descriptor, "w", encoding="ascii") as handle:
                    handle.write(str(os.getpid()))
                    handle.flush()
                    os.fsync(handle.fileno())
                break
        else:  # pragma: no cover - loop either succeeds or raises
            raise TriggerError("unable to acquire trigger lease")
        self._leased = True
        try:
            yield self
        finally:
            self._leased = False
            try:
                self.lock_path.unlink()
            except FileNotFoundError:
                pass

    def _require_lease(self) -> None:
        if not self._leased:
            raise TriggerError("trigger state mutation requires an active lease")

    def _read(self) -> dict[str, object]:
        try:
            raw = self.path.read_bytes()
        except FileNotFoundError:
            return {
                "schema_version": "trigger-state.v1",
                "last_attempt_at": None,
                "last_attempt_digest": None,
                "last_attempt_status": None,
                "last_success_at": None,
                "last_success_digest": None,
            }
        except OSError as exc:
            raise TriggerError("trigger state is unavailable") from exc
        if len(raw) > 4096:
            raise TriggerError("trigger state is oversized")
        try:
            state = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise TriggerError("trigger state is invalid") from exc
        if not isinstance(state, dict) or set(state) != _STATE_KEYS:
            raise TriggerError("trigger state shape is invalid")
        if state["schema_version"] != "trigger-state.v1":
            raise TriggerError("trigger state version is invalid")
        for name in ("last_attempt_digest", "last_success_digest"):
            value = state[name]
            if value is not None and (
                not isinstance(value, str) or _DIGEST_RE.fullmatch(value) is None
            ):
                raise TriggerError(f"trigger state {name} is invalid")
        if state["last_attempt_status"] not in {None, "running", "failed", "completed"}:
            raise TriggerError("trigger state last_attempt_status is invalid")
        _parse_timestamp(state["last_attempt_at"], "last_attempt_at")
        _parse_timestamp(state["last_success_at"], "last_success_at")
        if canonical_json(state) != raw:
            raise TriggerError("trigger state is not canonical")
        return state

    def _write(self, state: dict[str, object]) -> None:
        self._require_lease()
        payload = canonical_json(state)
        temporary = self.path.with_name(
            f".{self.path.name}.{os.getpid()}.tmp"
        )
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self.path)
        except BaseException:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
            raise

    def assess(
        self,
        digest: str,
        *,
        now: datetime | None = None,
    ) -> TriggerDecision:
        self._require_lease()
        if _DIGEST_RE.fullmatch(digest) is None:
            raise TriggerError("material digest is invalid")
        current = _utc(now)
        state = self._read()
        success_at = _parse_timestamp(state["last_success_at"], "last_success_at")
        attempt_at = _parse_timestamp(state["last_attempt_at"], "last_attempt_at")
        same_failed_attempt_in_cooldown = (
            state["last_attempt_digest"] == digest
            and state["last_attempt_status"] in {"running", "failed"}
            and attempt_at is not None
            and current - attempt_at < self.retry
            and (success_at is None or attempt_at >= success_at)
        )
        if same_failed_attempt_in_cooldown:
            return TriggerDecision(False, digest, "retry_cooldown")
        if success_at is None:
            if attempt_at is None:
                reason = "initial"
            elif state["last_attempt_digest"] == digest:
                reason = "retry_due"
            else:
                reason = "material_changed"
            return TriggerDecision(True, digest, reason)
        if state["last_success_digest"] != digest:
            return TriggerDecision(True, digest, "material_changed")
        if current - success_at >= self.refresh:
            return TriggerDecision(True, digest, "periodic_refresh")
        return TriggerDecision(False, digest, "unchanged")

    def mark_attempt(self, digest: str, *, now: datetime | None = None) -> None:
        state = self._read()
        state.update(
            {
                "last_attempt_at": _timestamp(_utc(now)),
                "last_attempt_digest": digest,
                "last_attempt_status": "running",
            }
        )
        self._write(state)

    def mark_failed(self, digest: str, *, now: datetime | None = None) -> None:
        state = self._read()
        state.update(
            {
                "last_attempt_at": _timestamp(_utc(now)),
                "last_attempt_digest": digest,
                "last_attempt_status": "failed",
            }
        )
        self._write(state)

    def mark_completed(self, digest: str, *, now: datetime | None = None) -> None:
        timestamp = _timestamp(_utc(now))
        state = self._read()
        state.update(
            {
                "last_attempt_at": timestamp,
                "last_attempt_digest": digest,
                "last_attempt_status": "completed",
                "last_success_at": timestamp,
                "last_success_digest": digest,
            }
        )
        self._write(state)


__all__ = [
    "TRIGGER_POLICY_VERSION",
    "TriggerDecision",
    "TriggerError",
    "TriggerStateStore",
    "material_digest",
    "meaningful_material",
]
