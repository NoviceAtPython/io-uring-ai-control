"""One-shot, fail-closed planner/reviewer shadow pipeline."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime, timezone
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

from pydantic import ValidationError

from .artifacts import ArtifactError, ArtifactStore
from .budget import (
    BudgetLedger,
    PricingPolicy,
    Reservation,
    Settlement,
    usd_to_microdollars,
)
from .compiler import CompilationBlocked, compile_program
from .config import AppConfig, ProviderConfig
from .feedback import FeedbackStore, build_review_feedback
from .models import (
    HarnessContract,
    HarnessEnvironment,
    PlannerProposal,
    PromotionState,
    ProviderRole,
    ProviderTrace,
    QuarantineEnvelope,
    ReviewerVerdict,
    TelemetryPacket,
    ValidationRecord,
)
from .prompts import (
    AUDITOR_SYSTEM,
    PLANNER_INSTRUCTIONS,
    REVIEWER_SYSTEM,
    planner_input,
    reviewer_input,
)
from .providers import (
    ProviderAdapter,
    ProviderError,
    ProviderHTTPError,
    ProviderRefusalError,
    ProviderRequest,
    ProviderResult,
)
from .quarantine import QuarantineStore, canonical_json, sha256_json
from .schemas import strict_json_schema
from .validator import (
    VALIDATOR_HASH,
    VALIDATOR_VERSION,
    ValidationReport,
    require_valid,
    validate_proposal,
    validate_reviewer,
    validate_run_inputs,
)


class PipelineError(RuntimeError):
    pass


class PipelineRejected(PipelineError):
    pass


@dataclass(frozen=True, slots=True)
class RunOutcome:
    status: str
    reason: str
    envelope_digest: str | None = None
    envelope_path: Path | None = None


@dataclass(frozen=True, slots=True)
class _Call:
    result: ProviderResult
    settlement: Settlement


def _parse_date(value: str, name: str) -> date:
    try:
        return date.fromisoformat(value)
    except ValueError as exc:
        raise PipelineError(f"invalid {name} date in pricing configuration") from exc


def pricing_policy(config: ProviderConfig) -> PricingPolicy:
    return PricingPolicy(
        provider=config.name,
        model=config.model,
        version=config.pricing_version,
        effective_from=_parse_date(config.pricing_effective, "effective"),
        effective_until=_parse_date(config.pricing_expires, "expiry"),
        input_rate_microdollars_per_million=usd_to_microdollars(
            config.input_usd_per_million
        ),
        output_rate_microdollars_per_million=usd_to_microdollars(
            config.output_usd_per_million
        ),
    )


def build_ledger(config: AppConfig) -> BudgetLedger:
    providers = (
        config.planner,
        config.reviewer,
        config.auditor.provider,
        *config.planner_fallbacks,
    )
    quotas = {
        (provider.name, provider.model): provider.monthly_call_limit
        for provider in providers
    }
    return BudgetLedger(
        config.budget.database,
        hard_limit_microdollars=usd_to_microdollars(config.budget.hard_limit_usd),
        monthly_call_quotas=quotas,
        warning_thresholds_microdollars=tuple(
            usd_to_microdollars(value) for value in config.budget.warning_usd
        ),
        kill_switch_path=config.budget.kill_switch,
        daily_limit_microdollars=(
            usd_to_microdollars(config.budget.daily_limit_usd)
            if config.budget.daily_limit_usd is not None
            else None
        ),
    )


def _json_text(model: Any) -> str:
    return json.dumps(
        model.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )


def _digest_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _model_digest(model: Any) -> str:
    return _digest_bytes(canonical_json(model.model_dump(mode="json")))


def _client_id(role: str, request_key: str) -> str:
    return f"{role}-{request_key[:24]}"


def _request_key(
    role: str,
    provider: ProviderConfig,
    system_prompt: str,
    input_text: str,
    schema: Mapping[str, Any],
) -> str:
    material = canonical_json(
        {
            "role": role,
            "provider": provider.name,
            "model": provider.model,
            "pricing": provider.pricing_version,
            # Generation controls are part of the externally dispatched work.
            # Include them in the idempotency key so an explicitly changed,
            # audited timeout/effort profile is distinguishable from a hidden
            # retry of an uncertain prior request.
            "generation": {
                "max_input_tokens": provider.max_input_tokens,
                "max_output_tokens": provider.max_output_tokens,
                "reasoning_effort": provider.reasoning_effort,
                "request_timeout_seconds": provider.request_timeout_seconds,
            },
            "prompt": system_prompt,
            "input": input_text,
            "schema": schema,
        }
    )
    return hashlib.sha256(material).hexdigest()


def _principal_id(fleet_id: str) -> str:
    return "principal-" + hashlib.sha256(fleet_id.encode("utf-8")).hexdigest()[:32]


def _trace(role: ProviderRole, call: _Call) -> ProviderTrace:
    result = call.result
    if result.response_id is None:
        raise PipelineRejected("provider omitted the response identifier")
    usage = result.usage
    try:
        return ProviderTrace(
            role=role,
            provider=result.provider,
            model=result.model,
            response_id=result.response_id,
            client_request_id=result.client_request_id,
            input_tokens=usage.input_tokens if usage else 0,
            output_tokens=usage.output_tokens if usage else 0,
            reasoning_tokens=usage.reasoning_tokens if usage else 0,
            cost_microusd=call.settlement.charged_microdollars,
        )
    except ValidationError:
        # Provider metadata is untrusted too.  Fail closed without allowing a
        # Pydantic traceback to echo an invalid provider-controlled value.
        raise PipelineRejected(
            "provider trace failed strict local validation"
        ) from None


def _validation_record(report: ValidationReport) -> ValidationRecord:
    return ValidationRecord(
        validator_version=VALIDATOR_VERSION,
        validator_hash=VALIDATOR_HASH,
        passed_check_ids=list(report.passed_check_ids),
        failed_check_ids=list(report.failed_check_ids),
    )


class ShadowPipeline:
    """Coordinates model calls but has no executable promotion capability."""

    def __init__(
        self,
        config: AppConfig,
        *,
        ledger: BudgetLedger,
        planner: ProviderAdapter,
        reviewer: ProviderAdapter,
        auditor: ProviderAdapter | None = None,
        planner_fallbacks: tuple[tuple[ProviderAdapter, ProviderConfig], ...] = (),
        quarantine: QuarantineStore | None = None,
        feedback: FeedbackStore | None = None,
        artifacts: ArtifactStore | None = None,
    ) -> None:
        self.config = config
        self.ledger = ledger
        self.planner = planner
        self.reviewer = reviewer
        self.auditor = auditor
        self.planner_fallbacks = tuple(planner_fallbacks)
        self.quarantine = quarantine or QuarantineStore(
            config.runtime.quarantine_dir
        )
        self.feedback = feedback or FeedbackStore(
            config.runtime.state_dir / "review-feedback"
        )
        self.artifacts = artifacts or ArtifactStore(config.runtime.artifact_dir)

    def _call(
        self,
        *,
        role: str,
        adapter: ProviderAdapter,
        provider: ProviderConfig,
        system_prompt: str,
        input_text: str,
        schema: Mapping[str, Any],
        schema_name: str,
        principal_id: str,
    ) -> _Call:
        if len(input_text.encode("utf-8")) > self.config.runtime.max_packet_bytes:
            raise PipelineRejected("sanitized request exceeds the local byte cap")
        request_key = _request_key(role, provider, system_prompt, input_text, schema)
        reservation: Reservation = self.ledger.reserve_for_tokens(
            provider=provider.name,
            model=provider.model,
            request_key=request_key,
            max_input_tokens=provider.max_input_tokens,
            max_output_tokens=provider.max_output_tokens,
            pricing_policy=pricing_policy(provider),
            details={"role": role, "request_digest": request_key},
        )
        request = ProviderRequest(
            system_prompt=system_prompt,
            input_text=input_text,
            json_schema=schema,
            schema_name=schema_name,
            client_request_id=_client_id(role, request_key),
            principal_id=principal_id,
        )
        try:
            result = adapter.generate(request)
        except (ProviderRefusalError, ProviderHTTPError) as exc:
            # A clean, non-retryable provider decline (a safety refusal or a
            # policy 400 such as OpenAI cyber_policy) produced no billable output,
            # so settle it at zero instead of conservatively charging the full
            # reservation. Otherwise a probabilistic policy block would burn
            # budget on every attempt and starve the daily cap. Retryable HTTP
            # errors (408/409/429/5xx) may have done server-side work, so those
            # stay conservative and charge the reserve.
            if isinstance(exc, ProviderHTTPError) and exc.retryable:
                self.ledger.abandon(
                    reservation.reservation_id,
                    reason="retryable provider HTTP error with uncertain state",
                    details={"role": role},
                )
            else:
                self.ledger.settle(
                    reservation.reservation_id,
                    input_tokens=0,
                    output_tokens=0,
                    details={"role": role, "outcome": "provider_declined"},
                )
            raise
        except BaseException:
            # Dispatch state is uncertain (timeout, connection, protocol); there
            # are deliberately no retries. Conservatively charge the reserve.
            self.ledger.abandon(
                reservation.reservation_id,
                reason="provider call failed or completion state was uncertain",
                details={"role": role},
            )
            raise
        usage = result.usage
        settlement = self.ledger.settle(
            reservation.reservation_id,
            input_tokens=usage.input_tokens if usage else None,
            output_tokens=usage.output_tokens if usage else None,
            cached_input_tokens=usage.cached_input_tokens if usage else None,
            details={
                "role": role,
                "response_id": result.response_id or "missing",
                "provider_request_id": result.provider_request_id or "missing",
            },
        )
        if len(result.text.encode("utf-8")) > self.config.runtime.max_response_bytes:
            raise PipelineRejected("provider output exceeds the local byte cap")
        return _Call(result=result, settlement=settlement)

    @staticmethod
    def _parse_model(call: _Call, model: type[Any], label: str) -> Any:
        try:
            decoded = json.loads(call.result.text)
            if not isinstance(decoded, dict):
                raise TypeError("not an object")
            # JSON is the wire format. Pydantic strict mode intentionally accepts
            # JSON enum strings while refusing Python-side type coercion.
            return model.model_validate_json(call.result.text)
        except json.JSONDecodeError as exc:
            # Never include provider-controlled text, byte offsets, or decoder
            # messages in diagnostics.
            raise PipelineRejected(
                f"{label} failed strict local validation (invalid_json)"
            ) from exc
        except TypeError as exc:
            raise PipelineRejected(
                f"{label} failed strict local validation (root:not_object)"
            ) from exc
        except ValidationError as exc:
            # DEBUG AID (local file only, bounded): persist the raw rejected output
            # to the runtime working directory so a human can diagnose a schema
            # mismatch. It is inert data for inspection, never re-read as input.
            try:
                Path("last-rejected-proposal.json").write_text(
                    call.result.text[:65536], encoding="utf-8"
                )
            except OSError:
                pass
            # Report only model-declared top-level fields and Pydantic's stable
            # error categories.  Values, messages, nested provider-created keys,
            # and raw output never enter logs.
            declared_fields = set(getattr(model, "model_fields", {}))
            diagnostics: set[str] = set()
            for error in exc.errors(
                include_url=False,
                include_context=False,
                include_input=False,
            ):
                location = error.get("loc", ())
                root = location[0] if location else "root"
                if not isinstance(root, str) or root not in declared_fields:
                    root = "root"
                error_type = error.get("type", "validation_error")
                if not isinstance(error_type, str) or not error_type.replace(
                    "_", ""
                ).replace(".", "").isalnum():
                    error_type = "validation_error"
                diagnostics.add(f"{root}:{error_type}")
            detail = ",".join(sorted(diagnostics)[:8]) or "root:validation_error"
            raise PipelineRejected(
                f"{label} failed strict local validation ({detail})"
            ) from exc

    def _call_planner(
        self,
        *,
        system_prompt: str,
        input_text: str,
        schema: Mapping[str, Any],
        schema_name: str,
        principal_id: str,
    ) -> _Call:
        """Call the planner, failing over to approved fallback providers in order.

        Only a provider-side failure (policy refusal, timeout, transport, or an
        HTTP error such as OpenAI's ``cyber_policy`` 400) advances to the next
        provider; each provider applies its own policy and every downstream gate
        is unchanged. A local budget or byte-cap failure is not a provider
        decline and propagates immediately. If every provider declines, the
        cycle fails closed. Each attempt reserves and settles against its own
        provider's ledger quota; a declined attempt abandons its reservation in
        ``_call`` so it is not billed.
        """
        candidates = ((self.planner, self.config.planner), *self.planner_fallbacks)
        last_error: ProviderError | None = None
        for adapter, provider in candidates:
            try:
                return self._call(
                    role="planner",
                    adapter=adapter,
                    provider=provider,
                    system_prompt=system_prompt,
                    input_text=input_text,
                    schema=schema,
                    schema_name=schema_name,
                    principal_id=principal_id,
                )
            except ProviderError as exc:
                last_error = exc
                continue
        # Every candidate declined/failed. Re-raise the last provider error so a
        # no-fallback deployment keeps its exact original semantics (the caller's
        # error handling and the conservative timeout charge are unchanged); with
        # fallbacks configured, this is the last provider's decline. Fail closed.
        if last_error is not None:
            raise last_error
        raise PipelineRejected("no planner provider is configured")

    def run(
        self,
        telemetry: TelemetryPacket,
        contract: HarnessContract,
    ) -> RunOutcome:
        # All local authority, binding, integrity, and freshness checks happen
        # before the first budget reservation or external request.
        require_valid(
            validate_run_inputs(
                telemetry,
                contract,
                runtime_mode=self.config.runtime.mode,
            )
        )
        telemetry_text = _json_text(telemetry)
        contract_text = _json_text(contract)
        principal = _principal_id(telemetry.fleet_id)

        planner_call = self._call_planner(
            system_prompt=PLANNER_INSTRUCTIONS,
            input_text=planner_input(telemetry_text, contract_text),
            schema=strict_json_schema(PlannerProposal),
            schema_name="io_uring_fuzz_plan_v1",
            principal_id=principal,
        )
        proposal: PlannerProposal = self._parse_model(
            planner_call, PlannerProposal, "planner proposal"
        )
        proposal_report = validate_proposal(
            telemetry,
            proposal,
            contract,
            runtime_mode=self.config.runtime.mode,
        )
        require_valid(proposal_report)
        if proposal.abstain:
            return RunOutcome(status="abstained", reason=proposal.abstain_reason)

        validation_text = json.dumps(
            {
                "valid": proposal_report.valid,
                "passed_check_ids": proposal_report.passed_check_ids,
                "failed_check_ids": proposal_report.failed_check_ids,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        reviewer_call = self._call(
            role="reviewer",
            adapter=self.reviewer,
            provider=self.config.reviewer,
            system_prompt=REVIEWER_SYSTEM,
            input_text=reviewer_input(
                telemetry_text,
                contract_text,
                _json_text(proposal),
                validation_text,
            ),
            schema=strict_json_schema(ReviewerVerdict),
            schema_name="io_uring_fuzz_review_v1",
            principal_id=principal,
        )
        verdict: ReviewerVerdict = self._parse_model(
            reviewer_call, ReviewerVerdict, "reviewer verdict"
        )
        review_report = validate_reviewer(telemetry, proposal, verdict)
        # Persist only the lossy, enum/hash-only projection.  This happens
        # before the final acceptance gate so a structurally sound reject or
        # escalation can guide the next planner cycle without authorizing
        # quarantine (and without retaining reviewer prose/provider data).
        feedback_record = build_review_feedback(
            telemetry,
            proposal,
            verdict,
            review_report,
        )
        self.feedback.put(feedback_record)
        require_valid(review_report)

        traces = [
            _trace(ProviderRole.PLANNER, planner_call),
            _trace(ProviderRole.REVIEWER, reviewer_call),
        ]
        audit_verdict: ReviewerVerdict | None = None
        audit_report: ValidationReport | None = None

        proposal_digest = _model_digest(proposal)
        if (
            self.config.auditor.enabled
            and self.auditor is not None
            and int(proposal_digest.removeprefix("sha256:")[:8], 16)
            % self.config.auditor.sample_every
            == 0
        ):
            auditor_call = self._call(
                role="auditor",
                adapter=self.auditor,
                provider=self.config.auditor.provider,
                system_prompt=AUDITOR_SYSTEM,
                input_text=reviewer_input(
                    telemetry_text,
                    contract_text,
                    _json_text(proposal),
                    _json_text(verdict),
                ),
                schema=strict_json_schema(ReviewerVerdict),
                schema_name="io_uring_fuzz_audit_v1",
                principal_id=principal,
            )
            audit_verdict = self._parse_model(
                auditor_call, ReviewerVerdict, "auditor verdict"
            )
            audit_report = validate_reviewer(telemetry, proposal, audit_verdict)
            require_valid(audit_report)
            traces.append(_trace(ProviderRole.AUDITOR, auditor_call))

        compiled_artifact_hashes: list[str] = []
        if proposal.programs and contract.environment is HarnessEnvironment.PRODUCTION:
            contract_digest = _model_digest(contract)
            for program in proposal.programs:
                try:
                    compiled = compile_program(program, contract)
                    manifest_digest, _, _ = self.artifacts.put(
                        compiled,
                        proposal_digest=proposal_digest,
                        program_digest=_model_digest(program),
                        harness_contract_digest=contract_digest,
                        validator_version=VALIDATOR_VERSION,
                        validator_hash=VALIDATOR_HASH,
                        target_hashes=contract.target_hashes,
                    )
                except (CompilationBlocked, ArtifactError, OSError) as exc:
                    raise PipelineRejected(
                        "deterministic artifact compilation or storage failed"
                    ) from exc
                compiled_artifact_hashes.append(manifest_digest)

        now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        envelope = QuarantineEnvelope(
            schema_version="quarantine-envelope.v1",
            envelope_id="env-" + proposal_digest[-24:],
            created_at=now,
            promotion_state=PromotionState.QUARANTINED,
            human_approval_required=True,
            isolated_canary_required=True,
            telemetry_packet_hash=_model_digest(telemetry),
            proposal_hash=proposal_digest,
            reviewer_verdict_hash=_model_digest(verdict),
            auditor_verdict_hash=(
                _model_digest(audit_verdict) if audit_verdict is not None else None
            ),
            harness_contract_hash=_model_digest(contract),
            compiled_artifact_hashes=compiled_artifact_hashes,
            target_hashes=telemetry.target_hashes,
            proposal=proposal,
            reviewer_verdict=verdict,
            auditor_verdict=audit_verdict,
            validations=[
                _validation_record(proposal_report),
                _validation_record(review_report),
            ]
            + ([_validation_record(audit_report)] if audit_report is not None else []),
            provider_traces=traces,
        )
        digest, path = self.quarantine.put(envelope.model_dump(mode="json"))
        return RunOutcome(
            status="quarantined",
            reason=(
                "accepted proposal and any deterministic artifacts were stored "
                "in quarantine; no canary or AFL queue was modified"
            ),
            envelope_digest=digest,
            envelope_path=path,
        )


def load_inputs(
    telemetry_path: str | Path,
    contract_path: str | Path,
) -> tuple[TelemetryPacket, HarnessContract]:
    try:
        telemetry = TelemetryPacket.model_validate_json(
            Path(telemetry_path).read_text(encoding="utf-8")
        )
        contract = HarnessContract.model_validate_json(
            Path(contract_path).read_text(encoding="utf-8")
        )
    except (OSError, ValidationError) as exc:
        raise PipelineError("telemetry or harness contract is unavailable/invalid") from exc
    return telemetry, contract
