"""Deterministic semantic gates between model output and quarantine."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
from typing import Iterable

from .compiler import status as compiler_status
from .models import (
    ArgumentValueKind,
    FindingSeverity,
    HarnessArgumentKind,
    HarnessContract,
    HarnessEnvironment,
    LaneKind,
    LinkMode,
    PlannerProposal,
    ResidualRisk,
    ReviewerVerdict,
    TelemetryPacket,
    VerdictKind,
)
from .quarantine import canonical_json


VALIDATOR_VERSION = "semantic-validator.v4"
VALIDATOR_HASH = "sha256:" + hashlib.sha256(
    b"io-uring-ai-control semantic-validator.v4"
).hexdigest()


@dataclass(frozen=True, slots=True)
class ValidationIssue:
    check_id: str
    message: str


@dataclass(frozen=True, slots=True)
class ValidationReport:
    passed_check_ids: tuple[str, ...]
    issues: tuple[ValidationIssue, ...]

    @property
    def valid(self) -> bool:
        return not self.issues

    @property
    def failed_check_ids(self) -> tuple[str, ...]:
        return tuple(issue.check_id for issue in self.issues)


class SemanticValidationError(ValueError):
    def __init__(self, report: ValidationReport) -> None:
        self.report = report
        summary = "; ".join(
            f"{issue.check_id}: {issue.message}" for issue in report.issues
        )
        super().__init__(summary or "semantic validation failed")


class _Checks:
    def __init__(self) -> None:
        self.passed: list[str] = []
        self.issues: list[ValidationIssue] = []

    def require(self, check_id: str, condition: bool, message: str) -> None:
        if condition:
            if check_id not in self.passed:
                self.passed.append(check_id)
        else:
            self.issues.append(ValidationIssue(check_id, message))

    def report(self) -> ValidationReport:
        return ValidationReport(tuple(self.passed), tuple(self.issues))


def _symbols(items: Iterable[object], field: str) -> dict[str, object]:
    return {str(getattr(item, field)): item for item in items}


def _integer_argument(step: object, name: str) -> int | None:
    for argument in getattr(step, "arguments", ()):
        if argument.name == name and argument.kind is ArgumentValueKind.INTEGER:
            return argument.integer_value
    return None


def validate_run_inputs(
    telemetry: TelemetryPacket,
    contract: HarnessContract,
    *,
    runtime_mode: str,
    now: datetime | None = None,
) -> ValidationReport:
    """Fail before a provider reservation when local authority is unsuitable."""

    checks = _Checks()
    packet_data = telemetry.model_dump(mode="json")
    claimed_packet_hash = packet_data.pop("packet_hash")
    computed_packet_hash = "sha256:" + hashlib.sha256(
        canonical_json(packet_data)
    ).hexdigest()
    checks.require(
        "preflight.packet-hash",
        claimed_packet_hash == computed_packet_hash,
        "telemetry packet hash does not match its canonical contents",
    )
    checks.require(
        "preflight.target-hashes",
        telemetry.target_hashes == contract.target_hashes,
        "telemetry and harness target hashes differ",
    )
    checks.require(
        "preflight.contract-mode",
        (runtime_mode == "mock" and contract.environment in {HarnessEnvironment.MOCK, HarnessEnvironment.TEST})
        or (
            runtime_mode == "shadow"
            and contract.environment is HarnessEnvironment.PRODUCTION
            and not contract.test_only
        ),
        "harness contract is not authorized for this runtime mode",
    )
    checks.require(
        "preflight.planner-view",
        bool(contract.verified),
        "semantic planner view has not been independently verified",
    )
    if (
        contract.environment is HarnessEnvironment.PRODUCTION
        and contract.deterministic_compiler
    ):
        bound_compiler = compiler_status(contract)
        checks.require(
            "preflight.compiler-authority",
            bound_compiler.enabled,
            "production contract is not bound to this exact compiler and codec",
        )
    if runtime_mode == "shadow":
        current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        generated = datetime.fromisoformat(
            telemetry.generated_at.replace("Z", "+00:00")
        ).astimezone(timezone.utc)
        checks.require(
            "preflight.telemetry-freshness",
            current - timedelta(hours=2) <= generated <= current + timedelta(minutes=5),
            "telemetry is stale or implausibly future-dated",
        )
    return checks.report()


def validate_proposal(
    telemetry: TelemetryPacket,
    proposal: PlannerProposal,
    contract: HarnessContract,
    *,
    runtime_mode: str,
) -> ValidationReport:
    checks = _Checks()
    checks.require(
        "binding.packet-id",
        proposal.packet_id == telemetry.packet_id,
        "proposal packet_id does not match telemetry",
    )
    checks.require(
        "binding.target-hashes",
        proposal.target_hashes == telemetry.target_hashes == contract.target_hashes,
        "telemetry, proposal, and harness target hashes differ",
    )
    checks.require(
        "contract.mode",
        (runtime_mode == "mock" and contract.environment in {HarnessEnvironment.MOCK, HarnessEnvironment.TEST})
        or (
            runtime_mode == "shadow"
            and contract.environment is HarnessEnvironment.PRODUCTION
            and not contract.test_only
        ),
        "mock/test contract cannot authorize an external shadow run",
    )
    checks.require(
        "contract.planner-view",
        bool(contract.verified),
        "semantic harness planner view is not independently verified",
    )

    evidence_refs = {item.evidence_ref for item in telemetry.evidence}
    cited_refs = set(proposal.hypothesis.evidence_refs)
    cited_refs.update(
        evidence_ref
        for priority in proposal.research_priorities
        for evidence_ref in priority.evidence_refs
    )
    checks.require(
        "evidence.references",
        cited_refs.issubset(evidence_refs),
        "proposal cites evidence absent from telemetry",
    )

    if proposal.abstain:
        checks.require(
            "proposal.abstention",
            not proposal.analysis_only
            and not proposal.research_priorities
            and not proposal.programs,
            "abstaining proposal contains analysis or programs",
        )
        return checks.report()

    profiles = _symbols(contract.profiles, "profile_id")
    operations = _symbols(contract.operations, "symbol")
    flags = _symbols(contract.flags, "symbol")
    resource_specs = _symbols(contract.resources, "resource_kind")

    if proposal.analysis_only:
        checks.require(
            "analysis.priority-count",
            bool(proposal.research_priorities) and not proposal.programs,
            "analysis-only proposal must contain priorities and no programs",
        )
        for priority in proposal.research_priorities:
            prefix = f"analysis.{priority.priority_id}"
            selected_profiles = [profiles.get(name) for name in priority.ring_profile_ids]
            checks.require(
                f"{prefix}.operations",
                set(priority.operation_families).issubset(set(operations)),
                "research priority references an unknown operation family",
            )
            checks.require(
                f"{prefix}.profiles",
                all(profile is not None for profile in selected_profiles)
                and not set(priority.ring_profile_ids)
                & set(contract.forbidden_profile_ids),
                "research priority references an unknown or forbidden profile",
            )
            checks.require(
                f"{prefix}.lanes",
                all(
                    profile is not None
                    and set(priority.preferred_lanes).issubset(set(profile.allowed_lanes))
                    for profile in selected_profiles
                ),
                "research priority lane is not allowed by every selected profile",
            )
        return checks.report()

    checks.require(
        "contract.program-gate",
        contract.deterministic_compiler
        and contract.decode_round_trip_verified
        and (
            contract.environment is not HarnessEnvironment.PRODUCTION
            or compiler_status(contract).enabled
        ),
        "program proposals require a deterministic compiler and verified decoder round trip",
    )
    total_variants = sum(program.requested_local_variants for program in proposal.programs)
    checks.require(
        "proposal.variant-bound",
        total_variants <= 64,
        "proposal asks for more than 64 deterministic local variants",
    )

    for program in proposal.programs:
        prefix = f"program.{program.program_id}"
        profile = profiles.get(program.ring_profile_id)
        checks.require(
            f"{prefix}.profile",
            profile is not None
            and program.ring_profile_id not in contract.forbidden_profile_ids,
            "unknown or forbidden ring profile",
        )
        if profile is not None:
            checks.require(
                f"{prefix}.profile-lane",
                program.lane in profile.allowed_lanes,
                "program lane is not allowed by ring profile",
            )

        bindings = {binding.resource_ref: binding for binding in program.resources}
        resources_valid = True
        resource_totals: dict[str, int] = {}
        for binding in program.resources:
            spec = resource_specs.get(binding.resource_kind)
            if spec is None or binding.quantity > spec.max_instances:
                resources_valid = False
            resource_totals[binding.resource_kind] = (
                resource_totals.get(binding.resource_kind, 0) + binding.quantity
            )
        for kind, quantity in resource_totals.items():
            spec = resource_specs.get(kind)
            if spec is None or quantity > spec.max_instances:
                resources_valid = False
        checks.require(
            f"{prefix}.resources",
            resources_valid,
            "resource declaration is unknown or exceeds harness maximum",
        )
        checks.require(
            f"{prefix}.step-count",
            len(program.steps) <= contract.operation_max_count,
            "program exceeds harness operation maximum",
        )

        for step in program.steps:
            step_prefix = f"{prefix}.step.{step.step_id}"
            checks.require(
                f"{step_prefix}.ring-ref",
                step.ring_ref == program.ring_profile_id,
                "step ring_ref differs from its program ring profile",
            )
            operation = operations.get(step.operation)
            checks.require(
                f"{step_prefix}.operation",
                operation is not None,
                "unknown harness operation",
            )
            if operation is None:
                continue
            checks.require(
                f"{step_prefix}.profile",
                program.ring_profile_id in operation.allowed_profiles,
                "operation is not permitted for this profile",
            )
            checks.require(
                f"{step_prefix}.lane",
                program.lane in operation.allowed_lanes,
                "operation is not permitted in this lane",
            )
            checks.require(
                f"{step_prefix}.flags",
                set(step.flags).issubset(set(operation.allowed_flags))
                and set(step.flags).issubset(set(flags)),
                "step contains an unknown or disallowed flag",
            )
            link_flags = {
                "iosqe_io_link",
                "iosqe_io_hardlink",
                "iosqe_io_drain",
            }
            selected_link_flags = set(step.flags) & link_flags
            expected_link_flags = {
                LinkMode.NONE: set(),
                LinkMode.LINK: {"iosqe_io_link"},
                LinkMode.HARD_LINK: {"iosqe_io_hardlink"},
                LinkMode.DRAIN: {"iosqe_io_drain"},
            }[step.link_mode]
            checks.require(
                f"{step_prefix}.link-mode",
                selected_link_flags == expected_link_flags,
                "link_mode conflicts with the selected SQE link flags",
            )
            checks.require(
                f"{step_prefix}.outcomes",
                set(step.expected_result_classes).issubset(
                    set(operation.expected_result_classes)
                ),
                "step expects a result class absent from the harness contract",
            )

            proposed_arguments = {argument.name: argument for argument in step.arguments}
            expected_arguments = {argument.name: argument for argument in operation.arguments}
            args_valid = set(proposed_arguments) == set(expected_arguments)
            for name, proposed in proposed_arguments.items():
                expected = expected_arguments.get(name)
                if expected is None:
                    args_valid = False
                    continue
                if expected.kind is HarnessArgumentKind.INTEGER:
                    args_valid &= proposed.kind is ArgumentValueKind.INTEGER
                    args_valid &= expected.minimum_value <= proposed.integer_value <= expected.maximum_value
                elif expected.kind is HarnessArgumentKind.BOOLEAN:
                    args_valid &= proposed.kind is ArgumentValueKind.BOOLEAN
                elif expected.kind is HarnessArgumentKind.ENUM:
                    args_valid &= proposed.kind is ArgumentValueKind.SYMBOL
                    args_valid &= proposed.symbol_value in expected.enum_symbols
                elif expected.kind is HarnessArgumentKind.RESOURCE:
                    args_valid &= proposed.kind is ArgumentValueKind.RESOURCE
                    binding = bindings.get(proposed.resource_ref)
                    args_valid &= binding is not None and binding.resource_kind == expected.resource_kind
            checks.require(
                f"{step_prefix}.arguments",
                bool(args_valid),
                "operation arguments do not exactly match the typed harness contract",
            )

        if contract.environment is HarnessEnvironment.PRODUCTION:
            # Variant expansion is intentionally a separate future compiler.
            # The first production compiler accepts exactly the reviewed base
            # program so no unreviewed mutation can enter an artifact.
            checks.require(
                f"{prefix}.native.base-only",
                program.requested_local_variants == 1 and not program.perturbations,
                "production v1 accepts one reviewed base program and no perturbations",
            )
            checks.require(
                f"{prefix}.native.no-fixed-file",
                all("iosqe_fixed_file" not in step.flags for step in program.steps),
                "the current harness writes real descriptors before SQE fixed-file interpretation",
            )

            for ordinal, step in enumerate(program.steps):
                step_prefix = f"{prefix}.step.{step.step_id}"
                if step.link_mode in {LinkMode.LINK, LinkMode.HARD_LINK}:
                    checks.require(
                        f"{step_prefix}.native.link-successor",
                        ordinal + 1 < len(program.steps),
                        "a linked request must have a following request",
                    )
                if step.link_mode is LinkMode.DRAIN:
                    checks.require(
                        f"{step_prefix}.native.drain-predecessor",
                        ordinal > 0,
                        "a drain request must have prior work to drain",
                    )
                if step.operation == "link_timeout":
                    checks.require(
                        f"{step_prefix}.native.link-timeout-predecessor",
                        ordinal > 0
                        and program.steps[ordinal - 1].link_mode
                        in {LinkMode.LINK, LinkMode.HARD_LINK},
                        "link_timeout must immediately follow a linked request",
                    )

                prior = program.steps[:ordinal]
                prior_operations = {item.operation for item in prior}
                prior_selectors = {
                    operations[item.operation].selector_modulus_value
                    for item in prior
                    if item.operation in operations
                }
                reference_requirements = {
                    "timeout_remove": ("user_data", "timeout", 8),
                    "timeout_update": ("user_data", "timeout", 8),
                    "poll_remove": ("user_data", "poll_add", 6),
                    "poll_update": ("old_user_data", "poll_add", 6),
                }
                requirement = reference_requirements.get(step.operation)
                if requirement is not None:
                    argument_name, producer, expected_value = requirement
                    checks.require(
                        f"{step_prefix}.native.reference",
                        producer in prior_operations
                        and _integer_argument(step, argument_name) == expected_value,
                        "request reference does not match a prior canonical producer",
                    )
                if step.operation == "cancel":
                    checks.require(
                        f"{step_prefix}.native.cancel-reference",
                        bool(prior_selectors)
                        and _integer_argument(step, "user_data") in prior_selectors,
                        "cancel user_data must name a prior canonical operation selector",
                    )

                if "iosqe_buffer_select" in step.flags:
                    control = sum(
                        int(getattr(flags.get(flag), "bit_value", 0))
                        for flag in step.flags
                    )
                    buffer_group = control >> 4
                    provider_exists = any(
                        item.operation == "provide_buffers"
                        and _integer_argument(item, "buffer_group") == buffer_group
                        for item in prior
                    )
                    checks.require(
                        f"{step_prefix}.native.buffer-provider",
                        provider_exists,
                        "buffer selection requires a prior matching provide_buffers step",
                    )
                if step.operation == "remove_buffers":
                    group = _integer_argument(step, "buffer_group")
                    checks.require(
                        f"{step_prefix}.native.buffer-remove",
                        any(
                            item.operation == "provide_buffers"
                            and _integer_argument(item, "buffer_group") == group
                            for item in prior
                        ),
                        "remove_buffers requires a prior matching provider",
                    )

            if program.ring_profile_id == "disabled_until_register":
                first = program.steps[0]
                checks.require(
                    f"{prefix}.native.enable-ring",
                    first.operation == "register_raw"
                    and (
                        _integer_argument(first, "register_opcode") is not None
                        and _integer_argument(first, "register_opcode") % 34 == 12
                    ),
                    "the disabled ring must begin with IORING_REGISTER_ENABLE_RINGS",
                )

    return checks.report()


def validate_reviewer(
    telemetry: TelemetryPacket,
    proposal: PlannerProposal,
    verdict: ReviewerVerdict,
) -> ValidationReport:
    checks = _Checks()
    checks.require(
        "review.binding",
        verdict.packet_id == telemetry.packet_id
        and verdict.proposal_id == proposal.proposal_id,
        "review is not bound to this packet and proposal",
    )
    evidence_refs = {item.evidence_ref for item in telemetry.evidence}
    review_refs = set(verdict.checked_evidence_refs)
    finding_refs = {
        ref for finding in verdict.findings for ref in finding.evidence_refs
    }
    proposal_refs = set(proposal.hypothesis.evidence_refs)
    proposal_refs.update(
        evidence_ref
        for priority in proposal.research_priorities
        for evidence_ref in priority.evidence_refs
    )
    checks.require(
        "review.evidence",
        review_refs.issubset(evidence_refs)
        and finding_refs.issubset(evidence_refs)
        and finding_refs.issubset(review_refs)
        and proposal_refs.issubset(review_refs),
        "review omits proposal evidence or cites evidence absent from telemetry",
    )
    program_steps = {
        program.program_id: {step.step_id for step in program.steps}
        for program in proposal.programs
    }
    finding_targets_valid = True
    for finding in verdict.findings:
        if finding.program_id:
            if finding.program_id not in program_steps:
                finding_targets_valid = False
            elif finding.step_id and finding.step_id not in program_steps[finding.program_id]:
                finding_targets_valid = False
        elif finding.step_id:
            finding_targets_valid = False
    checks.require(
        "review.finding-targets",
        finding_targets_valid,
        "review finding references an unknown program or step",
    )
    severe = {FindingSeverity.CRITICAL, FindingSeverity.HIGH}
    checks.require(
        "review.acceptance",
        verdict.verdict is VerdictKind.ACCEPT
        and verdict.safe_for_quarantine
        and verdict.residual_risk in {ResidualRisk.LOW, ResidualRisk.MEDIUM}
        and not any(finding.severity in severe for finding in verdict.findings),
        "independent reviewer did not accept with bounded residual risk and no severe findings",
    )
    return checks.report()


def require_valid(report: ValidationReport) -> ValidationReport:
    if not report.valid:
        raise SemanticValidationError(report)
    return report
