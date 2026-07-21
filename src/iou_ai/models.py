"""Strict, versioned data contracts for the io_uring AI control plane.

The provider-facing models deliberately contain semantic symbols only.  They do
not expose fields for executable bytes, source code, shell commands, filesystem
paths, credentials, or raw fuzzer logs.  Deterministic local code is responsible
for validating and compiling an accepted proposal against a verified harness
contract.
"""

from __future__ import annotations

from enum import Enum
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


Identifier = Annotated[
    str,
    Field(min_length=1, max_length=96, pattern=r"^[a-z0-9][a-z0-9._:-]*$"),
]
ProviderResponseId = Annotated[
    str,
    # OpenAI and Anthropic response identifiers are opaque provider values.
    # Anthropic legitimately uses mixed-case base62 material after ``msg_``.
    Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]*$"),
]
Symbol = Annotated[
    str,
    Field(min_length=1, max_length=80, pattern=r"^[a-z][a-z0-9_]*$"),
]
Digest = Annotated[str, Field(pattern=r"^sha256:[0-9a-f]{64}$")]
Timestamp = Annotated[
    str,
    Field(
        min_length=20,
        max_length=35,
        pattern=r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})$",
    ),
]
ShortText = Annotated[str, Field(min_length=1, max_length=240)]
SummaryText = Annotated[str, Field(min_length=1, max_length=800)]
EvidenceRef = Annotated[
    str,
    Field(min_length=1, max_length=96, pattern=r"^evidence:[a-z0-9][a-z0-9._:-]*$"),
]
NonNegativeInt = Annotated[int, Field(ge=0)]
PositiveInt = Annotated[int, Field(ge=1)]
PartsPerMillion = Annotated[int, Field(ge=0, le=1_000_000)]


_FORBIDDEN_TEXT_FRAGMENTS = (
    "-----begin private key-----",
    "authorization: bearer",
    "x-api-key:",
    "api_key=",
    "password=",
    "passwd=",
    "ssh-rsa ",
    "ssh-ed25519 ",
    "#!/bin/",
    "powershell -",
    "sh -c ",
    "bash -c ",
)


def _validate_sanitized_text(value: str) -> str:
    """Reject multiline/control/executable-looking text at the contract edge."""

    if value != value.strip():
        raise ValueError("text must not have leading or trailing whitespace")
    if "\n" in value or "\r" in value or "\x00" in value:
        raise ValueError("text must be a single sanitized line")
    lowered = value.casefold()
    if any(fragment in lowered for fragment in _FORBIDDEN_TEXT_FRAGMENTS):
        raise ValueError("text contains forbidden credential or command material")
    return value


class StrictModel(BaseModel):
    """Base for all wire contracts; coercion and undeclared fields fail closed."""

    model_config = ConfigDict(
        extra="forbid",
        strict=True,
        frozen=True,
        validate_assignment=True,
        use_enum_values=False,
    )


class LaneKind(str, Enum):
    STABLE_COVERAGE = "stable_coverage"
    PROBABILISTIC_RACE = "probabilistic_race"


class EvidenceKind(str, Enum):
    COVERAGE_DELTA = "coverage_delta"
    CORPUS_SHAPE = "corpus_shape"
    OUTCOME_CLASS = "outcome_class"
    RACE_SIGNAL = "race_signal"
    STALL_SIGNAL = "stall_signal"
    PRIOR_PROPOSAL = "prior_proposal"
    KERNEL_PATCH = "kernel_patch"
    MAIL_THREAD = "mail_thread"


class OutcomeKind(str, Enum):
    NO_CHANGE = "no_change"
    COVERAGE_GAIN = "coverage_gain"
    NOVEL_OUTCOME = "novel_outcome"
    UNSTABLE = "unstable"
    REJECTED = "rejected"
    NOT_RUN = "not_run"


class ArgumentValueKind(str, Enum):
    INTEGER = "integer"
    BOOLEAN = "boolean"
    SYMBOL = "symbol"
    RESOURCE = "resource"


class LinkMode(str, Enum):
    NONE = "none"
    LINK = "link"
    HARD_LINK = "hard_link"
    DRAIN = "drain"


class VerdictKind(str, Enum):
    ACCEPT = "accept"
    REJECT = "reject"
    ESCALATE = "escalate"


class FindingSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingCategory(str, Enum):
    SEMANTIC = "semantic"
    SAFETY = "safety"
    HARNESS_MISMATCH = "harness_mismatch"
    EVIDENCE_GAP = "evidence_gap"
    PRIVACY = "privacy"
    DETERMINISM = "determinism"
    BUDGET = "budget"
    SCOPE = "scope"


class ResidualRisk(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class HarnessEnvironment(str, Enum):
    PRODUCTION = "production"
    MOCK = "mock"
    TEST = "test"


class HarnessArgumentKind(str, Enum):
    INTEGER = "integer"
    BOOLEAN = "boolean"
    ENUM = "enum"
    RESOURCE = "resource"


class ByteOrder(str, Enum):
    LITTLE = "little"
    BIG = "big"
    NOT_APPLICABLE = "not_applicable"


class ResourceLifetime(str, Enum):
    PROGRAM = "program"
    STEP = "step"


class PromotionState(str, Enum):
    QUARANTINED = "quarantined"


class ProviderRole(str, Enum):
    PLANNER = "planner"
    REVIEWER = "reviewer"
    AUDITOR = "auditor"


class ExternalizationPolicy(StrictModel):
    redaction_version: Identifier
    sanitized_for_external_api: Literal[True]
    contains_raw_logs: Literal[False]
    contains_seed_bytes: Literal[False]
    contains_source_code: Literal[False]
    contains_filesystem_paths: Literal[False]
    contains_usernames: Literal[False]
    contains_credentials: Literal[False]
    contains_crash_traces: Literal[False]


class TargetHashes(StrictModel):
    harness_hash: Digest
    compiler_hash: Digest
    op_table_hash: Digest
    fleet_config_hash: Digest


class TelemetryWindow(StrictModel):
    start_at: Timestamp
    end_at: Timestamp
    duration_seconds: PositiveInt


class FleetSummary(StrictModel):
    workers_expected: PositiveInt
    workers_running: NonNegativeInt
    workers_stalled: NonNegativeInt
    executions_total: NonNegativeInt
    executions_per_second_milli: NonNegativeInt
    queue_entries: NonNegativeInt
    favored_entries: NonNegativeInt
    pending_entries: NonNegativeInt

    @model_validator(mode="after")
    def workers_are_bounded(self) -> "FleetSummary":
        if self.workers_running + self.workers_stalled > self.workers_expected:
            raise ValueError("running plus stalled workers exceeds expected workers")
        if self.favored_entries > self.queue_entries:
            raise ValueError("favored entries exceeds queue entries")
        if self.pending_entries > self.queue_entries:
            raise ValueError("pending entries exceeds queue entries")
        return self


class CoverageSummary(StrictModel):
    paths_total: NonNegativeInt
    paths_new_in_window: NonNegativeInt
    edges_total: NonNegativeInt
    edges_new_in_window: NonNegativeInt
    bitmap_density_ppm: PartsPerMillion
    corpus_bytes_total: NonNegativeInt
    corpus_entry_bytes_p50: NonNegativeInt
    corpus_entry_bytes_p95: NonNegativeInt


class OutcomeClassSummary(StrictModel):
    outcome_class: Symbol
    count: NonNegativeInt
    reproducible_count: NonNegativeInt

    @model_validator(mode="after")
    def reproducible_is_subset(self) -> "OutcomeClassSummary":
        if self.reproducible_count > self.count:
            raise ValueError("reproducible_count exceeds count")
        return self


class LaneSummary(StrictModel):
    lane: LaneKind
    workers_running: NonNegativeInt
    executions_total: NonNegativeInt
    executions_per_second_milli: NonNegativeInt
    queue_entries: NonNegativeInt
    paths_new_in_window: NonNegativeInt
    novel_outcomes_in_window: NonNegativeInt
    timeout_count: NonNegativeInt
    instability_ppm: PartsPerMillion


class EvidenceSummary(StrictModel):
    evidence_ref: EvidenceRef
    kind: EvidenceKind
    summary: SummaryText
    observation_count: PositiveInt

    _sanitize_summary = field_validator("summary")(_validate_sanitized_text)


class PriorProposalOutcome(StrictModel):
    proposal_id: Identifier
    outcome: OutcomeKind
    executions: NonNegativeInt
    paths_gained: NonNegativeInt
    novel_outcomes: NonNegativeInt
    summary: ShortText

    _sanitize_summary = field_validator("summary")(_validate_sanitized_text)


class TelemetryPacket(StrictModel):
    """Bounded, redacted aggregate packet safe to send to model providers."""

    schema_version: Literal["telemetry.v1"]
    packet_id: Identifier
    packet_hash: Digest
    generated_at: Timestamp
    fleet_id: Identifier
    campaign_id: Identifier
    kernel_release: Annotated[str, Field(min_length=1, max_length=80)]
    target_hashes: TargetHashes
    window: TelemetryWindow
    fleet: FleetSummary
    coverage: CoverageSummary
    lane_summaries: Annotated[list[LaneSummary], Field(min_length=2, max_length=2)]
    outcome_classes: Annotated[list[OutcomeClassSummary], Field(max_length=24)]
    evidence: Annotated[list[EvidenceSummary], Field(max_length=24)]
    prior_proposal_outcomes: Annotated[list[PriorProposalOutcome], Field(max_length=12)]
    externalization: ExternalizationPolicy

    _sanitize_kernel = field_validator("kernel_release")(_validate_sanitized_text)

    @model_validator(mode="after")
    def require_one_summary_per_lane(self) -> "TelemetryPacket":
        lanes = [item.lane for item in self.lane_summaries]
        if set(lanes) != {LaneKind.STABLE_COVERAGE, LaneKind.PROBABILISTIC_RACE}:
            raise ValueError("lane_summaries must contain each lane exactly once")
        if len(lanes) != len(set(lanes)):
            raise ValueError("lane_summaries contains duplicate lanes")
        refs = [item.evidence_ref for item in self.evidence]
        if len(refs) != len(set(refs)):
            raise ValueError("evidence_ref values must be unique")
        return self


class Hypothesis(StrictModel):
    claim: SummaryText
    evidence_refs: Annotated[list[EvidenceRef], Field(min_length=1, max_length=16)]
    expected_signal: ShortText

    _sanitize_claim = field_validator("claim")(_validate_sanitized_text)
    _sanitize_signal = field_validator("expected_signal")(_validate_sanitized_text)


class ResearchPriority(StrictModel):
    """Unordered Gate-A research direction; never an executable program."""

    priority_id: Symbol
    rationale: SummaryText
    evidence_refs: Annotated[list[EvidenceRef], Field(min_length=1, max_length=12)]
    operation_families: Annotated[list[Symbol], Field(min_length=1, max_length=16)]
    ring_profile_ids: Annotated[list[Symbol], Field(min_length=1, max_length=8)]
    preferred_lanes: Annotated[list[LaneKind], Field(min_length=1, max_length=2)]
    expected_signal: ShortText
    safety_notes: Annotated[list[ShortText], Field(max_length=8)]

    _sanitize_rationale = field_validator("rationale")(_validate_sanitized_text)
    _sanitize_signal = field_validator("expected_signal")(_validate_sanitized_text)

    @field_validator("safety_notes")
    @classmethod
    def sanitize_safety_notes(cls, values: list[str]) -> list[str]:
        return [_validate_sanitized_text(value) for value in values]

    @model_validator(mode="after")
    def require_unique_references(self) -> "ResearchPriority":
        for values, label in (
            (self.evidence_refs, "evidence_refs"),
            (self.operation_families, "operation_families"),
            (self.ring_profile_ids, "ring_profile_ids"),
            (self.preferred_lanes, "preferred_lanes"),
        ):
            if len(values) != len(set(values)):
                raise ValueError(f"research priority {label} must be unique")
        return self


class SymbolicArgument(StrictModel):
    """Typed argument with explicit sentinel fields for provider schema stability.

    Exactly one value field is semantically active according to ``kind``.  Unused
    string fields must be empty and unused scalar fields must be zero/false.  This
    avoids nullable unions while keeping the provider schema fully required.
    """

    name: Symbol
    kind: ArgumentValueKind
    integer_value: int
    boolean_value: bool
    symbol_value: Annotated[str, Field(max_length=80, pattern=r"^(?:|[a-z][a-z0-9_]*)$")]
    resource_ref: Annotated[str, Field(max_length=80, pattern=r"^(?:|[a-z][a-z0-9_]*)$")]

    @model_validator(mode="after")
    def enforce_active_value(self) -> "SymbolicArgument":
        if self.kind is ArgumentValueKind.INTEGER:
            if self.boolean_value or self.symbol_value or self.resource_ref:
                raise ValueError("integer argument has non-empty inactive values")
        elif self.kind is ArgumentValueKind.BOOLEAN:
            if self.integer_value != 0 or self.symbol_value or self.resource_ref:
                raise ValueError("boolean argument has non-empty inactive values")
        elif self.kind is ArgumentValueKind.SYMBOL:
            if not self.symbol_value:
                raise ValueError("symbol argument requires symbol_value")
            if self.integer_value != 0 or self.boolean_value or self.resource_ref:
                raise ValueError("symbol argument has non-empty inactive values")
        elif self.kind is ArgumentValueKind.RESOURCE:
            if not self.resource_ref:
                raise ValueError("resource argument requires resource_ref")
            if self.integer_value != 0 or self.boolean_value or self.symbol_value:
                raise ValueError("resource argument has non-empty inactive values")
        return self


class ResourceBinding(StrictModel):
    resource_ref: Symbol
    resource_kind: Symbol
    quantity: Annotated[int, Field(ge=1, le=64)]


class SymbolicStep(StrictModel):
    step_id: Symbol
    ordinal: Annotated[int, Field(ge=0, le=63)]
    operation: Symbol
    ring_ref: Symbol
    arguments: Annotated[list[SymbolicArgument], Field(max_length=16)]
    flags: Annotated[list[Symbol], Field(max_length=16)]
    link_mode: LinkMode
    expected_result_classes: Annotated[list[Symbol], Field(min_length=1, max_length=8)]

    @model_validator(mode="after")
    def require_unique_argument_and_flag_names(self) -> "SymbolicStep":
        names = [argument.name for argument in self.arguments]
        if len(names) != len(set(names)):
            raise ValueError("step argument names must be unique")
        if len(self.flags) != len(set(self.flags)):
            raise ValueError("step flags must be unique")
        return self


class Perturbation(StrictModel):
    kind: Symbol
    target_step_id: Symbol
    magnitude: Annotated[int, Field(ge=0, le=1_000_000)]
    rationale: ShortText

    _sanitize_rationale = field_validator("rationale")(_validate_sanitized_text)


class PlannerProgram(StrictModel):
    program_id: Symbol
    objective: SummaryText
    lane: LaneKind
    ring_profile_id: Symbol
    resources: Annotated[list[ResourceBinding], Field(max_length=16)]
    steps: Annotated[list[SymbolicStep], Field(min_length=1, max_length=64)]
    perturbations: Annotated[list[Perturbation], Field(max_length=8)]
    requested_local_variants: Annotated[int, Field(ge=1, le=32)]
    expected_signals: Annotated[list[ShortText], Field(min_length=1, max_length=8)]
    safety_notes: Annotated[list[ShortText], Field(max_length=8)]

    _sanitize_objective = field_validator("objective")(_validate_sanitized_text)

    @field_validator("expected_signals", "safety_notes")
    @classmethod
    def sanitize_text_lists(cls, values: list[str]) -> list[str]:
        return [_validate_sanitized_text(value) for value in values]

    @model_validator(mode="after")
    def enforce_program_references(self) -> "PlannerProgram":
        resource_refs = [resource.resource_ref for resource in self.resources]
        if len(resource_refs) != len(set(resource_refs)):
            raise ValueError("resource_ref values must be unique within a program")
        step_ids = [step.step_id for step in self.steps]
        if len(step_ids) != len(set(step_ids)):
            raise ValueError("step_id values must be unique within a program")
        if [step.ordinal for step in self.steps] != list(range(len(self.steps))):
            raise ValueError("step ordinals must be contiguous and start at zero")
        known_resources = set(resource_refs)
        for step in self.steps:
            for argument in step.arguments:
                if (
                    argument.kind is ArgumentValueKind.RESOURCE
                    and argument.resource_ref not in known_resources
                ):
                    raise ValueError(
                        f"step references undeclared resource {argument.resource_ref!r}"
                    )
        known_steps = set(step_ids)
        for perturbation in self.perturbations:
            if perturbation.target_step_id not in known_steps:
                raise ValueError(
                    f"perturbation references unknown step {perturbation.target_step_id!r}"
                )
        return self


class PlannerProposal(StrictModel):
    """Model-produced semantic IR; never an executable or directly importable seed."""

    schema_version: Literal["planner-proposal.v1"]
    proposal_id: Identifier
    packet_id: Identifier
    target_hashes: TargetHashes
    hypothesis: Hypothesis
    abstain: bool
    abstain_reason: Annotated[str, Field(max_length=400)]
    analysis_only: bool
    research_priorities: Annotated[list[ResearchPriority], Field(max_length=8)]
    programs: Annotated[list[PlannerProgram], Field(max_length=4)]

    _sanitize_abstain_reason = field_validator("abstain_reason")(
        lambda value: _validate_sanitized_text(value) if value else value
    )

    @model_validator(mode="after")
    def enforce_abstention_shape(self) -> "PlannerProposal":
        if self.abstain:
            if self.analysis_only or self.programs or self.research_priorities:
                raise ValueError(
                    "abstaining proposal must contain no analysis or programs"
                )
            if not self.abstain_reason:
                raise ValueError("abstaining proposal requires abstain_reason")
        elif self.analysis_only:
            if self.programs:
                raise ValueError("analysis-only proposal must contain no programs")
            if not self.research_priorities:
                raise ValueError("analysis-only proposal requires research priorities")
            if self.abstain_reason:
                raise ValueError("non-abstaining proposal must use an empty abstain_reason")
        else:
            if not self.programs:
                raise ValueError("non-abstaining proposal requires at least one program")
            if self.research_priorities:
                raise ValueError("program proposal cannot contain research priorities")
            if self.abstain_reason:
                raise ValueError("non-abstaining proposal must use an empty abstain_reason")
        priority_ids = [priority.priority_id for priority in self.research_priorities]
        if len(priority_ids) != len(set(priority_ids)):
            raise ValueError("priority_id values must be unique")
        program_ids = [program.program_id for program in self.programs]
        if len(program_ids) != len(set(program_ids)):
            raise ValueError("program_id values must be unique")
        return self


class ReviewFinding(StrictModel):
    finding_id: Identifier
    severity: FindingSeverity
    category: FindingCategory
    message: SummaryText
    evidence_refs: Annotated[list[EvidenceRef], Field(max_length=12)]
    program_id: Annotated[str, Field(max_length=80, pattern=r"^(?:|[a-z][a-z0-9_]*)$")]
    step_id: Annotated[str, Field(max_length=80, pattern=r"^(?:|[a-z][a-z0-9_]*)$")]

    _sanitize_message = field_validator("message")(_validate_sanitized_text)


class ReviewerVerdict(StrictModel):
    schema_version: Literal["reviewer-verdict.v1"]
    review_id: Identifier
    proposal_id: Identifier
    packet_id: Identifier
    verdict: VerdictKind
    summary: SummaryText
    findings: Annotated[list[ReviewFinding], Field(max_length=32)]
    checked_evidence_refs: Annotated[list[EvidenceRef], Field(max_length=24)]
    required_changes: Annotated[list[ShortText], Field(max_length=16)]
    residual_risk: ResidualRisk
    safe_for_quarantine: bool

    _sanitize_summary = field_validator("summary")(_validate_sanitized_text)

    @field_validator("required_changes")
    @classmethod
    def sanitize_required_changes(cls, values: list[str]) -> list[str]:
        return [_validate_sanitized_text(value) for value in values]

    @model_validator(mode="after")
    def enforce_verdict_semantics(self) -> "ReviewerVerdict":
        if self.verdict is VerdictKind.ACCEPT:
            severe = {
                FindingSeverity.CRITICAL,
                FindingSeverity.HIGH,
            }
            if any(finding.severity in severe for finding in self.findings):
                raise ValueError("accept verdict cannot contain critical or high findings")
            if not self.safe_for_quarantine:
                raise ValueError("accept verdict must explicitly be safe_for_quarantine")
            if self.required_changes:
                raise ValueError("accept verdict cannot require changes")
        elif self.safe_for_quarantine:
            raise ValueError("reject or escalate verdict cannot be safe_for_quarantine")
        return self


class HarnessArgumentSpec(StrictModel):
    name: Symbol
    kind: HarnessArgumentKind
    byte_width: Annotated[int, Field(ge=0, le=8)]
    signed: bool
    byte_order: ByteOrder
    minimum_value: int
    maximum_value: int
    enum_symbols: Annotated[list[Symbol], Field(max_length=64)]
    resource_kind: Annotated[str, Field(max_length=80, pattern=r"^(?:|[a-z][a-z0-9_]*)$")]
    summary: ShortText

    _sanitize_summary = field_validator("summary")(_validate_sanitized_text)

    @model_validator(mode="after")
    def enforce_argument_shape(self) -> "HarnessArgumentSpec":
        if self.minimum_value > self.maximum_value:
            raise ValueError("minimum_value exceeds maximum_value")
        if self.kind is HarnessArgumentKind.ENUM:
            if not self.enum_symbols:
                raise ValueError("enum argument requires enum_symbols")
            if self.resource_kind:
                raise ValueError("enum argument cannot name a resource_kind")
        elif self.kind is HarnessArgumentKind.RESOURCE:
            if not self.resource_kind:
                raise ValueError("resource argument requires resource_kind")
            if self.enum_symbols:
                raise ValueError("resource argument cannot have enum_symbols")
        elif self.enum_symbols or self.resource_kind:
            raise ValueError("integer/boolean arguments cannot have enum or resource metadata")
        if self.byte_width == 0 and self.byte_order is not ByteOrder.NOT_APPLICABLE:
            raise ValueError("zero-width argument must use not_applicable byte order")
        if self.byte_width > 0 and self.byte_order is ByteOrder.NOT_APPLICABLE:
            raise ValueError("encoded argument must declare byte order")
        return self


class HarnessProfile(StrictModel):
    profile_id: Symbol
    selector_value: Annotated[int, Field(ge=0, le=255)]
    setup_flags: Annotated[list[Symbol], Field(max_length=16)]
    allowed_lanes: Annotated[list[LaneKind], Field(min_length=1, max_length=2)]
    summary: ShortText

    _sanitize_summary = field_validator("summary")(_validate_sanitized_text)


class HarnessResourceSpec(StrictModel):
    resource_kind: Symbol
    lifetime: ResourceLifetime
    max_instances: Annotated[int, Field(ge=1, le=64)]
    summary: ShortText

    _sanitize_summary = field_validator("summary")(_validate_sanitized_text)


class HarnessFlagSpec(StrictModel):
    symbol: Symbol
    bit_value: Annotated[int, Field(ge=1, le=4_294_967_295)]
    summary: ShortText

    _sanitize_summary = field_validator("summary")(_validate_sanitized_text)


class HarnessOperation(StrictModel):
    symbol: Symbol
    selector_modulus_value: Annotated[int, Field(ge=0, le=255)]
    arguments: Annotated[list[HarnessArgumentSpec], Field(max_length=16)]
    allowed_flags: Annotated[list[Symbol], Field(max_length=16)]
    allowed_profiles: Annotated[list[Symbol], Field(min_length=1, max_length=16)]
    allowed_lanes: Annotated[list[LaneKind], Field(min_length=1, max_length=2)]
    expected_result_classes: Annotated[list[Symbol], Field(min_length=1, max_length=16)]
    summary: ShortText

    _sanitize_summary = field_validator("summary")(_validate_sanitized_text)


class HarnessContract(StrictModel):
    """Machine-readable contract extracted from and verified against deployed code."""

    schema_version: Literal["harness-contract.v1"]
    contract_id: Identifier
    generated_at: Timestamp
    environment: HarnessEnvironment
    # ``verified`` authorizes a hash-bound semantic planner view only.  Byte
    # emission remains a separate gate controlled by the two compiler fields.
    verified: bool
    test_only: bool
    verified_by: Identifier
    verification_evidence_hash: Digest
    source_revision_hash: Digest
    target_hashes: TargetHashes
    input_max_bytes: Annotated[int, Field(ge=1, le=1_048_576)]
    operation_max_count: Annotated[int, Field(ge=1, le=4096)]
    operation_selector_modulus: Annotated[int, Field(ge=1, le=256)]
    deterministic_compiler: bool
    decode_round_trip_verified: bool
    profiles: Annotated[list[HarnessProfile], Field(min_length=1, max_length=16)]
    resources: Annotated[list[HarnessResourceSpec], Field(max_length=32)]
    flags: Annotated[list[HarnessFlagSpec], Field(max_length=64)]
    operations: Annotated[list[HarnessOperation], Field(min_length=1, max_length=256)]
    forbidden_profile_ids: Annotated[list[Symbol], Field(max_length=16)]
    notes: Annotated[list[ShortText], Field(max_length=16)]

    @field_validator("notes")
    @classmethod
    def sanitize_notes(cls, values: list[str]) -> list[str]:
        return [_validate_sanitized_text(value) for value in values]

    @model_validator(mode="after")
    def enforce_contract_references(self) -> "HarnessContract":
        if self.environment is HarnessEnvironment.PRODUCTION and self.test_only:
            raise ValueError("production harness contract cannot be test_only")
        if self.environment is not HarnessEnvironment.PRODUCTION and not self.test_only:
            raise ValueError("mock/test harness contract must be test_only")
        # The inert byte codec may be round-trip verified before the separate
        # provider-program compiler is authorized. Program validation still
        # requires both gates; neither field alone permits byte emission.
        profiles = [profile.profile_id for profile in self.profiles]
        if len(profiles) != len(set(profiles)):
            raise ValueError("profile_id values must be unique")
        selectors = [profile.selector_value for profile in self.profiles]
        if len(selectors) != len(set(selectors)):
            raise ValueError("profile selector values must be unique")
        resources = [resource.resource_kind for resource in self.resources]
        if len(resources) != len(set(resources)):
            raise ValueError("resource_kind values must be unique")
        flags = [flag.symbol for flag in self.flags]
        if len(flags) != len(set(flags)):
            raise ValueError("flag symbols must be unique")
        operations = [operation.symbol for operation in self.operations]
        if len(operations) != len(set(operations)):
            raise ValueError("operation symbols must be unique")
        op_selectors = [operation.selector_modulus_value for operation in self.operations]
        if len(op_selectors) != len(set(op_selectors)):
            raise ValueError("operation selector values must be unique")
        if any(value >= self.operation_selector_modulus for value in op_selectors):
            raise ValueError("operation selector exceeds selector modulus")

        known_profiles = set(profiles)
        known_resources = set(resources)
        known_flags = set(flags)
        for operation in self.operations:
            if not set(operation.allowed_profiles).issubset(known_profiles):
                raise ValueError(f"operation {operation.symbol!r} references unknown profile")
            if not set(operation.allowed_flags).issubset(known_flags):
                raise ValueError(f"operation {operation.symbol!r} references unknown flag")
            for argument in operation.arguments:
                if (
                    argument.kind is HarnessArgumentKind.RESOURCE
                    and argument.resource_kind not in known_resources
                ):
                    raise ValueError(
                        f"operation {operation.symbol!r} references unknown resource kind"
                    )
        if set(self.forbidden_profile_ids) & known_profiles:
            raise ValueError("forbidden profiles cannot also be enabled profiles")
        return self


class ValidationRecord(StrictModel):
    validator_version: Identifier
    validator_hash: Digest
    # A complete production proposal can legitimately cross-check every
    # operation-specific safety rule (72 at the current contract size). Keep a
    # finite bound, but make it consistent with the 128-check deterministic
    # validation report so a valid local review cannot crash envelope creation.
    passed_check_ids: Annotated[list[Identifier], Field(min_length=1, max_length=128)]
    failed_check_ids: Annotated[list[Identifier], Field(max_length=64)]


class ProviderTrace(StrictModel):
    role: ProviderRole
    provider: Symbol
    model: Identifier
    response_id: ProviderResponseId
    client_request_id: Identifier
    input_tokens: NonNegativeInt
    output_tokens: NonNegativeInt
    reasoning_tokens: NonNegativeInt
    cost_microusd: NonNegativeInt


class QuarantineEnvelope(StrictModel):
    """Immutable, hash-bound handoff; it does not itself authorize execution."""

    schema_version: Literal["quarantine-envelope.v1"]
    envelope_id: Identifier
    created_at: Timestamp
    promotion_state: Literal[PromotionState.QUARANTINED]
    human_approval_required: Literal[True]
    isolated_canary_required: Literal[True]
    telemetry_packet_hash: Digest
    proposal_hash: Digest
    reviewer_verdict_hash: Digest
    auditor_verdict_hash: Digest | None
    harness_contract_hash: Digest
    compiled_artifact_hashes: Annotated[list[Digest], Field(max_length=128)]
    target_hashes: TargetHashes
    proposal: PlannerProposal
    reviewer_verdict: ReviewerVerdict
    auditor_verdict: ReviewerVerdict | None
    validations: Annotated[list[ValidationRecord], Field(min_length=1, max_length=16)]
    provider_traces: Annotated[list[ProviderTrace], Field(min_length=2, max_length=3)]

    @model_validator(mode="after")
    def bind_related_artifacts(self) -> "QuarantineEnvelope":
        if self.proposal.proposal_id != self.reviewer_verdict.proposal_id:
            raise ValueError("reviewer verdict is not bound to proposal_id")
        if self.proposal.packet_id != self.reviewer_verdict.packet_id:
            raise ValueError("reviewer verdict is not bound to packet_id")
        if self.proposal.target_hashes != self.target_hashes:
            raise ValueError("proposal target hashes differ from envelope target hashes")
        if self.reviewer_verdict.verdict is not VerdictKind.ACCEPT:
            raise ValueError("only accepted proposals can enter quarantine")
        if self.auditor_verdict is not None:
            if self.auditor_verdict.proposal_id != self.proposal.proposal_id:
                raise ValueError("auditor verdict is not bound to proposal_id")
            if self.auditor_verdict.packet_id != self.proposal.packet_id:
                raise ValueError("auditor verdict is not bound to packet_id")
            if self.auditor_verdict.verdict is not VerdictKind.ACCEPT:
                raise ValueError("sampled auditor did not accept the proposal")
            if self.auditor_verdict_hash is None:
                raise ValueError("auditor verdict hash is missing")
        elif self.auditor_verdict_hash is not None:
            raise ValueError("auditor verdict hash exists without a verdict")
        if any(record.failed_check_ids for record in self.validations):
            raise ValueError("quarantine envelope cannot contain failed validation checks")
        roles = [trace.role for trace in self.provider_traces]
        if len(roles) != len(set(roles)):
            raise ValueError("provider trace roles must be unique")
        if ProviderRole.PLANNER not in roles or ProviderRole.REVIEWER not in roles:
            raise ValueError("planner and reviewer provider traces are required")
        if (ProviderRole.AUDITOR in roles) != (self.auditor_verdict is not None):
            raise ValueError("auditor trace and verdict must appear together")
        return self


__all__ = [
    "ArgumentValueKind",
    "ByteOrder",
    "CoverageSummary",
    "Digest",
    "EvidenceKind",
    "EvidenceSummary",
    "ExternalizationPolicy",
    "FindingCategory",
    "FindingSeverity",
    "FleetSummary",
    "HarnessArgumentKind",
    "HarnessArgumentSpec",
    "HarnessContract",
    "HarnessEnvironment",
    "HarnessFlagSpec",
    "HarnessOperation",
    "HarnessProfile",
    "HarnessResourceSpec",
    "Hypothesis",
    "LaneKind",
    "LaneSummary",
    "LinkMode",
    "OutcomeClassSummary",
    "OutcomeKind",
    "PlannerProgram",
    "PlannerProposal",
    "PriorProposalOutcome",
    "PromotionState",
    "ProviderRole",
    "ProviderTrace",
    "QuarantineEnvelope",
    "ResearchPriority",
    "ResidualRisk",
    "ResourceBinding",
    "ResourceLifetime",
    "ReviewFinding",
    "ReviewerVerdict",
    "StrictModel",
    "SymbolicArgument",
    "SymbolicStep",
    "TargetHashes",
    "TelemetryPacket",
    "TelemetryWindow",
    "ValidationRecord",
    "VerdictKind",
]
