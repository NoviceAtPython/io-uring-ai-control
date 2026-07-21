"""Configuration loading with conservative, direct-provider defaults."""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from pathlib import Path
import tomllib
from typing import Any


class ConfigError(ValueError):
    """The configuration is incomplete or unsafe."""


@dataclass(frozen=True)
class BudgetConfig:
    database: Path
    hard_limit_usd: Decimal
    warning_usd: tuple[Decimal, ...]
    kill_switch: Path
    daily_limit_usd: Decimal | None = None


@dataclass(frozen=True)
class ProviderConfig:
    name: str
    endpoint: str
    model: str
    credential_file: Path
    monthly_call_limit: int
    max_input_tokens: int
    max_output_tokens: int
    input_usd_per_million: Decimal
    output_usd_per_million: Decimal
    pricing_version: str
    pricing_effective: str
    pricing_expires: str
    reasoning_effort: str = "high"
    request_timeout_seconds: int = 300

    def worst_case_usd(self) -> Decimal:
        return (
            Decimal(self.max_input_tokens) * self.input_usd_per_million
            + Decimal(self.max_output_tokens) * self.output_usd_per_million
        ) / Decimal(1_000_000)


@dataclass(frozen=True)
class AuditConfig:
    enabled: bool
    sample_every: int
    provider: ProviderConfig


@dataclass(frozen=True)
class RuntimeConfig:
    mode: str
    state_dir: Path
    quarantine_dir: Path
    artifact_dir: Path
    trigger_state_file: Path
    trigger_refresh_seconds: int
    trigger_retry_seconds: int
    telemetry_file: Path
    harness_contract_file: Path
    max_packet_bytes: int
    max_response_bytes: int


@dataclass(frozen=True)
class EventConfig:
    enabled: bool
    outbox_dir: Path
    execution_candidate_dir: Path
    projector_state_file: Path
    decision_archive_dir: Path
    decision_ttl_minutes: int


@dataclass(frozen=True)
class AppConfig:
    budget: BudgetConfig
    planner: ProviderConfig
    reviewer: ProviderConfig
    auditor: AuditConfig
    runtime: RuntimeConfig
    events: EventConfig
    # Ordered planner failover: tried in sequence only when the primary planner
    # declines (provider policy block, timeout, transport, HTTP error). Empty by
    # default; each entry is an approved (provider, model, endpoint).
    planner_fallbacks: tuple[ProviderConfig, ...] = ()


def _table(data: dict[str, Any], name: str) -> dict[str, Any]:
    value: Any = data
    for part in name.split("."):
        if not isinstance(value, dict):
            raise ConfigError(f"missing [{name}] table")
        value = value.get(part)
    if not isinstance(value, dict):
        raise ConfigError(f"missing [{name}] table")
    return value


def _required(table: dict[str, Any], name: str) -> Any:
    if name not in table:
        raise ConfigError(f"missing required setting: {name}")
    return table[name]


def _decimal(value: Any, name: str) -> Decimal:
    try:
        parsed = Decimal(str(value))
    except (InvalidOperation, ValueError) as exc:
        raise ConfigError(f"{name} must be a decimal value") from exc
    if parsed < 0:
        raise ConfigError(f"{name} must not be negative")
    return parsed


def _path(value: Any, base: Path) -> Path:
    path = Path(str(value))
    return path if path.is_absolute() else (base / path).resolve()


def _provider(data: dict[str, Any], section: str, base: Path) -> ProviderConfig:
    return _provider_table(_table(data, section), section, base)


def _provider_table(
    table: dict[str, Any], section: str, base: Path
) -> ProviderConfig:
    result = ProviderConfig(
        name=str(_required(table, "name")),
        endpoint=str(_required(table, "endpoint")),
        model=str(_required(table, "model")),
        credential_file=_path(_required(table, "credential_file"), base),
        monthly_call_limit=int(_required(table, "monthly_call_limit")),
        max_input_tokens=int(_required(table, "max_input_tokens")),
        max_output_tokens=int(_required(table, "max_output_tokens")),
        input_usd_per_million=_decimal(
            _required(table, "input_usd_per_million"),
            f"{section}.input_usd_per_million",
        ),
        output_usd_per_million=_decimal(
            _required(table, "output_usd_per_million"),
            f"{section}.output_usd_per_million",
        ),
        pricing_version=str(_required(table, "pricing_version")),
        pricing_effective=str(_required(table, "pricing_effective")),
        pricing_expires=str(_required(table, "pricing_expires")),
        reasoning_effort=str(table.get("reasoning_effort", "high")),
        request_timeout_seconds=int(table.get("request_timeout_seconds", 300)),
    )
    if result.monthly_call_limit < 0:
        raise ConfigError(f"{section}.monthly_call_limit must not be negative")
    if result.max_input_tokens <= 0 or result.max_output_tokens <= 0:
        raise ConfigError(f"{section} token limits must be positive")
    if not 60 <= result.request_timeout_seconds <= 720:
        raise ConfigError(
            f"{section}.request_timeout_seconds must be between 60 and 720"
        )
    allowed_efforts = (
        {"low", "medium", "high", "xhigh", "max"}
        if result.name == "openai"
        else {"low", "medium", "high"}
    )
    if result.reasoning_effort not in allowed_efforts:
        raise ConfigError(f"{section}.reasoning_effort is not approved")
    if not result.endpoint.startswith("https://"):
        raise ConfigError(f"{section}.endpoint must use https")
    return result


def load_config(path: str | Path) -> AppConfig:
    config_path = Path(path).resolve()
    with config_path.open("rb") as handle:
        data = tomllib.load(handle)
    base = config_path.parent

    budget_table = _table(data, "budget")
    warnings = budget_table.get("warning_usd", [])
    if not isinstance(warnings, list):
        raise ConfigError("budget.warning_usd must be a list")
    daily_raw = budget_table.get("daily_limit_usd")
    daily_limit_usd = (
        _decimal(daily_raw, "budget.daily_limit_usd") if daily_raw is not None else None
    )
    budget = BudgetConfig(
        database=_path(_required(budget_table, "database"), base),
        hard_limit_usd=_decimal(
            _required(budget_table, "hard_limit_usd"), "budget.hard_limit_usd"
        ),
        warning_usd=tuple(_decimal(v, "budget.warning_usd") for v in warnings),
        kill_switch=_path(_required(budget_table, "kill_switch"), base),
        daily_limit_usd=daily_limit_usd,
    )
    if any(value >= budget.hard_limit_usd for value in budget.warning_usd):
        raise ConfigError("budget warning thresholds must be below the hard limit")
    if budget.daily_limit_usd is not None and (
        budget.daily_limit_usd <= 0 or budget.daily_limit_usd > budget.hard_limit_usd
    ):
        raise ConfigError("budget.daily_limit_usd must be positive and <= hard limit")

    runtime_table = _table(data, "runtime")
    mode = str(_required(runtime_table, "mode"))
    if mode not in {"mock", "shadow"}:
        raise ConfigError("runtime.mode must be 'mock' or 'shadow'; live is not implemented")
    runtime = RuntimeConfig(
        mode=mode,
        state_dir=_path(_required(runtime_table, "state_dir"), base),
        quarantine_dir=_path(_required(runtime_table, "quarantine_dir"), base),
        artifact_dir=_path(
            runtime_table.get(
                "artifact_dir",
                Path(str(_required(runtime_table, "state_dir"))) / "artifacts",
            ),
            base,
        ),
        trigger_state_file=_path(
            runtime_table.get(
                "trigger_state_file",
                Path(str(_required(runtime_table, "state_dir"))) / "trigger-state.json",
            ),
            base,
        ),
        trigger_refresh_seconds=int(
            runtime_table.get("trigger_refresh_seconds", 48 * 60 * 60)
        ),
        trigger_retry_seconds=int(
            runtime_table.get("trigger_retry_seconds", 48 * 60 * 60)
        ),
        telemetry_file=_path(_required(runtime_table, "telemetry_file"), base),
        harness_contract_file=_path(
            _required(runtime_table, "harness_contract_file"), base
        ),
        max_packet_bytes=int(runtime_table.get("max_packet_bytes", 65_536)),
        max_response_bytes=int(runtime_table.get("max_response_bytes", 65_536)),
    )
    if runtime.max_packet_bytes <= 0 or runtime.max_response_bytes <= 0:
        raise ConfigError("runtime byte limits must be positive")
    if not 3600 <= runtime.trigger_refresh_seconds <= 7 * 24 * 60 * 60:
        raise ConfigError("runtime.trigger_refresh_seconds must be between 1 hour and 7 days")
    if not 900 <= runtime.trigger_retry_seconds <= 7 * 24 * 60 * 60:
        raise ConfigError("runtime.trigger_retry_seconds must be between 15 minutes and 7 days")

    events_value = data.get("events", {})
    if not isinstance(events_value, dict):
        raise ConfigError("[events] must be a table")
    events = EventConfig(
        enabled=bool(events_value.get("enabled", False)),
        outbox_dir=_path(
            events_value.get("outbox_dir", runtime.state_dir / "events"), base
        ),
        execution_candidate_dir=_path(
            events_value.get(
                "execution_candidate_dir",
                runtime.state_dir / "execution" / "candidates",
            ),
            base,
        ),
        projector_state_file=_path(
            events_value.get(
                "projector_state_file", runtime.state_dir / "event-projector-state.json"
            ),
            base,
        ),
        decision_archive_dir=_path(
            events_value.get(
                "decision_archive_dir", runtime.state_dir / "decisions"
            ),
            base,
        ),
        decision_ttl_minutes=int(events_value.get("decision_ttl_minutes", 30)),
    )
    if not 5 <= events.decision_ttl_minutes <= 2880:
        raise ConfigError("events.decision_ttl_minutes must be between 5 and 2880")

    planner = _provider(data, "planner", base)
    reviewer = _provider(data, "reviewer", base)
    audit_table = _table(data, "auditor")
    auditor = AuditConfig(
        enabled=bool(_required(audit_table, "enabled")),
        sample_every=int(_required(audit_table, "sample_every")),
        provider=_provider(data, "auditor.provider", base),
    )
    if auditor.sample_every <= 0:
        raise ConfigError("auditor.sample_every must be positive")

    if planner.model != "gpt-5.6-sol":
        raise ConfigError("planner.model must be pinned to gpt-5.6-sol for this rollout")
    if reviewer.model != "claude-sonnet-5":
        raise ConfigError("reviewer.model must be pinned to claude-sonnet-5")
    if auditor.provider.model != "claude-fable-5":
        raise ConfigError("auditor model must be pinned to claude-fable-5")
    if (planner.name, planner.endpoint) != (
        "openai",
        "https://api.openai.com/v1/responses",
    ):
        raise ConfigError("planner must use the direct official OpenAI Responses endpoint")
    for label, provider in (("reviewer", reviewer), ("auditor", auditor.provider)):
        if (provider.name, provider.endpoint) != (
            "anthropic",
            "https://api.anthropic.com/v1/messages",
        ):
            raise ConfigError(
                f"{label} must use the direct official Anthropic Messages endpoint"
            )

    # Optional ordered planner failover. Each `[[planner_fallback]]` table is a
    # full provider spec. Only an approved (provider, model, endpoint) triple is
    # accepted so failover cannot silently route to an unvetted model/endpoint.
    fallback_tables = data.get("planner_fallback", [])
    if not isinstance(fallback_tables, list):
        raise ConfigError("planner_fallback must be an array of tables")
    approved_fallbacks = {
        ("openai", "gpt-5.6-sol", "https://api.openai.com/v1/responses"),
        ("anthropic", "claude-opus-4-8", "https://api.anthropic.com/v1/messages"),
    }
    planner_fallbacks: list[ProviderConfig] = []
    for index, table in enumerate(fallback_tables):
        if not isinstance(table, dict):
            raise ConfigError("planner_fallback entries must be tables")
        provider = _provider_table(table, f"planner_fallback[{index}]", base)
        if (provider.name, provider.model, provider.endpoint) not in approved_fallbacks:
            raise ConfigError(
                f"planner_fallback[{index}] is not an approved (provider, model, endpoint)"
            )
        planner_fallbacks.append(provider)

    return AppConfig(
        budget=budget,
        planner=planner,
        reviewer=reviewer,
        auditor=auditor,
        runtime=runtime,
        events=events,
        planner_fallbacks=tuple(planner_fallbacks),
    )


def read_credential(path: Path) -> str:
    """Read a secret at call time; callers must never log the return value."""
    try:
        value = path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise ConfigError(f"credential file is unavailable: {path}") from exc
    if not value:
        raise ConfigError(f"credential file is empty: {path}")
    return value
