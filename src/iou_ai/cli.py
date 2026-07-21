"""Small operator CLI; all commands are shadow-only."""

from __future__ import annotations

import argparse
from dataclasses import asdict
import json
from pathlib import Path
import sys

from .budget import BudgetError, microdollars_to_usd
from .config import ConfigError, load_config, read_credential
from .pipeline import PipelineError, ShadowPipeline, build_ledger, load_inputs
from .providers import AnthropicAdapter, MockAdapter, OpenAIAdapter, ProviderError
from .triggers import TriggerError, TriggerStateStore, material_digest
from .validator import SemanticValidationError


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="iou-ai",
        description="Fail-closed io_uring AI shadow controller",
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=Path("/etc/iou-ai/config.toml"),
        help="controller TOML configuration",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("doctor", help="validate configuration and local inputs")
    subparsers.add_parser("budget-status", help="show local calendar-month ledger")
    run = subparsers.add_parser("run", help="perform one mock or external shadow run")
    run.add_argument("--telemetry", type=Path)
    run.add_argument("--contract", type=Path)
    scheduled = subparsers.add_parser(
        "run-if-needed",
        help="run only for changed meaningful evidence or a bounded refresh",
    )
    scheduled.add_argument("--telemetry", type=Path)
    scheduled.add_argument("--contract", type=Path)
    subparsers.add_parser("disable", help="create the local API-call kill switch")
    subparsers.add_parser("enable", help="remove the local API-call kill switch")
    return parser


def _status_dict(status: object) -> dict[str, object]:
    value = asdict(status)
    for name in (
        "hard_limit_microdollars",
        "charged_microdollars",
        "active_reserved_microdollars",
        "effective_spend_microdollars",
        "remaining_microdollars",
    ):
        value[name.replace("microdollars", "usd")] = str(
            microdollars_to_usd(value[name])
        )
    return value


def _adapters(config, config_path: Path):
    if config.runtime.mode == "mock":
        root = config_path.resolve().parent
        planner = MockAdapter((root / "proposal.mock.json").read_text(encoding="utf-8"))
        reviewer = MockAdapter((root / "reviewer.mock.json").read_text(encoding="utf-8"))
        return planner, reviewer, None, ()

    openai_key = read_credential(config.planner.credential_file)
    anthropic_key = read_credential(config.reviewer.credential_file)
    planner = OpenAIAdapter(
        openai_key,
        model=config.planner.model,
        max_output_tokens=config.planner.max_output_tokens,
        reasoning_effort=config.planner.reasoning_effort,
        timeout_seconds=config.planner.request_timeout_seconds,
    )
    reviewer = AnthropicAdapter(
        anthropic_key,
        model=config.reviewer.model,
        max_output_tokens=config.reviewer.max_output_tokens,
        reasoning_effort=config.reviewer.reasoning_effort,
        timeout_seconds=config.reviewer.request_timeout_seconds,
    )
    auditor = (
        AnthropicAdapter(
            anthropic_key,
            model=config.auditor.provider.model,
            max_output_tokens=config.auditor.provider.max_output_tokens,
            reasoning_effort=config.auditor.provider.reasoning_effort,
            timeout_seconds=config.auditor.provider.request_timeout_seconds,
        )
        if config.auditor.enabled
        else None
    )

    def _build(provider):
        # Each fallback reads its own configured credential (openai.key /
        # anthropic.key) and its own model/effort/limits, exactly like the primary.
        key = read_credential(provider.credential_file)
        if provider.name == "openai":
            return OpenAIAdapter(
                key,
                model=provider.model,
                max_output_tokens=provider.max_output_tokens,
                reasoning_effort=provider.reasoning_effort,
                timeout_seconds=provider.request_timeout_seconds,
            )
        return AnthropicAdapter(
            key,
            model=provider.model,
            max_output_tokens=provider.max_output_tokens,
            reasoning_effort=provider.reasoning_effort,
            timeout_seconds=provider.request_timeout_seconds,
        )

    planner_fallbacks = tuple(
        (_build(provider), provider) for provider in config.planner_fallbacks
    )
    return planner, reviewer, auditor, planner_fallbacks


def _doctor(config, config_path: Path) -> dict[str, object]:
    checks: dict[str, object] = {
        "mode": config.runtime.mode,
        "hard_budget_usd": str(config.budget.hard_limit_usd),
        "planner": config.planner.model,
        "reviewer": config.reviewer.model,
        "auditor": config.auditor.provider.model if config.auditor.enabled else "disabled",
        "compiler_enabled": False,
        "fleet_write_capability": False,
    }
    load_inputs(config.runtime.telemetry_file, config.runtime.harness_contract_file)
    checks["telemetry"] = "valid"
    checks["harness_contract"] = "valid"
    if config.runtime.mode == "shadow":
        checks["openai_credential_file"] = config.planner.credential_file.is_file()
        checks["anthropic_credential_file"] = config.reviewer.credential_file.is_file()
        if not all(
            (
                checks["openai_credential_file"],
                checks["anthropic_credential_file"],
            )
        ):
            checks["ready"] = False
            return checks
    else:
        root = config_path.resolve().parent
        checks["mock_responses"] = all(
            (root / name).is_file()
            for name in ("proposal.mock.json", "reviewer.mock.json")
        )
    checks["ready"] = True
    return checks


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        config = load_config(args.config)
        if args.command == "doctor":
            print(json.dumps(_doctor(config, args.config), indent=2, sort_keys=True))
            return 0

        ledger = build_ledger(config)
        if args.command == "budget-status":
            print(json.dumps(_status_dict(ledger.status()), indent=2, sort_keys=True))
            return 0
        if args.command == "disable":
            config.budget.kill_switch.parent.mkdir(parents=True, exist_ok=True)
            config.budget.kill_switch.touch(exist_ok=True)
            print("AI calls disabled locally")
            return 0
        if args.command == "enable":
            config.budget.kill_switch.unlink(missing_ok=True)
            print("AI calls enabled locally; the ledger and quotas still apply")
            return 0

        telemetry_path = args.telemetry or config.runtime.telemetry_file
        contract_path = args.contract or config.runtime.harness_contract_file
        telemetry, contract = load_inputs(telemetry_path, contract_path)
        trigger = None
        digest = None
        if args.command == "run-if-needed":
            trigger = TriggerStateStore(
                config.runtime.trigger_state_file,
                refresh_seconds=config.runtime.trigger_refresh_seconds,
                retry_seconds=config.runtime.trigger_retry_seconds,
            )
        if trigger is None:
            planner, reviewer, auditor, planner_fallbacks = _adapters(
                config, args.config
            )
            pipeline = ShadowPipeline(
                config,
                ledger=ledger,
                planner=planner,
                reviewer=reviewer,
                auditor=auditor,
                planner_fallbacks=planner_fallbacks,
            )
            outcome = pipeline.run(telemetry, contract)
        else:
            digest = material_digest(telemetry, contract, config=config)
            with trigger.lease():
                decision = trigger.assess(digest)
                if not decision.should_run:
                    print(
                        json.dumps(
                            {
                                "status": "skipped",
                                "reason": decision.reason,
                                "material_digest": decision.material_digest,
                                "budget": _status_dict(ledger.status()),
                            },
                            indent=2,
                            sort_keys=True,
                        )
                    )
                    return 0
                trigger.mark_attempt(digest)
                try:
                    planner, reviewer, auditor, planner_fallbacks = _adapters(
                        config, args.config
                    )
                    pipeline = ShadowPipeline(
                        config,
                        ledger=ledger,
                        planner=planner,
                        reviewer=reviewer,
                        auditor=auditor,
                        planner_fallbacks=planner_fallbacks,
                    )
                    outcome = pipeline.run(telemetry, contract)
                except BaseException:
                    trigger.mark_failed(digest)
                    raise
                trigger.mark_completed(digest)
        print(
            json.dumps(
                {
                    "status": outcome.status,
                    "reason": outcome.reason,
                    "envelope_digest": outcome.envelope_digest,
                    "envelope_path": str(outcome.envelope_path)
                    if outcome.envelope_path
                    else None,
                    "material_digest": digest,
                    "budget": _status_dict(ledger.status()),
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 0
    except (
        ConfigError,
        PipelineError,
        BudgetError,
        ProviderError,
        SemanticValidationError,
        TriggerError,
        OSError,
    ) as exc:
        print(f"blocked: {exc}", file=sys.stderr)
        return 2
