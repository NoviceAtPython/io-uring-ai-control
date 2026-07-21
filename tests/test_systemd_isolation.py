from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_event_projector_has_no_network_or_fleet_path_authority() -> None:
    unit = (ROOT / "deploy/systemd/iou-ai-event-projector.service").read_text(
        encoding="utf-8"
    )
    assert "PrivateNetwork=true" in unit
    assert "RestrictAddressFamilies=AF_UNIX" in unit
    assert "NoNewPrivileges=true" in unit
    assert "CapabilityBoundingSet=\n" in unit
    assert "ReadWritePaths=/var/lib/iou-ai/runtime /var/lib/iou-ai/events" in unit
    for forbidden in (
        "/root/fuzzer_workspace",
        "nat_out",
        "nat_seeds",
        "iou-fleet",
        "openai.key",
        "anthropic.key",
    ):
        assert forbidden not in unit


def test_shadow_service_deadline_exceeds_three_bounded_provider_calls() -> None:
    unit = (ROOT / "deploy/systemd/iou-ai-shadow.service").read_text(encoding="utf-8")
    assert "TimeoutStartSec=25min" in unit
    # One planner request may wait up to 10 minutes; the independent reviewer
    # and sampled auditor each retain a five-minute upper bound.
    assert 600 + 300 + 300 < 25 * 60
    assert "KillSignal=SIGINT" in unit


def test_activation_does_not_enable_shadow_or_touch_production_fleet() -> None:
    script = (ROOT / "deploy/remote/activate-readonly.sh").read_text(encoding="utf-8")
    assert "iou-ai-shadow.timer" not in script
    assert "iou-ai-notify.timer" not in script
    assert "iou-ai-decision-import.timer" not in script
    for forbidden in ("systemctl stop iou-fleet", "nat_out", "nat_seeds"):
        assert forbidden not in script
    assert "iou-ai-event-projector.timer" not in script
    assert "systemctl start iou-ai-event-projector.service" not in script


def test_notifier_has_only_redacted_relay_authority() -> None:
    unit = (ROOT / "deploy/systemd/iou-ai-notify.service").read_text(
        encoding="utf-8"
    )
    assert "User=iou-ai-notify" in unit
    assert (
        "ExecStart=/opt/iou-ai/current/.venv/bin/iou-ai-notify run "
        "--events /var/lib/iou-ai/events "
        "--receipts /var/lib/iou-ai-notify/receipts "
        "--decision-inbox /var/lib/iou-ai-decisions/inbox "
        "--state-dir /var/lib/iou-ai-notify/state "
        "--endpoint-file /etc/iou-ai/relay-endpoint "
        "--token-file /run/credentials/iou-ai-notify.service/relay.token"
    ) in unit
    assert "LoadCredential=relay.token:/etc/iou-ai/credentials/relay.token" in unit
    assert "LoadCredential=relay.endpoint:" not in unit
    assert "ConditionFileNotEmpty=/etc/iou-ai/relay-endpoint" in unit
    assert "ConditionFileNotEmpty=/etc/iou-ai/credentials/relay.token" in unit
    assert "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6" in unit
    assert (
        "ReadOnlyPaths=/opt/iou-ai /etc/iou-ai/relay-endpoint "
        "/var/lib/iou-ai/events"
    ) in unit
    assert (
        "ReadWritePaths=/var/lib/iou-ai-notify/receipts "
        "/var/lib/iou-ai-notify/state /var/lib/iou-ai-decisions/inbox"
    ) in unit
    assert unit.count("ReadWritePaths=") == 1
    assert "ProtectSystem=strict" in unit
    assert "NoNewPrivileges=true" in unit
    assert "CapabilityBoundingSet=\n" in unit
    inaccessible = next(
        line for line in unit.splitlines() if line.startswith("InaccessiblePaths=")
    )
    for forbidden in (
        "/etc/iou-ai/credentials",
        "/var/lib/iou-ai-decisions/archive",
        "/var/lib/iou-ai/quarantine",
        "/var/lib/iou-ai/contracts",
        "/var/lib/iou-ai/runtime",
        "/var/lib/iou-ai/inbox",
        "/var/lib/iou-ai/lkml",
        "/var/lib/iou-ai/export",
        "/var/lib/iou-ai-canary",
        "/opt/iou-ai-canary",
    ):
        assert forbidden in inaccessible
    for forbidden in (
        "openai.key",
        "anthropic.key",
        "decision.key",
        "/root/fuzzer_workspace",
        "nat_out",
        "nat_seeds",
        "iou-fleet",
    ):
        assert forbidden not in unit


def test_decision_importer_is_offline_and_cannot_execute() -> None:
    unit = (ROOT / "deploy/systemd/iou-ai-decision-import.service").read_text(
        encoding="utf-8"
    )
    assert "User=iou-ai-decision" in unit
    assert (
        "ExecStart=/opt/iou-ai/current/.venv/bin/iou-ai-decisions "
        "--events /var/lib/iou-ai/events "
        "--inbox /var/lib/iou-ai-decisions/inbox "
        "--archive /var/lib/iou-ai-decisions/archive "
        "--key-file "
        "/run/credentials/iou-ai-decision-import.service/decision.key"
    ) in unit
    assert "PrivateNetwork=true" in unit
    assert "RestrictAddressFamilies=AF_UNIX" in unit
    assert "AF_INET" not in unit
    assert "LoadCredential=decision.key:" in unit
    assert "ConditionFileNotEmpty=/etc/iou-ai/credentials/decision.key" in unit
    assert (
        "ReadOnlyPaths=/opt/iou-ai /var/lib/iou-ai/events "
        "/var/lib/iou-ai-decisions/inbox"
    ) in unit
    assert "ReadWritePaths=/var/lib/iou-ai-decisions/archive" in unit
    assert unit.count("ReadWritePaths=") == 1
    assert "ProtectSystem=strict" in unit
    assert "NoNewPrivileges=true" in unit
    assert "CapabilityBoundingSet=\n" in unit
    inaccessible = next(
        line for line in unit.splitlines() if line.startswith("InaccessiblePaths=")
    )
    for forbidden in (
        "/etc/iou-ai/credentials",
        "/var/lib/iou-ai-notify",
        "/var/lib/iou-ai/quarantine",
        "/var/lib/iou-ai/contracts",
        "/var/lib/iou-ai/runtime",
        "/var/lib/iou-ai/inbox",
        "/var/lib/iou-ai/lkml",
        "/var/lib/iou-ai/export",
        "/var/lib/iou-ai-canary",
        "/opt/iou-ai-canary",
    ):
        assert forbidden in inaccessible
    for forbidden in (
        "openai.key",
        "anthropic.key",
        "relay.token",
        "relay.endpoint",
        "/root/fuzzer_workspace",
        "nat_out",
        "nat_seeds",
        "iou-fleet",
    ):
        assert forbidden not in unit


def test_notification_units_are_installed_but_never_enabled() -> None:
    install = (ROOT / "deploy/remote/install.sh").read_text(encoding="utf-8")
    assert "install -d -o root -g iou-ai -m 0751 /var/lib/iou-ai" in install
    for unit in (
        "iou-ai-notify.service",
        "iou-ai-notify.timer",
        "iou-ai-decision-import.service",
        "iou-ai-decision-import.timer",
    ):
        assert unit in install
    assert "/etc/iou-ai/relay-endpoint" not in install
    for credential in ("relay.token", "decision.key"):
        assert f"/dev/null /etc/iou-ai/credentials/{credential}" not in install
    assert "systemctl enable" not in install
    assert "systemctl start" not in install


def test_notification_timers_require_explicit_operator_enablement() -> None:
    for name, service in (
        ("iou-ai-notify.timer", "iou-ai-notify.service"),
        ("iou-ai-decision-import.timer", "iou-ai-decision-import.service"),
    ):
        timer = (ROOT / "deploy/systemd" / name).read_text(encoding="utf-8")
        assert f"Unit={service}" in timer
        assert "WantedBy=timers.target" in timer

    activation = (ROOT / "deploy/remote/activate-readonly.sh").read_text(
        encoding="utf-8"
    )
    assert "iou-ai-notify" not in activation
    assert "iou-ai-decision-import" not in activation


def test_auto_promote_unit_is_offline_and_killswitchable() -> None:
    # The unattended lane runs as root (isolated Nyx canary + root-owned inbox), so
    # its containment properties matter more than any other unit's. It must never
    # reach the network -- it neither calls a model nor a relay -- and the operator
    # must be able to halt autonomous promotion by creating a single file.
    unit = (ROOT / "deploy/systemd/iou-ai-auto.service").read_text(encoding="utf-8")
    assert "PrivateNetwork=true" in unit
    assert "RestrictAddressFamilies=AF_UNIX" in unit
    assert "NoNewPrivileges=true" in unit
    assert "Type=oneshot" in unit
    # ProtectHome must NOT be full-mask: the isolated canary reads its kernel
    # config through /root/fuzzer_workspace, so a masked /root breaks VM boot.
    # read-only preserves containment (no writes to home) without that breakage.
    directives = [ln.strip() for ln in unit.splitlines() if not ln.lstrip().startswith("#")]
    assert "ProtectHome=read-only" in directives
    assert "ProtectHome=true" not in directives
    # Two independent kill switches: the global paid-AI one and an auto-only one.
    assert (
        "ConditionPathExists=!/var/lib/iou-ai/runtime/AI_CALLS_DISABLED" in unit
    )
    assert (
        "ConditionPathExists=!/var/lib/iou-ai/runtime/AUTO_PROMOTE_DISABLED" in unit
    )

    timer = (ROOT / "deploy/systemd/iou-ai-auto.timer").read_text(encoding="utf-8")
    assert "Unit=iou-ai-auto.service" in timer
    assert "WantedBy=timers.target" in timer

    # Autonomous promotion must never be switched on by the read-only activation.
    activation = (ROOT / "deploy/remote/activate-readonly.sh").read_text(
        encoding="utf-8"
    )
    assert "iou-ai-auto" not in activation


def test_auto_cycle_approves_with_the_auto_signer_not_the_human_one() -> None:
    # An unattended promotion must be attributable to the auto policy in the
    # decision archive -- never recorded as though a human approved it.
    cycle = (ROOT / "deploy/remote/auto_cycle.sh").read_text(encoding="utf-8")
    assert "--auto" in cycle
    assert "iou-ai-promoter" in cycle
    assert "--processed-dir" in cycle  # bounded retries, so flaky rejects recover


def test_canary_runner_uses_only_the_isolated_snapshot() -> None:
    runner = (ROOT / "deploy/remote/nyx_canary_oneshot.sh").read_text(
        encoding="utf-8"
    )
    assert "CANARY_ROOT=/opt/iou-ai-canary/current" in runner
    assert "WORK_ROOT=/var/lib/iou-ai-canary/work" in runner
    assert "PATH=\"$NYX:$PATH\"" in runner
    for forbidden in (
        "/root/fuzzer_workspace",
        "nat_out",
        "afl-fuzz",
        "rm -rf /root",
    ):
        assert forbidden not in runner


def test_snapshot_preparation_copies_but_never_executes_the_live_toolchain() -> None:
    script = (ROOT / "deploy/remote/prepare-isolated-canary.sh").read_text(
        encoding="utf-8"
    )
    assert "SOURCE_ROOT=/root/fuzzer_workspace" in script
    assert "cp -a \"$TARGET\" \"$STAGE/targets/iou_native_kasan\"" in script
    assert "cp -a \"$RUNTIME/nyx_mode\" \"$STAGE/afl/nyx_mode\"" in script
    assert "snapshot symlink escapes its isolated root" in script
    assert "Nyx runtime root is a symlink" in script
    assert "snapshot symlink target was not copied: $relative -> $target_relative" in script
    assert "snapshot retains a dangling symlink" in script
    assert "normalize_links \"$RUNTIME/nyx_mode\" \"$STAGE/afl/nyx_mode\"" in script
    assert "assert_snapshot_links \"$STAGE/afl/nyx_mode\"" in script
    assert "afl-cmin -X" not in script
    assert "afl-fuzz" not in script
    assert "systemctl" not in script


def test_link_diagnostic_is_read_only_and_excludes_fuzzer_data() -> None:
    script = (ROOT / "deploy/remote/inspect-isolated-links.sh").read_text(
        encoding="utf-8"
    )
    assert "scope=%s status=%s path=%s target=%s" in script
    for forbidden in ("afl-cmin", "afl-fuzz", "nat_out", "systemctl", "mktemp"):
        assert forbidden not in script


def test_canary_selftest_is_single_shot_and_snapshot_only() -> None:
    script = (ROOT / "deploy/remote/run-isolated-canary-selftest.sh").read_text(
        encoding="utf-8"
    )
    assert "CANARY_ROOT=/opt/iou-ai-canary/current" in script
    assert "printf '\\000'" in script
    assert "CANARY_PER_SEED_MS=5000 CANARY_OUTER_SECONDS=90" in script
    assert '"live_fleet_modified":false' in script
    assert "execution candidate" in script
    for forbidden in (
        "/root/fuzzer_workspace",
        "nat_out",
        "afl-cmin -X",
        "afl-fuzz -",
        "systemctl",
    ):
        assert forbidden not in script
