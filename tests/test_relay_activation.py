from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_relay_activation_is_root_only_no_fleet_and_no_shadow_path() -> None:
    script = (ROOT / "deploy/remote/activate-relay.sh").read_text(encoding="utf-8")

    assert 'if [ "$(id -u)" -ne 0 ]; then' in script
    assert "iou-ai-shadow" not in script
    for forbidden in (
        "iou-fleet",
        "/root/fuzzer_workspace",
        "nat_out",
        "nat_seeds",
        "afl-fuzz",
        "qemu-system",
    ):
        assert forbidden not in script


def test_relay_activation_installs_least_privilege_files_only_after_probe() -> None:
    script = (ROOT / "deploy/remote/activate-relay.sh").read_text(encoding="utf-8")

    assert (
        'for name in relay-endpoint relay.token decision.key telegram-bot.token '
        'telegram-chat.id; do'
    ) in script
    assert 'install -o root -g iou-ai-notify -m 0640' in script
    assert '"$STAGING/relay-endpoint" "$ENDPOINT_NEW"' in script
    assert script.count('install -o root -g root -m 0600') >= 4
    assert '"$STAGING/relay.token" "$TOKEN_NEW"' in script
    assert '"$STAGING/decision.key" "$DECISION_NEW"' in script
    assert '"$STAGING/telegram-bot.token" "$TELEGRAM_TOKEN_NEW"' in script
    assert '"$STAGING/telegram-chat.id" "$TELEGRAM_CHAT_NEW"' in script
    assert '"$NOTIFY" probe' in script
    assert '--decision-key-file "$STAGING/decision.key"' in script
    assert 'GET /v1/ready' in script
    assert script.index('"$NOTIFY" probe') < script.index("systemctl enable $TIMER_UNITS")


def test_relay_activation_requires_a_clean_disabled_timer_set_and_rolls_back() -> None:
    script = (ROOT / "deploy/remote/activate-relay.sh").read_text(encoding="utf-8")

    for unit in (
        "iou-ai-event-projector.timer",
        "iou-ai-notify.timer",
        "iou-ai-decision-import.timer",
    ):
        assert unit in script
    assert 'systemctl is-enabled --quiet "$unit" || systemctl is-active --quiet "$unit"' in script
    assert "refusing to replace existing relay configuration" in script
    assert "systemctl disable $TIMER_UNITS" in script
    assert "systemctl disable --now $TIMER_UNITS" in script
    assert "COMMITTED=1" in script


def test_telegram_setup_is_root_only_and_never_enables_or_touches_the_fleet() -> None:
    script = (ROOT / "deploy/remote/configure-telegram-relay.sh").read_text(
        encoding="utf-8"
    )

    assert 'if [ "$(id -u)" -ne 0 ]; then' in script
    assert "telegram-pair" in script
    assert '"$NOTIFY" telegram-webhook' not in script
    assert '"$NOTIFY" probe' in script
    assert "systemctl enable" not in script
    assert "systemctl start" not in script
    assert "iou-ai-shadow" not in script
    for forbidden in (
        "iou-fleet",
        "/root/fuzzer_workspace",
        "nat_out",
        "nat_seeds",
        "afl-fuzz",
        "qemu-system",
    ):
        assert forbidden not in script
