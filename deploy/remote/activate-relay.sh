#!/bin/sh
set -eu

# One-time activation for the redacted notification/decision path.  It has no
# authority over the fuzzing fleet: it installs only relay configuration and
# starts only the three notification timers after a no-write remote probe.
if [ "$(id -u)" -ne 0 ]; then
    echo "run with sudo: sudo sh deploy/remote/activate-relay.sh" >&2
    exit 1
fi

CURRENT=/opt/iou-ai/current
ACTIVE_RELEASE=$(readlink -f "$CURRENT" 2>/dev/null || true)
if [ -z "$ACTIVE_RELEASE" ] || [ ! -d "$ACTIVE_RELEASE" ]; then
    echo "active io-uring AI release is unavailable" >&2
    exit 1
fi

NOTIFY="$ACTIVE_RELEASE/.venv/bin/iou-ai-notify"
if [ ! -x "$NOTIFY" ]; then
    echo "active release does not contain the relay activation tools" >&2
    exit 1
fi
# Verify that this installed release has the side-effect-free probe before
# accepting or copying any human-entered secret material.
if ! "$NOTIFY" probe --help >/dev/null 2>&1; then
    echo "active release lacks the relay readiness probe" >&2
    exit 1
fi

# The operator stages five one-line ASCII files outside the repository.  The
# source can be a user-owned handoff directory; every value is copied to a
# root-only temporary directory before validation, so later source changes
# cannot alter the value that is probed or installed. Neither this path nor its
# contents are printed.
RELAY_CREDENTIAL_SOURCE=${IOU_AI_RELAY_CREDENTIAL_SOURCE:-/home/saedyn/iou-ai-relay-credentials}
if [ ! -d "$RELAY_CREDENTIAL_SOURCE" ] || [ -L "$RELAY_CREDENTIAL_SOURCE" ]; then
    echo "relay credential handoff directory is unavailable or unsafe" >&2
    exit 1
fi
for name in relay-endpoint relay.token decision.key telegram-bot.token telegram-chat.id; do
    candidate="$RELAY_CREDENTIAL_SOURCE/$name"
    if [ ! -f "$candidate" ] || [ -L "$candidate" ]; then
        echo "relay credential handoff is missing a required regular file" >&2
        exit 1
    fi
done

TIMER_UNITS="iou-ai-event-projector.timer iou-ai-notify.timer iou-ai-decision-import.timer"
for unit in $TIMER_UNITS; do
    if ! systemctl cat "$unit" >/dev/null 2>&1; then
        echo "required relay timer is unavailable" >&2
        exit 1
    fi
    # This script is deliberately activation-only.  Refusing an already live
    # set avoids replacing credentials beneath a running notification process.
    if systemctl is-enabled --quiet "$unit" || systemctl is-active --quiet "$unit"; then
        echo "relay timers are already enabled or active; disable them before rotating relay credentials" >&2
        exit 1
    fi
done

ENDPOINT_DEST=/etc/iou-ai/relay-endpoint
TOKEN_DEST=/etc/iou-ai/credentials/relay.token
DECISION_DEST=/etc/iou-ai/credentials/decision.key
TELEGRAM_TOKEN_DEST=/etc/iou-ai/credentials/telegram-bot.token
TELEGRAM_CHAT_DEST=/etc/iou-ai/credentials/telegram-chat.id
for destination in "$ENDPOINT_DEST" "$TOKEN_DEST" "$DECISION_DEST" "$TELEGRAM_TOKEN_DEST" "$TELEGRAM_CHAT_DEST"; do
    if [ -e "$destination" ] || [ -L "$destination" ]; then
        echo "refusing to replace existing relay configuration; inspect or remove it explicitly first" >&2
        exit 1
    fi
done

STAGING=
ENDPOINT_NEW=
TOKEN_NEW=
DECISION_NEW=
TELEGRAM_TOKEN_NEW=
TELEGRAM_CHAT_NEW=
INSTALLED_ENDPOINT=0
INSTALLED_TOKEN=0
INSTALLED_DECISION=0
INSTALLED_TELEGRAM_TOKEN=0
INSTALLED_TELEGRAM_CHAT=0
COMMITTED=0

cleanup() {
    # No destination existed before this activation.  If any post-validation
    # step fails, remove only files created by this invocation and leave all
    # relay timers disabled.
    if [ "$COMMITTED" -ne 1 ]; then
        if [ "$INSTALLED_ENDPOINT" -eq 1 ]; then rm -f -- "$ENDPOINT_DEST"; fi
        if [ "$INSTALLED_TOKEN" -eq 1 ]; then rm -f -- "$TOKEN_DEST"; fi
        if [ "$INSTALLED_DECISION" -eq 1 ]; then rm -f -- "$DECISION_DEST"; fi
        if [ "$INSTALLED_TELEGRAM_TOKEN" -eq 1 ]; then rm -f -- "$TELEGRAM_TOKEN_DEST"; fi
        if [ "$INSTALLED_TELEGRAM_CHAT" -eq 1 ]; then rm -f -- "$TELEGRAM_CHAT_DEST"; fi
    fi
    if [ -n "$ENDPOINT_NEW" ]; then rm -f -- "$ENDPOINT_NEW"; fi
    if [ -n "$TOKEN_NEW" ]; then rm -f -- "$TOKEN_NEW"; fi
    if [ -n "$DECISION_NEW" ]; then rm -f -- "$DECISION_NEW"; fi
    if [ -n "$TELEGRAM_TOKEN_NEW" ]; then rm -f -- "$TELEGRAM_TOKEN_NEW"; fi
    if [ -n "$TELEGRAM_CHAT_NEW" ]; then rm -f -- "$TELEGRAM_CHAT_NEW"; fi
    if [ -n "$STAGING" ] && [ -d "$STAGING" ]; then rm -rf -- "$STAGING"; fi
}
trap cleanup 0
trap 'exit 1' HUP INT TERM

umask 077
STAGING=$(mktemp -d /run/iou-ai-relay-activate.XXXXXX)
install -o root -g root -m 0600 \
    "$RELAY_CREDENTIAL_SOURCE/relay-endpoint" "$STAGING/relay-endpoint"
install -o root -g root -m 0600 \
    "$RELAY_CREDENTIAL_SOURCE/relay.token" "$STAGING/relay.token"
install -o root -g root -m 0600 \
    "$RELAY_CREDENTIAL_SOURCE/decision.key" "$STAGING/decision.key"
install -o root -g root -m 0600 \
    "$RELAY_CREDENTIAL_SOURCE/telegram-bot.token" "$STAGING/telegram-bot.token"
install -o root -g root -m 0600 \
    "$RELAY_CREDENTIAL_SOURCE/telegram-chat.id" "$STAGING/telegram-chat.id"

telegram_token=$(cat "$STAGING/telegram-bot.token")
if ! printf '%s' "$telegram_token" | grep -Eq '^[0-9]{6,20}:[A-Za-z0-9_-]{30,}$' \
    || [ "$(printf '%s' "$telegram_token" | wc -c)" -ne "$(wc -c < "$STAGING/telegram-bot.token")" ]; then
    echo "Telegram bot credential is invalid" >&2
    exit 1
fi
telegram_chat=$(cat "$STAGING/telegram-chat.id")
if ! printf '%s' "$telegram_chat" | grep -Eq '^[1-9][0-9]{0,18}$' \
    || [ "$(printf '%s' "$telegram_chat" | wc -c)" -ne "$(wc -c < "$STAGING/telegram-chat.id")" ]; then
    echo "Telegram recipient binding is invalid" >&2
    exit 1
fi
telegram_token=
telegram_chat=

# The probe makes exactly one authenticated GET /v1/ready request. It proves
# the staged decision key matches the relay HMAC with a fresh challenge, without
# transmitting that key. The protocol has no event body and the remote route is
# read-only, so it cannot send SMS or create a human decision. Suppress tool
# diagnostics in case a future transport implementation adds contextual error
# text.
if ! "$NOTIFY" probe \
    --endpoint-file "$STAGING/relay-endpoint" \
    --token-file "$STAGING/relay.token" \
    --decision-key-file "$STAGING/decision.key" >/dev/null 2>&1
then
    echo "relay readiness check failed; no relay timer was enabled" >&2
    exit 1
fi

install -d -o root -g iou-ai -m 0751 /etc/iou-ai
install -d -o root -g root -m 0700 /etc/iou-ai/credentials
ENDPOINT_NEW="$ENDPOINT_DEST.$$.new"
TOKEN_NEW="$TOKEN_DEST.$$.new"
DECISION_NEW="$DECISION_DEST.$$.new"
TELEGRAM_TOKEN_NEW="$TELEGRAM_TOKEN_DEST.$$.new"
TELEGRAM_CHAT_NEW="$TELEGRAM_CHAT_DEST.$$.new"
install -o root -g iou-ai-notify -m 0640 \
    "$STAGING/relay-endpoint" "$ENDPOINT_NEW"
install -o root -g root -m 0600 \
    "$STAGING/relay.token" "$TOKEN_NEW"
install -o root -g root -m 0600 \
    "$STAGING/decision.key" "$DECISION_NEW"
install -o root -g root -m 0600 \
    "$STAGING/telegram-bot.token" "$TELEGRAM_TOKEN_NEW"
install -o root -g root -m 0600 \
    "$STAGING/telegram-chat.id" "$TELEGRAM_CHAT_NEW"
# Create final names with hard links instead of replacement moves. Both source
# and destination are under /etc, so this is an atomic no-clobber operation: a
# concurrent or stale destination makes activation fail rather than replacing a
# file that this invocation did not create.
ln -T -- "$ENDPOINT_NEW" "$ENDPOINT_DEST"
INSTALLED_ENDPOINT=1
rm -f -- "$ENDPOINT_NEW"
ENDPOINT_NEW=
ln -T -- "$TOKEN_NEW" "$TOKEN_DEST"
INSTALLED_TOKEN=1
rm -f -- "$TOKEN_NEW"
TOKEN_NEW=
ln -T -- "$DECISION_NEW" "$DECISION_DEST"
INSTALLED_DECISION=1
rm -f -- "$DECISION_NEW"
DECISION_NEW=
ln -T -- "$TELEGRAM_TOKEN_NEW" "$TELEGRAM_TOKEN_DEST"
INSTALLED_TELEGRAM_TOKEN=1
rm -f -- "$TELEGRAM_TOKEN_NEW"
TELEGRAM_TOKEN_NEW=
ln -T -- "$TELEGRAM_CHAT_NEW" "$TELEGRAM_CHAT_DEST"
INSTALLED_TELEGRAM_CHAT=1
rm -f -- "$TELEGRAM_CHAT_NEW"
TELEGRAM_CHAT_NEW=

# Enabling and starting timers are separate so a partial systemd failure is
# rolled back to the same disabled state in which activation began.  No service
# is invoked directly here; timer scheduling begins only after every preflight
# and credential installation above succeeds.
if ! systemctl enable $TIMER_UNITS; then
    systemctl disable $TIMER_UNITS >/dev/null 2>&1 || true
    echo "failed to enable relay timers; activation rolled back" >&2
    exit 1
fi
if ! systemctl start $TIMER_UNITS; then
    systemctl disable --now $TIMER_UNITS >/dev/null 2>&1 || true
    echo "failed to start relay timers; activation rolled back" >&2
    exit 1
fi

COMMITTED=1
echo "Relay readiness passed; event projection, Telegram delivery, and decision import timers are enabled."
