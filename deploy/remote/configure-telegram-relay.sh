#!/bin/sh
set -eu

# One-time Telegram relay setup. It deliberately performs only the two narrow,
# authenticated control call needed to verify the locally bootstrapped private
# chat binding. Telegram's callback-only webhook is installed by the local
# bootstrap because Cloudflare egress to Telegram is not assumed. It never
# reads an event, enables a unit,
# invokes an AI model, or interacts with the fuzzing fleet.
if [ "$(id -u)" -ne 0 ]; then
    echo "run with sudo: sudo sh deploy/remote/configure-telegram-relay.sh" >&2
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
    echo "active release does not contain the Telegram relay setup tools" >&2
    exit 1
fi
for command in telegram-pair probe; do
    if ! "$NOTIFY" "$command" --help >/dev/null 2>&1; then
        echo "active release lacks a required Telegram relay setup command" >&2
        exit 1
    fi
done

# Never change a remote recipient or callback destination while the local relay
# is live. This is a configuration-only tool, not a credential-rotation path.
TIMER_UNITS="iou-ai-event-projector.timer iou-ai-notify.timer iou-ai-decision-import.timer"
for unit in $TIMER_UNITS; do
    if ! systemctl cat "$unit" >/dev/null 2>&1; then
        echo "required relay timer is unavailable" >&2
        exit 1
    fi
    if systemctl is-enabled --quiet "$unit" || systemctl is-active --quiet "$unit"; then
        echo "relay timers are already enabled or active; disable them before Telegram setup" >&2
        exit 1
    fi
done

# Read only the user-staged single-line handoff files. They are copied into a
# root-only temporary directory before validation so a subsequent source-path
# change cannot affect the values used by the HMAC-bound setup calls. Secrets,
# endpoint, bot token, chat identifier, and proof values are never printed.
RELAY_CREDENTIAL_SOURCE=${IOU_AI_RELAY_CREDENTIAL_SOURCE:-/home/saedyn/iou-ai-relay-credentials}
if [ ! -d "$RELAY_CREDENTIAL_SOURCE" ] || [ -L "$RELAY_CREDENTIAL_SOURCE" ]; then
    echo "relay credential handoff directory is unavailable or unsafe" >&2
    exit 1
fi
for name in relay-endpoint relay.token decision.key; do
    candidate="$RELAY_CREDENTIAL_SOURCE/$name"
    if [ ! -f "$candidate" ] || [ -L "$candidate" ]; then
        echo "relay credential handoff is missing a required regular file" >&2
        exit 1
    fi
done

STAGING=
cleanup() {
    if [ -n "$STAGING" ] && [ -d "$STAGING" ]; then rm -rf -- "$STAGING"; fi
}
trap cleanup 0
trap 'exit 1' HUP INT TERM

umask 077
STAGING=$(mktemp -d /run/iou-ai-telegram-setup.XXXXXX)
install -o root -g root -m 0600 \
    "$RELAY_CREDENTIAL_SOURCE/relay-endpoint" "$STAGING/relay-endpoint"
install -o root -g root -m 0600 \
    "$RELAY_CREDENTIAL_SOURCE/relay.token" "$STAGING/relay.token"
install -o root -g root -m 0600 \
    "$RELAY_CREDENTIAL_SOURCE/decision.key" "$STAGING/decision.key"

# Pairing is idempotent on the relay. The local bootstrap has already validated
# exactly one private /start sender and installed the callback-only webhook;
# this call confirms only that the relay has the singular binding.
"$NOTIFY" telegram-pair \
    --endpoint-file "$STAGING/relay-endpoint" \
    --token-file "$STAGING/relay.token" \
    --decision-key-file "$STAGING/decision.key" >/dev/null
# This is the same authenticated no-write query activation will repeat before
# it can enable timers. It sends no event and creates no approval decision.
"$NOTIFY" probe \
    --endpoint-file "$STAGING/relay-endpoint" \
    --token-file "$STAGING/relay.token" \
    --decision-key-file "$STAGING/decision.key" >/dev/null

echo "Telegram private receiver binding is verified; relay timers remain disabled."
