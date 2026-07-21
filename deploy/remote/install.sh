#!/bin/sh
set -eu

# Versioned privileged installer. It never stops, restarts, or edits the AFL/Nyx fleet.
if [ "$(id -u)" -ne 0 ]; then
    echo "run with sudo: sudo sh deploy/remote/install.sh" >&2
    exit 1
fi

SOURCE=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
VERSION=0.1.42
RELEASE=/opt/iou-ai/releases/$VERSION

# Fail before changing deployment state when Ubuntu's split-out venv package is
# missing. The host currently uses Python 3.14.
if ! python3 -c 'import ensurepip' >/dev/null 2>&1; then
    echo "python ensurepip is unavailable; install python3.14-venv and retry" >&2
    exit 1
fi

if ! getent group iou-ai >/dev/null 2>&1; then
    groupadd --system iou-ai
fi
if ! getent passwd iou-ai >/dev/null 2>&1; then
    useradd --system --gid iou-ai --home-dir /var/lib/iou-ai --shell /usr/sbin/nologin iou-ai
fi
if ! getent group iou-ai-events >/dev/null 2>&1; then
    groupadd --system iou-ai-events
fi
usermod -a -G iou-ai-events iou-ai
if ! getent group iou-ai-decisions >/dev/null 2>&1; then
    groupadd --system iou-ai-decisions
fi
if ! getent group iou-ai-notify >/dev/null 2>&1; then
    groupadd --system iou-ai-notify
fi
if ! getent passwd iou-ai-notify >/dev/null 2>&1; then
    useradd --system --gid iou-ai-notify --home-dir /var/lib/iou-ai-notify --shell /usr/sbin/nologin iou-ai-notify
fi
if ! getent group iou-ai-decision >/dev/null 2>&1; then
    groupadd --system iou-ai-decision
fi
if ! getent passwd iou-ai-decision >/dev/null 2>&1; then
    useradd --system --gid iou-ai-decision --home-dir /var/lib/iou-ai-decisions --shell /usr/sbin/nologin iou-ai-decision
fi
usermod -a -G iou-ai-events,iou-ai-decisions iou-ai-notify
usermod -a -G iou-ai-events,iou-ai-decisions iou-ai-decision

install -d -o root -g root -m 0755 /opt/iou-ai/releases
if [ -e "$RELEASE/.install-complete" ]; then
    echo "release is already installed: $RELEASE"
else
    if [ -d "$RELEASE" ]; then
        echo "resuming incomplete release: $RELEASE"
    else
        install -d -o root -g root -m 0755 "$RELEASE"
    fi
    if [ "$SOURCE" != "$RELEASE" ]; then
        cp -a "$SOURCE"/. "$RELEASE"/
    fi
    chown -R root:root "$RELEASE"
    python3 -m venv --clear "$RELEASE/.venv"
    "$RELEASE/.venv/bin/python" -m pip install --disable-pip-version-check "$RELEASE"

    # scp and restrictive operator umasks must not make the immutable release
    # unreadable to the unprivileged service account. Preserve executable bits
    # created by the venv, add directory traversal/read access, and remove all
    # group/other writes.
    chown -R root:root "$RELEASE"
    chmod -R a+rX "$RELEASE"
    chmod -R go-w "$RELEASE"
    chmod 0755 "$RELEASE"/deploy/remote/*.sh

    touch "$RELEASE/.install-complete"
    chown root:root "$RELEASE/.install-complete"
    chmod 0644 "$RELEASE/.install-complete"
fi

ln -sfn "$RELEASE" /opt/iou-ai/current
# Allow service accounts to traverse to explicitly permitted files without
# allowing them to list this directory. Individual configuration remains 0640.
install -d -o root -g iou-ai -m 0751 /etc/iou-ai
install -d -o root -g root -m 0700 /etc/iou-ai/credentials
install -d -o root -g iou-ai -m 0751 /var/lib/iou-ai
install -d -o root -g iou-ai -m 0750 \
    /var/lib/iou-ai/contracts \
    /var/lib/iou-ai/export
install -d -o iou-ai -g iou-ai -m 0700 \
    /var/lib/iou-ai/runtime \
    /var/lib/iou-ai/inbox \
    /var/lib/iou-ai/quarantine \
    /var/lib/iou-ai/artifacts \
    /var/lib/iou-ai/lkml
# Root-owned execution-authority tree (validation/canary reports + approval-ready
# candidates). The isolated canary runs as root and writes here; the store
# self-creates the validation-reports/canary-reports/candidates subtrees.
install -d -o root -g root -m 0750 /var/lib/iou-ai-execution
# Static AFL foreign-sync allowlist root + per-worker-set inboxes the root promoter
# publishes one approved seed into, plus the promotion-receipt store. The live
# AFL/Nyx fleet ingests these inboxes via `afl-fuzz -F`. Root-owned end to end:
# only the root promoter writes here and only the root fleet reads here.
install -d -o root -g root -m 0750 \
    /var/lib/iou-ai-execution/sync \
    /var/lib/iou-ai-execution/sync/native_ai_sync \
    /var/lib/iou-ai-execution/sync/kasan_ai_sync \
    /var/lib/iou-ai-execution/promotion-receipts \
    /var/lib/iou-ai-execution/canary-processed
install -d -o iou-ai -g iou-ai-events -m 2750 /var/lib/iou-ai/events
install -d -o iou-ai-notify -g iou-ai-notify -m 0700 \
    /var/lib/iou-ai-notify \
    /var/lib/iou-ai-notify/receipts \
    /var/lib/iou-ai-notify/state
install -d -o root -g iou-ai-decisions -m 0750 /var/lib/iou-ai-decisions
install -d -o iou-ai-notify -g iou-ai-decisions -m 2750 /var/lib/iou-ai-decisions/inbox
install -d -o iou-ai-decision -g iou-ai-decisions -m 2750 /var/lib/iou-ai-decisions/archive

# Preserve any pre-0.1.1 ledger or operator kill switch while moving controller
# writes out of the root state directory.
if [ -e /var/lib/iou-ai/budget.sqlite3 ] && [ ! -e /var/lib/iou-ai/runtime/budget.sqlite3 ]; then
    mv /var/lib/iou-ai/budget.sqlite3 /var/lib/iou-ai/runtime/budget.sqlite3
fi
if [ -e /var/lib/iou-ai/AI_CALLS_DISABLED ] && [ ! -e /var/lib/iou-ai/runtime/AI_CALLS_DISABLED ]; then
    mv /var/lib/iou-ai/AI_CALLS_DISABLED /var/lib/iou-ai/runtime/AI_CALLS_DISABLED
fi
chown -R iou-ai:iou-ai \
    /var/lib/iou-ai/runtime \
    /var/lib/iou-ai/inbox \
    /var/lib/iou-ai/quarantine \
    /var/lib/iou-ai/artifacts \
    /var/lib/iou-ai/lkml

install -o root -g iou-ai -m 0640 "$RELEASE/deploy/config.shadow.toml" /etc/iou-ai/config.toml
install -o root -g root -m 0644 "$RELEASE/deploy/systemd/iou-ai-shadow.service" /etc/systemd/system/iou-ai-shadow.service
install -o root -g root -m 0644 "$RELEASE/deploy/systemd/iou-ai-shadow.timer" /etc/systemd/system/iou-ai-shadow.timer
for unit in \
    iou-ai-lkml.service \
    iou-ai-lkml.timer \
    iou-ai-export.service \
    iou-ai-export.timer \
    iou-ai-telemetry.service \
    iou-ai-telemetry.timer \
    iou-ai-event-projector.service \
    iou-ai-event-projector.timer \
    iou-ai-notify.service \
    iou-ai-notify.timer \
    iou-ai-decision-import.service \
    iou-ai-decision-import.timer \
    iou-ai-auto.service \
    iou-ai-auto.timer
do
    install -o root -g root -m 0644 \
        "$RELEASE/deploy/systemd/$unit" "/etc/systemd/system/$unit"
done

# Do not overwrite credentials on upgrades and do not enable any timer automatically.
if [ ! -e /etc/iou-ai/credentials/openai.key ]; then
    install -o root -g root -m 0600 /dev/null /etc/iou-ai/credentials/openai.key
fi
if [ ! -e /etc/iou-ai/credentials/anthropic.key ]; then
    install -o root -g root -m 0600 /dev/null /etc/iou-ai/credentials/anthropic.key
fi

systemctl daemon-reload
echo "Installed release $VERSION. No service or timer was enabled and the fuzz fleet was not changed."
