#!/bin/sh
set -eu

# One-time root activation for intake and read-only telemetry only. It does not
# stop, restart, signal, reconfigure, or write to the AFL/Nyx fleet. It also
# deliberately does not enable the AI shadow timer.
if [ "$(id -u)" -ne 0 ]; then
    echo "run with sudo: sudo sh deploy/remote/activate-readonly.sh" >&2
    exit 1
fi

SOURCE=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
CREDENTIAL_SOURCE=${IOU_AI_CREDENTIAL_SOURCE:-/home/saedyn/iou-ai-credentials}
VERSION=0.1.38
TARGET_RELEASE=/opt/iou-ai/releases/$VERSION

sh "$SOURCE/deploy/remote/install.sh"
ACTIVE_RELEASE=$(readlink -f /opt/iou-ai/current)
if [ "$ACTIVE_RELEASE" != "$TARGET_RELEASE" ]; then
    echo "active release mismatch: expected $TARGET_RELEASE, found $ACTIVE_RELEASE" >&2
    exit 1
fi
echo "using installed release: $ACTIVE_RELEASE"

test -f "$CREDENTIAL_SOURCE/openai.key"
test -f "$CREDENTIAL_SOURCE/anthropic.key"
install -o root -g root -m 0600 \
    "$CREDENTIAL_SOURCE/openai.key" /etc/iou-ai/credentials/openai.key
install -o root -g root -m 0600 \
    "$CREDENTIAL_SOURCE/anthropic.key" /etc/iou-ai/credentials/anthropic.key

sh /opt/iou-ai/current/deploy/remote/snapshot-authority.sh
/opt/iou-ai/current/.venv/bin/iou-ai-contract \
    --authority-dir /var/lib/iou-ai/contracts/authority \
    --output /var/lib/iou-ai/contracts/harness-contract.production.json
chown root:iou-ai /var/lib/iou-ai/contracts/harness-contract.production.json
chmod 0640 /var/lib/iou-ai/contracts/harness-contract.production.json

# Give the unprivileged operator a read-only handoff copy for independent
# contract extraction. The authoritative copy remains root-owned under
# /var/lib/iou-ai/contracts/authority.
AUTHORITY_HANDOFF=/home/saedyn/iou-ai-authority
install -d -o saedyn -g saedyn -m 0700 "$AUTHORITY_HANDOFF"
latest_snapshot=
for snapshot in /var/lib/iou-ai/contracts/authority/io_uring_harness_native.*.c; do
    latest_snapshot=$snapshot
done
test -n "$latest_snapshot"
install -o saedyn -g saedyn -m 0600 \
    "$latest_snapshot" "$AUTHORITY_HANDOFF/io_uring_harness_native.c"
install -o saedyn -g saedyn -m 0600 \
    "${latest_snapshot%.c}.sha256" "$AUTHORITY_HANDOFF/io_uring_harness_native.sha256"

snapshot_name=$(basename "$latest_snapshot")
snapshot_stamp=${snapshot_name#io_uring_harness_native.}
snapshot_stamp=${snapshot_stamp%.c}
for artifact in /var/lib/iou-ai/contracts/authority/iou_*."$snapshot_stamp".*; do
    test -f "$artifact" || continue
    install -o saedyn -g saedyn -m 0600 \
        "$artifact" "$AUTHORITY_HANDOFF/$(basename "$artifact")"
done

systemctl start iou-ai-lkml.service
systemctl start iou-ai-export.service
systemctl start iou-ai-telemetry.service
systemctl enable --now \
    iou-ai-lkml.timer \
    iou-ai-export.timer \
    iou-ai-telemetry.timer

echo "Read-only intake is active. The live AFL/Nyx fleet was not changed."
echo "Production contract active. Deterministic compilation is now ENABLED: accepted proposals compile to bytes IN QUARANTINE only."
echo "Live byte emission to the fleet remains gated behind the isolated canary + human approval + the separate promoter."
echo "Relay activation state was not changed by this read-only activation."
echo "The AI shadow timer remains disabled pending one manual quarantined run."
echo "Authority handoff: $AUTHORITY_HANDOFF"
