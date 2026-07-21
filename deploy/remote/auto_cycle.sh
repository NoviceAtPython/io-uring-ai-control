#!/bin/sh
# One unattended promotion cycle, run as root by iou-ai-auto.service.
#
#   canary any newly compiled artifact  ->  auto-approve  ->  promote
#
# Each stage is independently fail-closed and re-verifies the whole authority
# chain; this script only sequences them. It deliberately exits 0 even when a
# stage has nothing to do (exit 4), so an idle cycle is not reported as a unit
# failure -- but every stage's JSON goes to the journal, so `journalctl -u
# iou-ai-auto` always shows exactly what happened and why.
#
# The approval here is signed `operator:auto-v1`, NOT `operator:local-v1`: the
# archive records that the auto policy accepted a candidate, never that a human
# did. Promotion still publishes only into the allowlisted foreign-sync inbox.
set -u
CONFIG=${IOU_AI_CONFIG:-/etc/iou-ai/config.toml}
RUNNER=${IOU_AI_RUNNER:-/opt/iou-ai/current/deploy/remote/nyx_canary_oneshot.sh}
CAMPAIGN=${IOU_AI_CAMPAIGN:-io-uring-coverage-2026-07}
BIN=/opt/iou-ai/current/.venv/bin
PROCESSED=${IOU_AI_PROCESSED:-/var/lib/iou-ai-execution/canary-processed}
MAX=${IOU_AI_MAX_ENVELOPES:-4}

install -d -o root -g root -m 0750 "$PROCESSED" 2>/dev/null || true

echo "=== canary (scan, max $MAX) ==="
"$BIN/iou-ai-canary" --config "$CONFIG" --runner "$RUNNER" --campaign "$CAMPAIGN" \
    --worker-set native_stable --scan --max "$MAX" --processed-dir "$PROCESSED"
echo "canary exit=$?"

echo "=== auto-approve (operator:auto-v1) ==="
"$BIN/iou-ai-approve" --config "$CONFIG" --auto --scan
echo "approve exit=$?"

echo "=== promote ==="
"$BIN/iou-ai-promoter" --config "$CONFIG" --runner "$RUNNER" --campaign "$CAMPAIGN" --scan
echo "promoter exit=$?"

exit 0
