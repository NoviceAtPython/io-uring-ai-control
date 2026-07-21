#!/bin/sh
set -eu

# Root-only exporter: copies allowlisted AFL fuzzer_stats and uname. It never
# reads queue entries, seed bytes, crash traces, kernel logs, or API credentials.
if [ "$(id -u)" -ne 0 ]; then
    echo "run with sudo" >&2
    exit 1
fi

EXPORT_ROOT=/var/lib/iou-ai/export
DEST=$EXPORT_ROOT/raw-stats
NEXT=$EXPORT_ROOT/raw-stats.next
PREVIOUS=$EXPORT_ROOT/raw-stats.previous

SOURCE=
for candidate in \
    /root/fuzzer_workspace/nat_out \
    /root/fuzzer_workspace/nyx_targets/nat_out
do
    candidate_count=0
    for candidate_stats in "$candidate"/*/fuzzer_stats; do
        test -f "$candidate_stats" || continue
        candidate_count=$((candidate_count + 1))
    done
    if [ "$candidate_count" -eq 10 ]; then
        if [ -n "$SOURCE" ]; then
            echo "multiple fleet outputs contain exactly 10 workers; refusing ambiguity" >&2
            exit 1
        fi
        SOURCE=$candidate
    fi
done

if [ -z "$SOURCE" ]; then
    echo "no approved fleet output contains exactly 10 fuzzer_stats files" >&2
    exit 1
fi

test -d "$SOURCE"
if [ -e "$NEXT" ]; then
    echo "stale temporary export exists: $NEXT" >&2
    exit 1
fi
install -d -o root -g iou-ai -m 0750 "$NEXT"
count=0
for stats in "$SOURCE"/*/fuzzer_stats; do
    test -f "$stats" || continue
    worker=$(basename "$(dirname "$stats")")
    case "$worker" in
        *[!0-9]*|'') continue ;;
    esac
    install -d -o root -g iou-ai -m 0750 "$NEXT/$worker"
    install -o root -g iou-ai -m 0640 "$stats" "$NEXT/$worker/fuzzer_stats"
    count=$((count + 1))
done
if [ "$count" -ne 10 ]; then
    echo "expected 10 fuzzer_stats files, found $count" >&2
    exit 1
fi
uname -r > "$NEXT/kernel-release"
chown root:iou-ai "$NEXT/kernel-release"
chmod 0640 "$NEXT/kernel-release"
# A bounded, seed-free profile helps the planner choose coverage work based on
# real operation frequencies rather than a static guess.  It is optional: an
# unavailable profile is omitted and regular telemetry still rotates normally.
if /opt/iou-ai/current/.venv/bin/iou-ai-corpus-profile \
    --corpus-dir "$SOURCE" \
    --contract /var/lib/iou-ai/contracts/harness-contract.production.json \
    --output "$NEXT/operation-profile.json" \
    --max-workers 10 \
    --max-per-worker 64
then
    chown root:iou-ai "$NEXT/operation-profile.json"
    chmod 0640 "$NEXT/operation-profile.json"
else
    echo "operation profile unavailable; rotating numeric fleet telemetry without it" >&2
fi
if [ -e "$PREVIOUS" ]; then
    find "$PREVIOUS" -depth -mindepth 1 -delete
    rmdir "$PREVIOUS"
fi
if [ -e "$DEST" ]; then
    mv "$DEST" "$PREVIOUS"
fi
mv "$NEXT" "$DEST"

# Emit one bounded, numeric-only health line to journald.  The operator is in
# the adm group and can inspect this without gaining access to raw fleet paths,
# queue entries, seed bytes, command lines, or crash material.
summary=$(awk -F: '
function numeric(value) {
    gsub(/[[:space:]%]/, "", value)
    return value + 0
}
FNR == 1 { workers++ }
$1 ~ /^execs_done[[:space:]]*$/ { execs_total += numeric($2) }
$1 ~ /^execs_per_sec[[:space:]]*$/ { execs_per_sec += numeric($2) }
$1 ~ /^(corpus_count|paths_total)[[:space:]]*$/ {
    value = numeric($2); if (value > corpus_max) corpus_max = value
}
$1 ~ /^edges_found[[:space:]]*$/ {
    value = numeric($2); if (value > edges_max) edges_max = value
}
$1 ~ /^saved_crashes[[:space:]]*$/ {
    value = numeric($2); if (value > crashes_max) crashes_max = value
}
$1 ~ /^saved_hangs[[:space:]]*$/ {
    value = numeric($2); if (value > hangs_max) hangs_max = value
}
$1 ~ /^cycles_wo_finds[[:space:]]*$/ {
    value = numeric($2); if (value > cycles_wo_finds_max) cycles_wo_finds_max = value
}
$1 ~ /^stability[[:space:]]*$/ {
    value = numeric($2)
    if (!stability_seen || value < stability_min) stability_min = value
    stability_seen = 1
}
$1 ~ /^last_update[[:space:]]*$/ {
    value = numeric($2)
    if (!update_seen || value < oldest_update) oldest_update = value
    update_seen = 1
}
END {
    printf "workers=%d execs_total=%.0f execs_per_sec=%.3f corpus_max=%.0f edges_max=%.0f crashes_max=%.0f hangs_max=%.0f cycles_wo_finds_max=%.0f stability_min=%.3f oldest_update=%.0f", workers, execs_total, execs_per_sec, corpus_max, edges_max, crashes_max, hangs_max, cycles_wo_finds_max, stability_min, oldest_update
}
' "$DEST"/*/fuzzer_stats)
echo "exported 10 allowlisted fuzzer_stats files without changing the fleet; $summary"
