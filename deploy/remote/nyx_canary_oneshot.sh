#!/bin/sh
# nyx_canary_oneshot.sh SEED_PATH
#
# Root-owned isolated one-shot Nyx canary. Runs ONE candidate seed once through
# a separately snapshotted KASAN Nyx target via `afl-cmin -X` (StandAlone role
# -> its own unique workdir + PID-keyed shm), with NO fuzzing and no contact
# with the live target tree or any live AFL corpus. Prints exactly ONE JSON line
# to stdout for canary.py:
#   {"executions_total":N,"harness_accepted":b,"timed_out":b,"signal_number":0,"infrastructure_error":b}
# Exit 0 = a completed measurement (PASS or seed-REJECT); non-zero = infra error.
# All human-readable diagnostics go to stderr only. Must be run as root.
set -u

SEED=${1:-}
CANARY_ROOT=/opt/iou-ai-canary/current
NYX=$CANARY_ROOT/afl
TGT=$CANARY_ROOT/targets
WORK_ROOT=/var/lib/iou-ai-canary/work
SHAREDIR=iou_native_kasan
PER_SEED_MS=${CANARY_PER_SEED_MS:-5000}
OUTER_SECONDS=${CANARY_OUTER_SECONDS:-90}

emit() { # executions harness_accepted timed_out infrastructure_error
    printf '{"executions_total":%s,"harness_accepted":%s,"timed_out":%s,"signal_number":0,"infrastructure_error":%s}\n' \
        "$1" "$2" "$3" "$4"
}

[ -f "$CANARY_ROOT/.ready" ] || { echo "canary: isolated snapshot is not ready" >&2; emit 0 false false true; exit 3; }
[ -n "$SEED" ] && [ -f "$SEED" ] || { echo "canary: seed file missing: $SEED" >&2; emit 0 false false true; exit 3; }
[ -d "$TGT/$SHAREDIR" ] || { echo "canary: sharedir missing" >&2; emit 0 false false true; exit 3; }
[ -x "$NYX/afl-cmin" ] || { echo "canary: afl-cmin missing" >&2; emit 0 false false true; exit 3; }
[ -x "$NYX/afl-showmap" ] || { echo "canary: afl-showmap missing" >&2; emit 0 false false true; exit 3; }
[ -d "$NYX/nyx_mode" ] || { echo "canary: nyx runtime missing" >&2; emit 0 false false true; exit 3; }
[ -d "$WORK_ROOT" ] || { echo "canary: isolated work root missing" >&2; emit 0 false false true; exit 3; }

W=$(mktemp -d "$WORK_ROOT/run.XXXXXX") || { echo "canary: mktemp failed" >&2; emit 0 false false true; exit 3; }
trap 'rm -rf "$W"' EXIT
mkdir -p "$W/in" "$W/out"
# harness caps input at 2048 bytes; feed exactly what it will consume
head -c 2048 "$SEED" > "$W/in/candidate"

cd "$TGT" || { echo "canary: cd failed" >&2; emit 0 false false true; exit 3; }

PATH="$NYX:$PATH" AFL_PATH="$NYX/nyx_mode" AFL_SKIP_CPUFREQ=1 AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 \
timeout -k 5 "$OUTER_SECONDS" nice -n 19 \
    "$NYX/afl-cmin" -X -t "$PER_SEED_MS" -i "$W/in" -o "$W/out" -- "./$SHAREDIR" \
    > "$W/log" 2>&1
RC=$?

BOOTS=$(grep -c 'Booting VM' "$W/log" 2>/dev/null); [ -n "$BOOTS" ] || BOOTS=0
KEPT=$(find "$W/out" -type f 2>/dev/null | wc -l)
PANIC=$(grep -ciE 'kasan|BUG:|kernel panic|general protection|use-after-free|stack-out-of-bounds' "$W/log" 2>/dev/null)
TMOUT=$(grep -ciE 'timeout|tmout|timed out' "$W/log" 2>/dev/null)

# Operator diagnostics (stderr only; canary.py ignores stderr).
{
    echo "canary: rc=$RC boots=$BOOTS kept=$KEPT panic=$PANIC tmout=$TMOUT"
    tail -n 40 "$W/log" | sed 's/^/canary-log: /'
} >&2

if [ "$RC" -eq 124 ]; then
    # outer hard timeout: the seed wedged the run -> REJECT as a hang
    emit "$BOOTS" false true false; exit 0
fi
if [ "$BOOTS" -lt 1 ]; then
    echo "canary: VM never booted -> infrastructure failure" >&2
    emit 0 false false true; exit 4
fi
if [ "$RC" -eq 0 ] && [ "$KEPT" -eq 1 ]; then
    # ran clean, produced coverage, kept by cmin -> PASS-eligible
    emit "$BOOTS" true false false; exit 0
fi
# VM ran but the seed was dropped -> crashed or hung: REJECT (never a PASS).
if [ "$TMOUT" -ge 1 ] && [ "$PANIC" -lt 1 ]; then
    emit "$BOOTS" false true false; exit 0
fi
emit "$BOOTS" false false false; exit 0
