#!/bin/sh
set -eu

# Root-only, READ-ONLY reconnaissance for an isolated Nyx canary.  It starts
# no VM, invokes no fuzzer, writes no AFL queue, and never reads a seed.  The
# report supplies the facts needed to build a separate canary snapshot instead
# of guessing that afl-cmin's flags or the live target layout are compatible.
if [ "$(id -u)" -ne 0 ]; then
    echo "run with sudo" >&2
    exit 1
fi

WORKSPACE=/root/fuzzer_workspace
NYX=$WORKSPACE/AFLplusplus
NATIVE=$WORKSPACE/nyx_targets/iou_native_pack
KASAN=$WORKSPACE/nyx_targets/iou_native_kasan
RUNNER=/opt/iou-ai/current/deploy/remote/nyx_canary_oneshot.sh
OUT=/home/saedyn/iou-ai-authority/canary-preflight.json
TMP=$OUT.tmp-$$

test -x "$NYX/afl-cmin"
test -x "$NYX/afl-fuzz"
test -f "$RUNNER"
install -d -o saedyn -g saedyn -m 0700 /home/saedyn/iou-ai-authority
trap 'rm -f "$TMP"' EXIT HUP INT TERM

target_type() {
    if [ -f "$1" ]; then
        printf 'regular-file'
    elif [ -d "$1" ]; then
        printf 'directory'
    else
        printf 'missing'
    fi
}

manifest_digest() {
    flavor=$1
    latest=
    for candidate in /var/lib/iou-ai/contracts/authority/iou_"$flavor".*.target.sha256; do
        test -f "$candidate" || continue
        latest=$candidate
    done
    test -n "$latest" || { echo "missing ${flavor} target authority manifest" >&2; exit 1; }
    # The activation snapshot already hashed the complete directory (when the
    # target is a directory). Hash its immutable manifest here rather than
    # re-hashing a potentially multi-gigabyte Nyx tree during this lightweight
    # preflight.
    sha256sum "$latest" | awk '{print $1}'
}

native_qemu=$(ps -C qemu-system-x86 -o args= | awk -v needle="sharedir=$NATIVE" 'index($0, needle) { count++ } END { print count + 0 }')
kasan_qemu=$(ps -C qemu-system-x86 -o args= | awk -v needle="sharedir=$KASAN" 'index($0, needle) { count++ } END { print count + 0 }')
afl_workers=$(pgrep -x afl-fuzz 2>/dev/null | wc -l)
qemu_workers=$(pgrep -x qemu-system-x86 2>/dev/null | wc -l)
help_hash=$("$NYX/afl-cmin" -h 2>&1 | head -n 256 | sha256sum | awk '{print $1}')

cat > "$TMP" <<EOF
{"schema_version":"canary-preflight.v1","afl_cmin_sha256":"$(sha256sum "$NYX/afl-cmin" | awk '{print $1}')","afl_fuzz_sha256":"$(sha256sum "$NYX/afl-fuzz" | awk '{print $1}')","runner_sha256":"$(sha256sum "$RUNNER" | awk '{print $1}')","afl_cmin_help_sha256":"$help_hash","native_target_type":"$(target_type "$NATIVE")","native_target_manifest_sha256":"$(manifest_digest native)","kasan_target_type":"$(target_type "$KASAN")","kasan_target_manifest_sha256":"$(manifest_digest kasan)","live_afl_workers":$afl_workers,"live_qemu_workers":$qemu_workers,"live_native_qemu_references":$native_qemu,"live_kasan_qemu_references":$kasan_qemu,"probe_started_vm":false,"probe_modified_fleet":false}
EOF

# The report is machine-readable, bounded, and has no raw command lines,
# filesystem paths, corpus names, seeds, logs, tokens, or credentials.
install -o saedyn -g saedyn -m 0600 "$TMP" "$OUT"
echo "wrote read-only canary capability report: $OUT"
