#!/bin/sh
set -eu

# Build a root-owned, content-checked snapshot for the Nyx canary. This is a
# copy-only operation: it never starts a VM, invokes a fuzzer, writes an AFL
# queue, or signals a live worker. The runner consumes only this snapshot.
if [ "$(id -u)" -ne 0 ]; then
    echo "run with sudo" >&2
    exit 1
fi

SOURCE_ROOT=/root/fuzzer_workspace
RUNTIME=$SOURCE_ROOT/AFLplusplus
TARGET=$SOURCE_ROOT/nyx_targets/iou_native_kasan
RUNNER=/opt/iou-ai/current/deploy/remote/nyx_canary_oneshot.sh
PREFLIGHT=/home/saedyn/iou-ai-authority/canary-preflight.json
ROOT=/opt/iou-ai-canary
VERSIONS=$ROOT/versions
WORK_ROOT=/var/lib/iou-ai-canary/work
STAGE=$VERSIONS/.stage-$$

die() { echo "canary snapshot blocked: $*" >&2; exit 1; }
test -f "$PREFLIGHT" || die "read-only preflight is missing"
test -x "$RUNTIME/afl-cmin" || die "afl-cmin is missing"
test -x "$RUNTIME/afl-showmap" || die "afl-showmap is missing"
test -d "$RUNTIME/nyx_mode" || die "Nyx runtime directory is missing"
test -d "$TARGET" || die "KASAN target directory is missing"
test ! -L "$RUNTIME/nyx_mode" || die "Nyx runtime root is a symlink"
test ! -L "$TARGET" || die "KASAN target root is a symlink"
test -f "$RUNNER" || die "canary runner is missing"

json_hash() {
    key=$1
    value=$(sed -n 's/.*"'"$key"'":"\([0-9a-f][0-9a-f]*\)".*/\1/p' "$PREFLIGHT")
    case "$value" in
        ????????????????????????????????????????????????????????????????) printf '%s\n' "$value" ;;
        *) die "preflight field $key is unavailable" ;;
    esac
}

current_hash() { sha256sum "$1" | awk '{print $1}'; }
test "$(json_hash afl_cmin_sha256)" = "$(current_hash "$RUNTIME/afl-cmin")" || die "afl-cmin changed since preflight"
test "$(json_hash runner_sha256)" = "$(current_hash "$RUNNER")" || die "runner changed since preflight"

tree_digest() {
    (
        cd "$1"
        find . -xdev -type f -print0 | LC_ALL=C sort -z | xargs -0 -r sha256sum | sha256sum | awk '{print $1}'
    )
}

runtime_digest() {
    (
        cd "$RUNTIME"
        {
            sha256sum ./afl-cmin ./afl-showmap
            find ./nyx_mode -xdev -type f -print0 | LC_ALL=C sort -z | xargs -0 -r sha256sum
        } | sha256sum | awk '{print $1}'
    )
}

normalize_links() {
    source_root=$1
    destination_root=$2
    find "$source_root" -xdev -type l -print | while IFS= read -r link; do
        relative=${link#"$source_root"/}
        destination_link=$destination_root/$relative
        resolved=$(readlink -f "$link" 2>/dev/null || true)
        if [ -z "$resolved" ] || [ ! -e "$resolved" ]; then
            # These are broken links in QEMU build/documentation material. They
            # cannot be reached through the snapshot and are omitted rather
            # than copied as dangling links. The clean Nyx self-test remains
            # the final proof that no runtime dependency was removed.
            rm -f "$destination_link"
            continue
        fi
        case "$resolved" in
            "$source_root")
                target_relative=.
                destination_target=$destination_root
                ;;
            "$source_root"/*)
                target_relative=${resolved#"$source_root"/}
                destination_target=$destination_root/$target_relative
                ;;
            *) die "snapshot symlink escapes its isolated root" ;;
        esac
        test -e "$destination_target" || die "snapshot symlink target was not copied: $relative -> $target_relative"
        relative_target=$(realpath --relative-to="$(dirname "$destination_link")" "$destination_target") || die "snapshot link normalization failed"
        rm -f "$destination_link"
        ln -s "$relative_target" "$destination_link"
    done
}

assert_snapshot_links() {
    root=$1
    find "$root" -xdev -type l -print | while IFS= read -r link; do
        resolved=$(readlink -f "$link" 2>/dev/null || true)
        test -n "$resolved" || die "snapshot retains an unresolved symlink"
        test -e "$resolved" || die "snapshot retains a dangling symlink"
        case "$resolved" in
            "$root"|"$root"/*) ;;
            *) die "snapshot symlink escapes its isolated root" ;;
        esac
    done
}

# Internal source links are rewritten to relative links in the copied tree.
# Absolute source links must never survive the copy because they could refer
# back to the live workspace. Broken source links are omitted; escaping links
# are rejected before any snapshot becomes usable.
test ! -L "$RUNTIME/afl-cmin" || die "afl-cmin is a symlink"
test ! -L "$RUNTIME/afl-showmap" || die "afl-showmap is a symlink"

target_before=$(tree_digest "$TARGET")
runtime_before=$(runtime_digest)
snapshot_id=$(printf '%s:%s\n' "$target_before" "$runtime_before" | sha256sum | awk '{print $1}')
destination=$VERSIONS/$snapshot_id
test ! -e "$destination" || die "identical snapshot already exists; refusing to overwrite it"

install -d -o root -g root -m 0755 "$VERSIONS"
install -d -o root -g root -m 0700 "$WORK_ROOT"
install -d -o root -g root -m 0700 "$STAGE/afl" "$STAGE/targets"
trap 'rm -rf "$STAGE"' EXIT HUP INT TERM
cp -a "$RUNTIME/afl-cmin" "$RUNTIME/afl-showmap" "$STAGE/afl/"
cp -a "$RUNTIME/nyx_mode" "$STAGE/afl/nyx_mode"
cp -a "$TARGET" "$STAGE/targets/iou_native_kasan"

normalize_links "$TARGET" "$STAGE/targets/iou_native_kasan"
normalize_links "$RUNTIME/nyx_mode" "$STAGE/afl/nyx_mode"
assert_snapshot_links "$STAGE/targets/iou_native_kasan"
assert_snapshot_links "$STAGE/afl/nyx_mode"
test "$target_before" = "$(tree_digest "$TARGET")" || die "live target changed during copy"
test "$runtime_before" = "$(runtime_digest)" || die "Nyx runtime changed during copy"
test "$target_before" = "$(tree_digest "$STAGE/targets/iou_native_kasan")" || die "target copy digest mismatch"
(
    cd "$STAGE/afl"
    {
        sha256sum ./afl-cmin ./afl-showmap
        find ./nyx_mode -xdev -type f -print0 | LC_ALL=C sort -z | xargs -0 -r sha256sum
    } | sha256sum | awk '{print $1}'
) | grep -qx "$runtime_before" || die "runtime copy digest mismatch"

source_link_count=$(find "$TARGET" "$RUNTIME/nyx_mode" -xdev -type l | wc -l)
snapshot_link_count=$(find "$STAGE/targets/iou_native_kasan" "$STAGE/afl/nyx_mode" -xdev -type l | wc -l)
omitted_link_count=$((source_link_count - snapshot_link_count))
test "$omitted_link_count" -ge 0 || die "snapshot link accounting failed"

printf '{"schema_version":"isolated-canary-snapshot.v1","snapshot_id":"%s","target_tree_sha256":"%s","runtime_tree_sha256":"%s","runner_sha256":"%s","unresolved_links_omitted":%s,"source_live_fleet_modified":false}\n' \
    "$snapshot_id" "$target_before" "$runtime_before" "$(current_hash "$RUNNER")" "$omitted_link_count" \
    > "$STAGE/snapshot.json"
touch "$STAGE/.ready"
chown -R root:root "$STAGE"
chmod -R go-w "$STAGE"
find "$STAGE" -type d -exec chmod 0755 {} +
find "$STAGE" -type f -exec chmod a+r {} +
chmod 0755 "$STAGE/afl/afl-cmin" "$STAGE/afl/afl-showmap"
mv "$STAGE" "$destination"
ln -sfn "$destination" "$ROOT/current"
trap - EXIT HUP INT TERM
echo "prepared isolated Nyx canary snapshot: $destination"
