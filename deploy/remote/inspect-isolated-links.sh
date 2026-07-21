#!/bin/sh
set -eu

# Root-only, read-only diagnostic for links that block an isolated Nyx copy.
# It starts no VM and prints only relative in-tree names and link targets; no
# corpus entries, seed bytes, logs, credentials, or process command lines.
if [ "$(id -u)" -ne 0 ]; then
    echo "run with sudo" >&2
    exit 1
fi

inspect_root() {
    scope=$1
    root=$2
    test -d "$root"
    find "$root" -xdev -type l -print | while IFS= read -r link; do
        relative=${link#"$root"/}
        target=$(readlink "$link")
        resolved=$(readlink -f "$link" 2>/dev/null || true)
        if [ -z "$resolved" ] || [ ! -e "$resolved" ]; then
            status=unresolved
        else
            case "$resolved" in
                "$root"|"$root"/*) status=internal ;;
                *) status=escapes_root ;;
            esac
        fi
        printf 'scope=%s status=%s path=%s target=%s\n' \
            "$scope" "$status" "$relative" "$target"
    done
}

inspect_root target /root/fuzzer_workspace/nyx_targets/iou_native_kasan
inspect_root nyx_runtime /root/fuzzer_workspace/AFLplusplus/nyx_mode
