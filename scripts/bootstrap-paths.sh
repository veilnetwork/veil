#!/usr/bin/env bash
# Shared install/uninstall input policy. Source only; no system mutations.
bootstrap_validate_targets() {
    local data="$1" user="$2" part current=""
    [[ "$user" =~ ^[a-z_][a-z0-9_-]*$ && "$user" != root ]] || {
        echo 'invalid VEIL_USER (must be a non-root POSIX username)' >&2; return 1;
    }
    [[ "$data" =~ ^/[A-Za-z0-9._/-]+$ && "$data" != */ ]] || {
        echo 'DATA_DIR must be a normalized absolute directory path' >&2; return 1;
    }
    case "$data" in
        *//*|*/./*|*/../*|*/.|*/..|/bin|/boot|/dev|/etc|/home|/lib|/lib64|/media|/mnt|/opt|/proc|/root|/run|/sbin|/srv|/sys|/tmp|/usr|/var|/var/lib|/var/log|/usr/local|/usr/local/bin|/usr/bin|/usr/lib|/usr/sbin|/etc/*|/dev/*|/proc/*|/sys/*|/bin/*|/sbin/*|/boot/*)
            echo 'DATA_DIR must name a dedicated application directory' >&2; return 1 ;;
    esac
    # A symlink in any existing ancestor can turn a harmless-looking lexical
    # path into an unrelated system tree. Check before touching services too.
    local -a parts
    IFS=/ read -r -a parts <<< "$data"
    for part in "${parts[@]}"; do
        [[ -z "$part" ]] && continue
        current="$current/$part"
        [[ ! -L "$current" ]] || { echo 'DATA_DIR must not traverse symlinks' >&2; return 1; }
    done
}
