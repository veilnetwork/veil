#!/bin/sh
# shellcheck shell=sh
# ============================================================================
# veil installer  —  Linux & macOS  (rustup-style one-liner)
#
#   curl --proto '=https' --tlsv1.2 -sSf \
#     https://raw.githubusercontent.com/veilnetwork/veil/main/scripts/install.sh | sh
#
# Downloads PREBUILT, sha256-verified binaries from GitHub Releases and walks
# you from `curl` all the way to a running node. No Rust toolchain required.
#
# What it installs (pick any subset; default: veil-cli):
#   veil-cli     the node + self-updater (client leaf OR public server)
#   ogate           IP-over-veil TUN gateway (server-side)
#   oproxy-client   local SOCKS5/HTTP proxy -> veil
#   oproxy-server   veil exit/proxy server
#
# Quick examples:
#   sh install.sh                       # just the node, into ~/.veil/bin
#   sh install.sh --all                 # node + ogate + oproxy (client+server)
#   sh install.sh --components ogate,oproxy-client
#   sh install.sh --version 1.4.0 --prefix /usr/local --no-modify-path
#   VEIL_REPO=me/fork sh install.sh  # install from a fork/mirror
#
# Pass `--help` for the full flag list. POSIX sh — works under dash/ash/bash.
# ============================================================================
set -eu

# ── Defaults (override via env or flags) ────────────────────────────────────
REPO="${VEIL_REPO:-veilnetwork/veil}"
VEIL_HOME="${VEIL_HOME:-${HOME}/.veil}"
BIN_DIR=""                 # resolved after flag parse (prefix vs veil-home)
PREFIX=""                  # if set, install into $PREFIX/bin instead
REQ_VERSION="latest"       # 'latest' or an explicit X.Y.Z
COMPONENTS="veil-cli"   # comma list; --all expands to the full set
LIBC="auto"                # auto|musl|gnu (Linux only)
MODIFY_PATH=1
ASSUME_YES=0
QUICKSTART="auto"          # auto|yes|no — offer to init+run a node at the end
NO_VERIFY=0                # escape hatch; verification is ON by default
ALL_COMPONENTS="veil-cli ogate oproxy-client oproxy-server"

# ── Pretty output ───────────────────────────────────────────────────────────
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    _b="$(printf '\033[1m')"; _dim="$(printf '\033[2m')"; _r="$(printf '\033[0m')"
    _grn="$(printf '\033[1;32m')"; _ylw="$(printf '\033[1;33m')"
    _red="$(printf '\033[1;31m')"; _cyn="$(printf '\033[1;36m')"
else
    _b=""; _dim=""; _r=""; _grn=""; _ylw=""; _red=""; _cyn=""
fi
say()  { printf '%s\n' "${_cyn}veil${_r}: $*"; }
info() { printf '%s\n' "  $*"; }
ok()   { printf '%s\n' "${_grn}  ok${_r} $*"; }
warn() { printf '%s\n' "${_ylw}warning${_r}: $*" >&2; }
err()  { printf '%s\n' "${_red}error${_r}: $*" >&2; exit 1; }

usage() {
    cat <<EOF
${_b}veil installer${_r} — fetch prebuilt binaries and get a node running.

USAGE:
    install.sh [OPTIONS]

OPTIONS:
    --components <list>   Comma-separated subset to install.
                          Choices: veil-cli, ogate, oproxy-client, oproxy-server
                          (default: veil-cli)
    --all                 Install every binary (node + ogate + oproxy client/server)
    --version <X.Y.Z>     Install a specific release (default: latest)
    --prefix <dir>        Install into <dir>/bin (e.g. /usr/local) instead of
                          ~/.veil/bin. Use for system-wide / server installs.
    --bin-dir <dir>       Install binaries straight into <dir> (overrides --prefix).
    --libc <musl|gnu>     Linux only: pick the libc flavour
                          (default: musl — a static binary that runs on any distro).
    --no-modify-path      Do not touch your shell profile / PATH.
    --quickstart          After install, interactively init + start a node.
    --no-quickstart       Never prompt; just print the next-steps guide.
    -y, --yes             Assume "yes" to prompts (non-interactive).
    --no-verify           Skip sha256 verification (NOT recommended).
    -h, --help            Show this help.

ENVIRONMENT:
    VEIL_REPO          owner/repo to download from (default: ${REPO})
    VEIL_HOME          base dir (default: ~/.veil)

EXAMPLES:
    install.sh
    install.sh --all
    install.sh --components ogate,oproxy-server --prefix /usr/local
    install.sh --version 1.4.0 --no-modify-path --yes
EOF
}

# ── Parse flags ─────────────────────────────────────────────────────────────
while [ $# -gt 0 ]; do
    case "$1" in
        --components) COMPONENTS="${2:?--components needs a value}"; shift 2 ;;
        --components=*) COMPONENTS="${1#*=}"; shift ;;
        --all) COMPONENTS="$ALL_COMPONENTS"; shift ;;
        --version) REQ_VERSION="${2:?--version needs a value}"; shift 2 ;;
        --version=*) REQ_VERSION="${1#*=}"; shift ;;
        --prefix) PREFIX="${2:?--prefix needs a value}"; shift 2 ;;
        --prefix=*) PREFIX="${1#*=}"; shift ;;
        --bin-dir) BIN_DIR="${2:?--bin-dir needs a value}"; shift 2 ;;
        --bin-dir=*) BIN_DIR="${1#*=}"; shift ;;
        --libc) LIBC="${2:?--libc needs a value}"; shift 2 ;;
        --libc=*) LIBC="${1#*=}"; shift ;;
        --no-modify-path) MODIFY_PATH=0; shift ;;
        --quickstart) QUICKSTART="yes"; shift ;;
        --no-quickstart) QUICKSTART="no"; shift ;;
        -y|--yes) ASSUME_YES=1; shift ;;
        --no-verify) NO_VERIFY=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) err "unknown option '$1' (try --help)" ;;
    esac
done

# Normalise the components list (commas/spaces -> spaces) and validate.
COMPONENTS="$(printf '%s' "$COMPONENTS" | tr ',' ' ')"
for c in $COMPONENTS; do
    case " $ALL_COMPONENTS " in
        *" $c "*) : ;;
        *) err "unknown component '$c' (choices: $ALL_COMPONENTS)" ;;
    esac
done
[ -n "$COMPONENTS" ] || err "no components selected"

# Resolve install dir: --bin-dir > --prefix/bin > ~/.veil/bin
if [ -z "$BIN_DIR" ]; then
    if [ -n "$PREFIX" ]; then BIN_DIR="$PREFIX/bin"; else BIN_DIR="$VEIL_HOME/bin"; fi
fi

# ── Tool detection ──────────────────────────────────────────────────────────
have() { command -v "$1" >/dev/null 2>&1; }
need() { have "$1" || err "required tool '$1' not found in PATH"; }

# Downloader: curl preferred, wget fallback. fetch <url> <out-file>
DL=""
if have curl; then DL="curl"; elif have wget; then DL="wget"; else
    err "need either curl or wget installed"
fi
fetch() { # <url> <dest>
    if [ "$DL" = curl ]; then
        curl --proto '=https' --tlsv1.2 -fsSL "$1" -o "$2"
    else
        wget --https-only -q "$1" -O "$2"
    fi
}
fetch_stdout() { # <url>  (prints body; used for the releases API)
    if [ "$DL" = curl ]; then
        curl --proto '=https' --tlsv1.2 -fsSL "$1"
    else
        wget --https-only -q "$1" -O -
    fi
}

# sha256 of a file -> stdout (sha256sum | shasum | openssl, whichever exists)
sha256_of() { # <file>
    if have sha256sum; then sha256sum "$1" | awk '{print $1}'
    elif have shasum; then shasum -a 256 "$1" | awk '{print $1}'
    elif have openssl; then openssl dgst -sha256 "$1" | awk '{print $NF}'
    else err "no sha256 tool (need sha256sum, shasum, or openssl)"; fi
}

# ── Detect platform -> Rust target triple ───────────────────────────────────
detect_triple() {
    _os="$(uname -s)"; _arch="$(uname -m)"
    case "$_arch" in
        x86_64|amd64) _arch=x86_64 ;;
        aarch64|arm64) _arch=aarch64 ;;
        *) err "unsupported CPU architecture '$_arch'" ;;
    esac
    case "$_os" in
        Linux)
            # Both x86_64 and aarch64 publish musl (static — runs on any distro,
            # no glibc version dependency) and gnu builds. Default to musl.
            _flavour="$LIBC"
            [ "$_flavour" = auto ] && _flavour=musl
            case "$_flavour" in
                musl) TRIPLE="${_arch}-unknown-linux-musl" ;;
                gnu)  TRIPLE="${_arch}-unknown-linux-gnu" ;;
                *) err "--libc must be 'musl' or 'gnu'" ;;
            esac
            ;;
        Darwin)
            if [ "$_arch" = aarch64 ]; then
                TRIPLE="aarch64-apple-darwin"
            else
                err "no prebuilt binary for Intel macOS (x86_64-apple-darwin).
       Options: run on Apple Silicon, or build from source —
       git clone https://github.com/${REPO} && cargo build --release
       (see docs/en/install.md → 'Build from source')."
            fi
            ;;
        *)
            err "unsupported OS '$_os'. On Windows use install.ps1 (PowerShell):
       irm https://raw.githubusercontent.com/${REPO}/master/scripts/install.ps1 | iex"
            ;;
    esac
}

# ── Resolve version -> release tag ──────────────────────────────────────────
resolve_tag() {
    if [ "$REQ_VERSION" = latest ]; then
        say "resolving latest release of ${_b}${REPO}${_r} ..."
        _api="https://api.github.com/repos/${REPO}/releases/latest"
        # Parse "tag_name": "vX.Y.Z" without requiring jq.
        TAG="$(fetch_stdout "$_api" 2>/dev/null \
            | grep -m1 '"tag_name"' \
            | sed 's/.*"tag_name"[^"]*"\([^"]*\)".*/\1/')" || true
        [ -n "${TAG:-}" ] || err "could not determine the latest release.
       The project may not have published a release yet. Retry with an
       explicit tag: install.sh --version X.Y.Z
       (releases: https://github.com/${REPO}/releases)"
    else
        # Accept both '1.2.3' and 'v1.2.3'.
        TAG="v${REQ_VERSION#v}"
    fi
}

# ── Download + verify one component ─────────────────────────────────────────
install_component() { # <bin-name>
    _bin="$1"
    _asset="${_bin}-${TRIPLE}"
    _base="https://github.com/${REPO}/releases/download/${TAG}"
    _url="${_base}/${_asset}"
    _out="${TMP}/${_bin}"

    info "downloading ${_b}${_asset}${_r}"
    fetch "$_url" "$_out" || err "download failed: $_url
       (is component '${_bin}' published for ${TRIPLE} in ${TAG}?)"

    if [ "$NO_VERIFY" -eq 0 ]; then
        # sha256-<triple>.txt lists the BARE bin names (veil-cli, ogate, ...).
        # FAIL-CLOSED (supply-chain): without --no-verify, a missing manifest OR
        # a missing entry for this binary is a HARD ERROR. Pre-fix both cases
        # only warned and continued, so a binary served without (or stripped of)
        # its sha manifest installed unverified. Pass --no-verify to opt out.
        if [ ! -f "${TMP}/sha256.txt" ]; then
            fetch "${_base}/sha256-${TRIPLE}.txt" "${TMP}/sha256.txt" \
                || err "no sha256-${TRIPLE}.txt published — refusing to install
       an unverified ${_bin}. Re-run with --no-verify to override."
        fi
        _want="$(awk -v n="$_bin" '$2==n{print $1}' "${TMP}/sha256.txt" | head -n1)"
        if [ -z "$_want" ]; then
            err "${_bin} not listed in sha256-${TRIPLE}.txt — refusing to install
       an unverified binary. Re-run with --no-verify to override."
        fi
        _got="$(sha256_of "$_out")"
        [ "$_want" = "$_got" ] || err "sha256 MISMATCH for ${_bin}!
       expected $_want
       got      $_got
       Aborting — do not run this binary."
        ok "${_bin} sha256 verified"
    fi

    mkdir -p "$BIN_DIR"
    install -m 0755 "$_out" "${BIN_DIR}/${_bin}" 2>/dev/null \
        || { cp "$_out" "${BIN_DIR}/${_bin}" && chmod 0755 "${BIN_DIR}/${_bin}"; }
    ok "installed ${_b}${_bin}${_r} -> ${BIN_DIR}/${_bin}"
}

# ── PATH setup (rustup-style env file + profile hook) ───────────────────────
write_env_file() {
    # Only meaningful for the default ~/.veil layout; for a custom --prefix
    # like /usr/local/bin the dir is usually already on PATH.
    ENV_FILE="$VEIL_HOME/env"
    mkdir -p "$VEIL_HOME"
    cat > "$ENV_FILE" <<EOF
#!/bin/sh
# Adds veil binaries to PATH. Sourced from your shell profile.
case ":\${PATH}:" in
    *:"${BIN_DIR}":*) ;;
    *) export PATH="${BIN_DIR}:\${PATH}" ;;
esac
EOF
}

add_to_profile() {
    [ "$MODIFY_PATH" -eq 1 ] || return 0
    case ":${PATH}:" in *:"$BIN_DIR":*) return 0 ;; esac  # already on PATH
    write_env_file
    _line=". \"$VEIL_HOME/env\""
    _added=""
    for _rc in "$HOME/.profile" "$HOME/.bashrc" "$HOME/.zshrc"; do
        [ -e "$_rc" ] || { [ "$_rc" = "$HOME/.profile" ] || continue; }
        if [ ! -e "$_rc" ] || ! grep -qF "$VEIL_HOME/env" "$_rc" 2>/dev/null; then
            printf '\n# veil\n%s\n' "$_line" >> "$_rc"
            _added="$_added $_rc"
        fi
    done
    [ -n "$_added" ] && info "added PATH hook to:${_added}"
    PATH="${BIN_DIR}:${PATH}"; export PATH
}

# ── Post-install guidance ───────────────────────────────────────────────────
selected() { case " $COMPONENTS " in *" $1 "*) return 0 ;; *) return 1 ;; esac; }

print_guide() {
    printf '\n%s\n' "${_grn}${_b}✓ veil installed.${_r}"
    printf '%s\n' "${_dim}binaries in ${BIN_DIR}${_r}"

    # Make sure the tools are reachable in THIS shell.
    if ! command -v veil-cli >/dev/null 2>&1 && selected veil-cli; then
        printf '\n%s\n' "${_b}1) Put veil on your PATH${_r} (this shell):"
        if [ -f "$VEIL_HOME/env" ]; then
            info "${_cyn}. \"$VEIL_HOME/env\"${_r}     ${_dim}# or just open a new terminal${_r}"
        else
            info "${_cyn}export PATH=\"$BIN_DIR:\$PATH\"${_r}"
        fi
    fi

    if selected veil-cli; then
        cat <<EOF

${_b}2) Run a node (the 60-second path)${_r}
   ${_cyn}veil-cli config init${_r}        ${_dim}# fresh identity + config${_r}
   ${_cyn}veil-cli node run${_r}           ${_dim}# start in the background${_r}
   ${_cyn}veil-cli node show${_r}          ${_dim}# node id, uptime, peers${_r}
   ${_cyn}veil-cli node stop${_r}          ${_dim}# stop it${_r}

${_b}   Pick your role${_r}
   • ${_b}Client / leaf${_r} (default) — connects out, no public address:
       ${_cyn}veil-cli config init --profile mobile${_r}   ${_dim}# battery-aware leaf${_r}
   • ${_b}Server / relay${_r} — public listener others bootstrap from:
       ${_cyn}veil-cli config init --profile censorship-target --difficulty 24${_r}
       ${_dim}# binds wss://0.0.0.0:443; edit the config, open the port, then \`node run\`.${_r}
       ${_dim}# For a hardened systemd service + dedicated user, see${_r}
       ${_dim}#   scripts/install-bootstrap.sh  (build-from-source, root).${_r}
EOF
    fi

    if selected ogate; then
        cat <<EOF

${_b}ogate${_r} — route IP traffic over the veil (server-side, needs TUN):
   ${_cyn}ogate gen-config -o ogate.toml${_r}    ${_dim}# fill in network + peers + virtual IPs${_r}
   ${_cyn}sudo ogate up --config ogate.toml${_r}  ${_dim}# needs CAP_NET_ADMIN / root for the TUN${_r}
   ${_dim}docs: docs/en/ogate.md${_r}
EOF
    fi

    if selected oproxy-client; then
        cat <<EOF

${_b}oproxy-client${_r} — local SOCKS5/HTTP proxy into the veil:
   ${_cyn}oproxy-client --gen-config > oproxy-client.toml${_r}  ${_dim}# set server_node_id + listeners${_r}
   ${_cyn}oproxy-client --config oproxy-client.toml${_r}
   ${_dim}docs: docs/en/oproxy.md${_r}
EOF
    fi

    if selected oproxy-server; then
        cat <<EOF

${_b}oproxy-server${_r} — veil exit / proxy server:
   ${_cyn}oproxy-server --gen-config > oproxy-server.toml${_r}
   ${_cyn}oproxy-server --config oproxy-server.toml${_r}
   ${_dim}docs: docs/en/oproxy.md${_r}
EOF
    fi

    cat <<EOF

${_b}Docs & help${_r}
   ${_cyn}veil-cli --help${_r} · ${_cyn}veil-cli <cmd> --help${_r}
   Full guide:  https://github.com/${REPO}/blob/master/docs/en/install.md
   Uninstall:   rm -rf "$VEIL_HOME"  (and remove the PATH line from your shell profile)
EOF
}

# Optional: actually init + start a node for a first-time user.
maybe_quickstart() {
    selected veil-cli || return 0
    [ "$QUICKSTART" = no ] && return 0
    _do=0
    if [ "$QUICKSTART" = yes ] || [ "$ASSUME_YES" -eq 1 ]; then
        _do=1
    elif [ -t 0 ]; then
        printf '\n%s' "${_b}Initialise and start a node now? [y/N] ${_r}"
        read -r _ans 2>/dev/null || _ans=""
        case "$_ans" in y|Y|yes|YES) _do=1 ;; esac
    fi
    [ "$_do" -eq 1 ] || return 0

    CLI="${BIN_DIR}/veil-cli"
    say "initialising node config ..."
    if "$CLI" config locate >/dev/null 2>&1 && "$CLI" config show >/dev/null 2>&1; then
        info "config already exists — skipping init (use 'veil-cli config init --force' to recreate)"
    else
        "$CLI" config init || { warn "config init failed; run it yourself later"; return 0; }
    fi
    say "starting node in the background ..."
    "$CLI" node run || { warn "node run failed; check 'veil-cli node health'"; return 0; }
    sleep 2
    "$CLI" node show 2>/dev/null || true
    ok "node is up. Stop it with: veil-cli node stop"
}

# ── Main ────────────────────────────────────────────────────────────────────
main() {
    say "installer starting (repo ${_b}${REPO}${_r})"
    detect_triple
    info "platform: ${_b}${TRIPLE}${_r}"
    resolve_tag
    info "release:  ${_b}${TAG}${_r}"
    info "target:   ${_b}${BIN_DIR}${_r}"
    info "install:  ${_b}${COMPONENTS}${_r}"

    TMP="$(mktemp -d 2>/dev/null || mktemp -d -t veil)"
    trap 'rm -rf "$TMP"' EXIT INT TERM

    for c in $COMPONENTS; do install_component "$c"; done
    add_to_profile
    print_guide
    maybe_quickstart
}

main
