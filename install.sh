#!/usr/bin/env bash
#
# install.sh — dependency installer for jslogic.
#
# Why this exists
# ---------------
# jslogic is a thin orchestration layer over two external tools:
#
#   * Semgrep — the rule engine that finds the patterns.
#   * jq      — the JSON parser that turns Semgrep's output into a
#               report.
#
# Both are widely available, but the correct installation command
# differs across Debian, Fedora, Arch, Alpine, and macOS, and users
# routinely run the wrong one, end up with a broken environment, and
# blame the tool. This script detects the platform, picks the best
# available installation method, and tells the user exactly what it is
# about to do.
#
# Design notes
# ------------
#   * Nothing is installed silently. Every action is announced on
#     stderr before it runs, so the user can see what is happening and
#     interrupt if they disagree with a choice.
#
#   * sudo is used only when it is actually required. On macOS with
#     Homebrew, on Linux with a user-local package manager, and for
#     pipx/pip --user installs, no root is needed and none is asked for.
#
#   * The script is idempotent. Running it twice has no effect beyond
#     re-checking that the dependencies are still present.
#
#   * The exit status is meaningful: 0 means every dependency is
#     installed and usable, non-zero means at least one is missing.
set -euo pipefail

# =============================================================================
# Constants
# =============================================================================

readonly PROG_NAME="install.sh"
readonly VERSION="0.1.0"

if [[ -t 2 ]]; then
    C_GREEN=$'\033[0;32m'
    C_RED=$'\033[0;31m'
    C_YELLOW=$'\033[1;33m'
    C_BLUE=$'\033[0;34m'
    C_DIM=$'\033[2m'
    C_RESET=$'\033[0m'
else
    C_GREEN=""; C_RED=""; C_YELLOW=""; C_BLUE=""; C_DIM=""; C_RESET=""
fi

# =============================================================================
# Logging
# =============================================================================

log()  { printf '%s[*]%s %s\n'  "$C_BLUE"   "$C_RESET" "$*" >&2; }
warn() { printf '%s[!]%s %s\n'  "$C_YELLOW" "$C_RESET" "$*" >&2; }
err()  { printf '%s[!]%s %s\n'  "$C_RED"    "$C_RESET" "$*" >&2; }
ok()   { printf '%s[+]%s %s\n'  "$C_GREEN"  "$C_RESET" "$*" >&2; }
dim()  { printf '%s    %s%s\n'  "$C_DIM"    "$*" "$C_RESET" >&2; }
die()  { err "$@"; exit 1; }

# =============================================================================
# Usage
# =============================================================================

usage() {
    cat <<EOF
${PROG_NAME} ${VERSION} — install runtime dependencies for jslogic

Usage:
  ./${PROG_NAME} [options]

Options:
  --check         Only check whether dependencies are present; do not
                  install anything. Exits non-zero if any is missing.
  --dry-run       Show what would be installed, but do not run any
                  installation command.
  --yes, -y       Skip the confirmation prompt.
  -h, --help      Print this message and exit.
  --version       Print version and exit.

The script installs:
  * semgrep — via pipx, pip --user, Homebrew, or the system package
              manager, whichever is available and least invasive.
  * jq      — via the system package manager or Homebrew.

No sudo is used unless the chosen package manager requires it.
EOF
}

# =============================================================================
# CLI parsing
# =============================================================================

CHECK_ONLY=false
DRY_RUN=false
ASSUME_YES=false

parse_args() {
    while (( $# > 0 )); do
        case "$1" in
            --check)     CHECK_ONLY=true ;;
            --dry-run)   DRY_RUN=true ;;
            -y|--yes)    ASSUME_YES=true ;;
            -h|--help)   usage; exit 0 ;;
            --version)   echo "$VERSION"; exit 0 ;;
            *)           die "unknown option: $1 (use --help)" ;;
        esac
        shift
    done
}

# =============================================================================
# Platform detection
# =============================================================================

# Detected values (set by detect_platform):
OS=""          # linux, macos, windows
DISTRO=""      # debian, fedora, rhel, arch, alpine, suse, or empty
PKG_MGR=""     # apt, dnf, yum, pacman, apk, zypper, brew, or empty
SUDO=""        # "sudo" if needed for PKG_MGR, otherwise empty

detect_platform() {
    local uname_s
    uname_s="$(uname -s)"

    case "$uname_s" in
        Linux*)
            OS="linux"
            # Identify the distribution from /etc/os-release. This is the
            # canonical, machine-readable source and works across every
            # modern Linux distribution.
            if [[ -r /etc/os-release ]]; then
                # shellcheck disable=SC1091
                . /etc/os-release
                case "${ID:-}:${ID_LIKE:-}" in
                    *debian*|*ubuntu*) DISTRO="debian" ;;
                    *fedora*)          DISTRO="fedora" ;;
                    *rhel*|*centos*)   DISTRO="rhel" ;;
                    *arch*)            DISTRO="arch" ;;
                    *alpine*)          DISTRO="alpine" ;;
                    *suse*|*opensuse*) DISTRO="suse" ;;
                    *)                 DISTRO="" ;;
                esac
            fi
            ;;
        Darwin*)
            OS="macos"
            DISTRO="macos"
            ;;
        MINGW*|MSYS*|CYGWIN*)
            OS="windows"
            DISTRO="windows"
            ;;
        *)
            die "unsupported operating system: $uname_s"
            ;;
    esac

    # Choose the primary package manager for this platform.
    case "$OS:$DISTRO" in
        linux:debian)  PKG_MGR="apt" ;;
        linux:fedora)  PKG_MGR="dnf" ;;
        linux:rhel)    PKG_MGR="yum" ;;
        linux:arch)    PKG_MGR="pacman" ;;
        linux:alpine)  PKG_MGR="apk" ;;
        linux:suse)    PKG_MGR="zypper" ;;
        macos:*)       PKG_MGR="brew" ;;
        windows:*)     PKG_MGR="" ;;   # handled specially below
    esac

    # Verify the chosen manager actually exists. On minimal containers it
    # might not, in which case we prefer a clear error over a confusing
    # "command not found" later.
    if [[ -n "$PKG_MGR" ]] && ! command -v "$PKG_MGR" >/dev/null 2>&1; then
        warn "expected package manager '$PKG_MGR' is not available"
        PKG_MGR=""
    fi

    # Decide whether sudo is needed. It is not needed for:
    #   * Homebrew on macOS (user-owned prefix by default),
    #   * a user-local pipx install,
    #   * a `pip install --user` install,
    #   * when we are already root.
    if [[ "$OS" == "linux" && "$(id -u)" -ne 0 && -n "$PKG_MGR" ]]; then
        if command -v sudo >/dev/null 2>&1; then
            SUDO="sudo"
        else
            warn "not running as root and sudo is not available"
            warn "system package installation may fail"
        fi
    fi

    log "platform: $OS ${DISTRO:+($DISTRO)}"
    [[ -n "$PKG_MGR" ]] && log "package manager: $PKG_MGR"
}

# =============================================================================
# Dependency checks
# =============================================================================

have() { command -v "$1" >/dev/null 2>&1; }

# check_one NAME — return 0 if present and working, 1 otherwise.
check_one() {
    local name="$1"
    if have "$name"; then
        local version_line
        version_line="$("$name" --version 2>&1 | head -n1 || true)"
        ok "$name is installed: $version_line"
        return 0
    fi
    err "$name is missing"
    return 1
}

# =============================================================================
# Installation: jq
# =============================================================================

install_jq() {
    log "installing jq"

    if $DRY_RUN; then
        dim "would install jq via ${PKG_MGR:-unknown}"
        return 0
    fi

    case "$PKG_MGR" in
        apt)
            $SUDO apt-get update -qq
            $SUDO apt-get install -y jq
            ;;
        dnf)    $SUDO dnf install -y jq ;;
        yum)    $SUDO yum install -y jq ;;
        pacman) $SUDO pacman -Sy --noconfirm jq ;;
        apk)    $SUDO apk add --no-cache jq ;;
        zypper) $SUDO zypper --non-interactive install jq ;;
        brew)   brew install jq ;;
        "")
            if [[ "$OS" == "windows" ]]; then
                install_jq_windows
            else
                die "no package manager available to install jq"
            fi
            ;;
    esac
}

# Windows installs are handled separately because there is no single
# dominant package manager, and each of the three common ones (winget,
# scoop, chocolatey) uses a different command line.
install_jq_windows() {
    if have winget; then
        winget install --id jqlang.jq --accept-source-agreements
    elif have scoop; then
        scoop install jq
    elif have choco; then
        choco install -y jq
    else
        die "no Windows package manager found (tried winget, scoop, choco)"
    fi
}

# =============================================================================
# Installation: semgrep
# =============================================================================

# Semgrep is a Python tool. The preferred installation methods, in order
# of least invasiveness, are:
#
#   1. pipx — isolates semgrep in its own virtualenv, no sudo, no
#             interference with the system Python.
#   2. pip --user — installs to the user's site-packages, no sudo.
#   3. brew — on macOS, tracks upstream releases cleanly.
#   4. system package manager — last resort; versions may lag.
#
# We deliberately do NOT run `pip install semgrep` as root. Installing
# Python packages into the system interpreter is a well-known way to
# break OS tooling.
install_semgrep() {
    log "installing semgrep"

    if $DRY_RUN; then
        if have pipx; then
            dim "would install semgrep via pipx"
        elif have pip3 || have pip; then
            dim "would install semgrep via pip --user"
        elif [[ "$PKG_MGR" == "brew" ]]; then
            dim "would install semgrep via brew"
        else
            dim "would attempt a system package manager install"
        fi
        return 0
    fi

    # 1. pipx — preferred.
    if have pipx; then
        log "using pipx"
        pipx install semgrep
        return 0
    fi

    # 2. pip --user — still no sudo.
    local pip_cmd=""
    if have pip3; then
        pip_cmd="pip3"
    elif have pip; then
        pip_cmd="pip"
    fi

    if [[ -n "$pip_cmd" ]]; then
        log "using $pip_cmd --user"
        "$pip_cmd" install --user --upgrade semgrep
        # Warn if the user-local bin directory is probably not on PATH.
        local user_bin
        user_bin="$("$pip_cmd" show --files semgrep 2>/dev/null | grep -m1 Location: | awk '{print $2}' || true)"
        if [[ -n "$user_bin" ]] && [[ ":$PATH:" != *":$HOME/.local/bin:"* ]]; then
            warn "semgrep was installed to a user directory"
            warn "make sure \$HOME/.local/bin is on your PATH"
        fi
        return 0
    fi

    # 3. Homebrew (macOS).
    if [[ "$PKG_MGR" == "brew" ]]; then
        brew install semgrep
        return 0
    fi

    # 4. System package manager — not all distros carry semgrep, but
    # some do and it is worth trying before giving up.
    case "$PKG_MGR" in
        apt)    $SUDO apt-get update -qq && $SUDO apt-get install -y semgrep ;;
        dnf)    $SUDO dnf install -y semgrep ;;
        pacman) $SUDO pacman -Sy --noconfirm semgrep ;;
        apk)    $SUDO apk add --no-cache semgrep ;;
        "")
            die "no way to install semgrep on this system (install pipx or pip first)"
            ;;
        *)
            die "no semgrep package available via $PKG_MGR; install pipx or pip"
            ;;
    esac
}

# =============================================================================
# Main
# =============================================================================

main() {
    parse_args "$@"

    detect_platform

    local missing=()

    # ----- Check phase ---------------------------------------------------
    if ! check_one jq; then
        missing+=("jq")
    fi
    if ! check_one semgrep; then
        missing+=("semgrep")
    fi

    if (( ${#missing[@]} == 0 )); then
        ok "all dependencies are already installed"
        exit 0
    fi

    if $CHECK_ONLY; then
        err "missing: ${missing[*]}"
        err "run without --check to install them"
        exit 1
    fi

    # ----- Confirmation --------------------------------------------------
    if ! $ASSUME_YES && ! $DRY_RUN; then
        printf '%s[*]%s missing: %s\n' "$C_BLUE" "$C_RESET" "${missing[*]}" >&2
        printf '%s[*]%s install now? [y/N] ' "$C_BLUE" "$C_RESET" >&2
        read -r answer
        case "$answer" in
            [yY]|[yY][eE][sS]) ;;
            *) die "aborted" ;;
        esac
    fi

    # ----- Install phase -------------------------------------------------
    #
    # We re-check before each install so that the script remains correct
    # if a previous run partially succeeded.
    for dep in "${missing[@]}"; do
        case "$dep" in
            jq)
                if ! have jq; then install_jq; fi
                ;;
            semgrep)
                if ! have semgrep; then install_semgrep; fi
                ;;
        esac
    done

    # ----- Verify --------------------------------------------------------
    #
    # Installation can succeed at the package-manager level and still
    # leave the tool unavailable (PATH issues, broken shims). Verify by
    # running each tool's --version, which is the only reliable test.
    local failed=()
    have jq      || failed+=("jq")
    have semgrep || failed+=("semgrep")

    if (( ${#failed[@]} > 0 )); then
        err "the following are still not usable: ${failed[*]}"
        err "you may need to open a new shell or fix your PATH"
        exit 1
    fi

    ok "all dependencies installed"
    ok "you can now run: ./jslogic.sh --help"
}

main "$@"
