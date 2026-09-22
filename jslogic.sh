#!/usr/bin/env bash
#
# jslogic — security-relevant logic scanner for JavaScript / TypeScript.
#
# Why this exists
# ---------------
# Modern SPA bundles contain thousands of small logic fragments, and the
# security-relevant ones (URL validation, redirect sinks, fetch calls,
# regex-based sanitizers) are scattered across minified or bundled code.
# Reading them by hand is impractical once a bundle exceeds a few
# hundred KB.
#
# jslogic uses Semgrep as a rule engine to find those fragments, then
# extracts the surrounding source context so a human can review them
# with minimal noise. The output is a Markdown-friendly report suitable
# for a bug-bounty notes file, a pentest deliverable, or a bug report
# appendix.
#
# Two scan profiles are provided:
#
#   * normal (default) — the focused rule set. Fast, low false-positive
#     rate, targets the routing/validation/network logic that most often
#     leads to real findings.
#
#   * full (-f) — the focused rule set plus a catch-all rule that
#     surfaces every regex literal and regex API call. Noisier, slower,
#     but useful when the goal is complete manual review of the regex
#     surface of an application.
#
# Design notes
# ------------
#   * The script is intentionally a shell script, not a compiled tool.
#     Its job is orchestration: run Semgrep, parse JSON, extract context.
#     Semgrep and jq do the heavy lifting.
#
#   * Findings are deduplicated by (file, line, rule) before context is
#     extracted. Semgrep occasionally reports the same logical finding
#     multiple times when a rule has overlapping patterns; without dedup
#     the report would contain the same code block three or four times.
#
#   * Paths are made absolute before being handed to Semgrep, so the
#     context extractor can open them regardless of the working
#     directory the script was invoked from.
#
#   * Ctrl-C aborts cleanly: the temporary JSON is removed, but the
#     partially written report is left in place so the user can inspect
#     what was found before the interruption.
set -euo pipefail

# =============================================================================
# Constants
# =============================================================================

readonly VERSION="0.2.0"
readonly PROG_NAME="jslogic"

# Where the script itself lives. Rule files are resolved relative to this
# directory, so the whole project can be copied or cloned anywhere without
# touching the script.
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly RULE_DIR="${SCRIPT_DIR}/rules"

# Default rule files. These can be overridden with -r.
readonly DEFAULT_RULE_FILE="${RULE_DIR}/routing-logic.yaml"
readonly FULL_RULE_FILE="${RULE_DIR}/routing-logic-full.yaml"

# Default number of context lines shown above and below each finding.
readonly DEFAULT_CONTEXT=4

# ANSI colors. Disabled automatically when stderr is not a TTY.
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
# Logging helpers
# =============================================================================

log()  { printf '%s[*]%s %s\n'  "$C_BLUE"   "$C_RESET" "$*" >&2; }
warn() { printf '%s[!]%s %s\n'  "$C_YELLOW" "$C_RESET" "$*" >&2; }
err()  { printf '%s[!]%s %s\n'  "$C_RED"    "$C_RESET" "$*" >&2; }
ok()   { printf '%s[+]%s %s\n'  "$C_GREEN"  "$C_RESET" "$*" >&2; }
die()  { err "$@"; exit 1; }

# =============================================================================
# Usage
# =============================================================================

usage() {
    cat <<EOF
${PROG_NAME} ${VERSION} — security logic scanner for JS/TS bundles

Usage:
  ${PROG_NAME} [options] <path-to-js-directory>

Modes:
  (default)     focused rule set (routing-logic.yaml)
  -f            full rule set, includes catch-all regex discovery
                (routing-logic-full.yaml)

Options:
  -f            Enable full scan mode.
  -o FILE       Write the report to FILE.
                Default: ./jslogic__s.txt (or ./jslogic-full__s.txt with -f).
  -r FILE       Use a custom Semgrep rule file (overrides -f).
  -c N          Number of context lines to show above and below each
                finding (default: ${DEFAULT_CONTEXT}).
  -s LEVEL      Only report findings at this severity or above.
                LEVEL is one of: INFO, WARNING, ERROR (default: INFO).
  -m N          Stop after N findings. Useful when a rule is too noisy.
  --no-context  Print only the finding list, not the surrounding code.
  -q            Quiet. Suppress progress; only errors are printed.
  -v            Verbose. Print every file as it is processed.
  --version     Print version and exit.
  -h, --help    Print this message and exit.

Examples:
  ${PROG_NAME} ./target_js_files
  ${PROG_NAME} -f ./target_js_files
  ${PROG_NAME} -o report.md -c 8 ./target_js_files
  ${PROG_NAME} -s ERROR -m 50 ./target_js_files
EOF
}

# =============================================================================
# Cleanup
# =============================================================================

TEMP_JSON=""

cleanup() {
    # Only remove the temp file if we created one. The report itself is
    # intentionally preserved even on interrupt, so the user can review
    # whatever was already extracted.
    if [[ -n "$TEMP_JSON" && -f "$TEMP_JSON" ]]; then
        rm -f "$TEMP_JSON"
    fi
}
trap cleanup EXIT

# On SIGINT we exit through the normal trap so the temp file is cleaned.
trap 'echo; err "interrupted"; exit 130' INT TERM

# =============================================================================
# Dependency check
# =============================================================================

check_dependencies() {
    local missing=()
    command -v semgrep >/dev/null 2>&1 || missing+=("semgrep")
    command -v jq      >/dev/null 2>&1 || missing+=("jq")

    if (( ${#missing[@]} > 0 )); then
        err "missing required tool(s): ${missing[*]}"
        err "install with: pip install semgrep  /  apt install jq"
        exit 1
    fi

    if [[ ! -f "$RULE_FILE" ]]; then
        die "rule file not found: $RULE_FILE"
    fi
}

# =============================================================================
# CLI parsing
# =============================================================================

FULL_SCAN=false
QUIET=false
VERBOSE=false
NO_CONTEXT=false
CONTEXT="$DEFAULT_CONTEXT"
SEVERITY_MIN="INFO"
MAX_FINDINGS=0
RULE_FILE=""
OUTPUT_FILE=""

parse_args() {
    local opt
    while getopts ":fo:r:c:s:m:qvh-:" opt; do
        case "$opt" in
            f) FULL_SCAN=true ;;
            o) OUTPUT_FILE="$OPTARG" ;;
            r) RULE_FILE="$OPTARG" ;;
            c) CONTEXT="$OPTARG" ;;
            s) SEVERITY_MIN="$OPTARG" ;;
            m) MAX_FINDINGS="$OPTARG" ;;
            q) QUIET=true ;;
            v) VERBOSE=true ;;
            h) usage; exit 0 ;;
            -)
                # Long options: only --no-context, --version, --help.
                case "${OPTARG}" in
                    no-context) NO_CONTEXT=true ;;
                    version)    echo "$VERSION"; exit 0 ;;
                    help)       usage; exit 0 ;;
                    *)          die "unknown option: --$OPTARG" ;;
                esac
                ;;
            :) die "option -$OPTARG requires an argument" ;;
            \?) die "unknown option: -$OPTARG" ;;
        esac
    done
    shift $((OPTIND - 1))

    if (( $# != 1 )); then
        usage
        exit 1
    fi

    TARGET_DIR="$1"
}

# =============================================================================
# Main
# =============================================================================

main() {
    parse_args "$@"

    # ----- Resolve rule file and output path -----------------------------
    #
    # Precedence for rule file:
    #   1. -r FILE       (explicit override)
    #   2. -f            → full rule set
    #   3. otherwise     → default (focused) rule set
    if [[ -z "$RULE_FILE" ]]; then
        if $FULL_SCAN; then
            RULE_FILE="$FULL_RULE_FILE"
        else
            RULE_FILE="$DEFAULT_RULE_FILE"
        fi
    fi

    # Output path: default is derived from mode.
    if [[ -z "$OUTPUT_FILE" ]]; then
        if $FULL_SCAN; then
            OUTPUT_FILE="$(pwd)/jslogic-full__s.txt"
        else
            OUTPUT_FILE="$(pwd)/jslogic__s.txt"
        fi
    fi

    # ----- Validate input directory --------------------------------------
    if [[ ! -d "$TARGET_DIR" ]]; then
        die "directory does not exist: $TARGET_DIR"
    fi
    # Make the path absolute so Semgrep reports absolute paths, which the
    # context extractor can then open from any working directory.
    TARGET_DIR="$(cd "$TARGET_DIR" && pwd)"

    check_dependencies

    # ----- Banner --------------------------------------------------------
    $QUIET || log "scanning $TARGET_DIR"
    $QUIET || log "rules: $(basename "$RULE_FILE")"
    $QUIET || log "output: $OUTPUT_FILE"
    if $FULL_SCAN && [[ -z "${RULE_FILE_OVERRIDE:-}" ]]; then
        $QUIET || warn "full scan mode enabled — expect higher noise"
    fi

    # ----- Run Semgrep ---------------------------------------------------
    #
    # We restrict to .js and .ts on purpose: HTML files inflate the run
    # time without adding much signal, and .map files are noisy in a way
    # that does not help a human reviewer. Users who need those can add
    # them by editing the include list below.
    TEMP_JSON="$(mktemp /tmp/jslogic.XXXXXX.json)"

    $QUIET || log "running semgrep..."
    if ! semgrep scan \
            --config "$RULE_FILE" \
            --include "*.js" \
            --include "*.ts" \
            --include "*.jsx" \
            --include "*.tsx" \
            --json \
            --quiet \
            "$TARGET_DIR" > "$TEMP_JSON" 2>/dev/null; then
        # semgrep returns non-zero on "findings present", not only on
        # error, so we must distinguish the two. If the JSON is empty or
        # invalid, the run genuinely failed.
        if ! jq -e '.results' "$TEMP_JSON" >/dev/null 2>&1; then
            die "semgrep failed; run without --quiet to see the error"
        fi
    fi

    # ----- Count and filter ----------------------------------------------
    local total
    total="$(jq '.results | length' "$TEMP_JSON")"

    if (( total == 0 )); then
        ok "scan complete — no findings"
        # Still create an empty report file so downstream tooling does not
        # trip over its absence.
        : > "$OUTPUT_FILE"
        exit 0
    fi

    # Severity ordering: INFO < WARNING < ERROR. Filter to the minimum
    # the user asked for. Numeric mapping keeps the jq expression simple.
    local sev_num
    case "$SEVERITY_MIN" in
        INFO)    sev_num=0 ;;
        WARNING) sev_num=1 ;;
        ERROR)   sev_num=2 ;;
        *)       die "invalid severity: $SEVERITY_MIN (use INFO, WARNING, ERROR)" ;;
    esac

    $QUIET || log "found $total finding(s); filtering at severity >= $SEVERITY_MIN"

    # ----- Extract findings ----------------------------------------------
    #
    # Format: TAB-separated (path, line, rule, severity). TSV is safer
    # than `|` because paths can contain pipes but essentially never
    # contain tabs.
    #
    # Findings are deduplicated by (path, line, rule) because Semgrep
    # sometimes reports the same logical hit twice when a rule's
    # `pattern-either` branches overlap.
    local findings
    findings="$(
        jq -r --argjson min "$sev_num" '
            def sev_num:
                if   . == "INFO"    then 0
                elif . == "WARNING" then 1
                elif . == "ERROR"   then 2
                else 0 end;

            [ .results[]
              | select((.extra.severity // "INFO" | sev_num) >= $min)
              | { path: .path,
                  line: .start.line,
                  rule: .check_id,
                  severity: (.extra.severity // "INFO") }
            ]
            | unique_by([.path, .line, .rule])
            | .[]
            | [.path, (.line | tostring), .rule, .severity] | @tsv
        ' "$TEMP_JSON"
    )"

    local kept
    kept="$(printf '%s\n' "$findings" | grep -c . || true)"
    kept="${kept:-0}"

    if (( kept == 0 )); then
        ok "no findings at severity >= $SEVERITY_MIN"
        : > "$OUTPUT_FILE"
        exit 0
    fi

    $QUIET || log "reporting $kept finding(s) after dedup"

    # ----- Write report --------------------------------------------------
    : > "$OUTPUT_FILE"

    local written=0
    local buf

    while IFS=$'\t' read -r file line rule severity; do
        [[ -z "$file" ]] && continue

        if (( MAX_FINDINGS > 0 && written >= MAX_FINDINGS )); then
            warn "reached -m limit of $MAX_FINDINGS; stopping"
            break
        fi

        # Compute the context window. Clamp the start at 1.
        local start=$(( line - CONTEXT ))
        (( start < 1 )) && start=1
        local end=$(( line + CONTEXT ))

        {
            echo "=================================================="
            echo "File:     $file"
            echo "Line:     $line"
            echo "Severity: $severity"
            echo "Rule:     $rule"
            echo "=================================================="
            if ! $NO_CONTEXT; then
                if [[ -r "$file" ]]; then
                    echo "\`\`\`javascript"
                    # -v is important here: awk must not interpret the
                    # values as part of its program.
                    awk -v s="$start" -v e="$end" 'NR>=s && NR<=e' "$file"
                    echo "\`\`\`"
                else
                    warn "cannot read source file: $file"
                    echo "(source file not readable)"
                fi
            fi
            echo
        } >> "$OUTPUT_FILE"

        written=$(( written + 1 ))
        if $VERBOSE; then
            log "  [$severity] $file:$line ($rule)"
        fi
    done <<< "$findings"

    ok "report written: $OUTPUT_FILE ($written finding(s))"
}

main "$@"
