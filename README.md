# jslogic

> Security logic scanner for JavaScript and TypeScript bundles.

`jslogic` is a focused scanner that finds security-relevant logic in
JS/TS code and extracts the surrounding context so a human can review it
quickly. It targets three categories that most often lead to real
findings during a client-side review:

- **Validation logic** — the checks that are supposed to reject bad
  input but often have a bypass.
- **DOM routing sinks** — the places where a value reaches the browser's
  navigation machinery. These are the direct XSS and open-redirect
  primitives.
- **Network request sinks** — the places where a value becomes the
  destination of an HTTP request. These are the client-side SSRF and
  path-traversal primitives.

The tool uses [Semgrep](https://semgrep.dev/) as its rule engine and `jq`
for report generation. The output is a Markdown-friendly text file with
each finding's source context, ready to drop into a notes file, a bug
report, or a pentest deliverable.

---

## Table of contents

- [Why](#why)
- [Features](#features)
- [Installation](#installation)
- [Quick start](#quick-start)
- [Usage](#usage)
- [Modes](#modes)
- [How it works](#how-it-works)
- [Rule anatomy](#rule-anatomy)
- [Output format](#output-format)
- [Examples](#examples)
- [Extending the rules](#extending-the-rules)
- [Performance](#performance)
- [Contributing](#contributing)

---

## Why

A modern SPA bundle contains thousands of small logic fragments. The
security-relevant ones — a `startsWith` check on a URL, a
`location.href =` assignment, a `fetch(userInput)` call — are buried
inside minified or bundled code, and the surrounding context that would
tell you whether they are exploitable is spread across a dozen lines.

Reading the whole bundle by hand is impractical. A grep for
`location.href` produces hundreds of hits with no way to tell which ones
matter. A general-purpose SAST tool produces a report so long that nobody
reads it.

`jslogic` takes the middle path: it looks for a **narrow set of
high-signal patterns**, restricts them to **variables whose names suggest
user-controllable input**, and presents each hit with the **surrounding
source context** so a reviewer can decide in seconds whether it is worth
chasing.

Typical uses:

- Client-side review during a web application pentest.
- Bug-bounty triage after collecting a target's JS bundles.
- Auditing a JS SDK or a library for open-redirect / SSRF primitives.
- Pre-engagement recon to identify where a target's validation lives.

---

## Features

- **Three categories of finding** — validation logic, DOM routing sinks,
  and network request sinks.
- **Variable-name filter** — every rule is restricted to variables whose
  names look like user input (`url`, `redirect`, `next`, `callback`,
  `api`, `path`, …). This is what keeps the report usable on a real
  bundle.
- **Two scan profiles** — a focused default profile and a `-f` full
  profile that adds a catch-all regex inventory.
- **Context extraction** — each finding is shown with N lines of
  surrounding code (default 4, configurable with `-c`).
- **Severity filtering** — `-s INFO|WARNING|ERROR` to cut noise.
- **Finding limit** — `-m N` to stop early when a rule is too noisy.
- **Deduplication** — the same logical hit is reported only once, even
  when Semgrep's `pattern-either` branches overlap.
- **Custom rules** — `-r FILE` to use your own Semgrep rule file.
- **Markdown-friendly output** — code blocks with language tags, ready
  for a report.
- **Interrupt-safe** — Ctrl-C cleans up the temp file but keeps the
  partial report.
- **Zero-config paths** — rules are resolved relative to the script, so
  the project works from anywhere.

---

## Installation

### 1. Install dependencies

```bash
./install.sh
```

The script detects the platform (Debian, Fedora, RHEL, Arch, Alpine,
SUSE, macOS, Windows via WSL/Git-Bash), picks the least invasive
installation method, and verifies the result. Options:

| Flag | Description |
|------|-------------|
| `--check` | Only check if dependencies are present; do not install. |
| `--dry-run` | Show what would be installed without running it. |
| `-y`, `--yes` | Skip the confirmation prompt. |

If you prefer to install manually:

- **Semgrep**: `pipx install semgrep` (recommended) or `pip install --user semgrep`.
- **jq**: use your platform's package manager
  (`apt install jq`, `dnf install jq`, `brew install jq`, …).

### 2. Make the scanner executable

```bash
chmod +x jslogic.sh
```

### 3. Verify

```bash
./jslogic.sh --help
```

### Requirements

- Bash 4.0 or newer.
- Semgrep (any recent version).
- jq 1.6 or newer.

The `install.sh` script handles all three on every mainstream platform.

---

## Quick start

```bash
# Scan a directory of JS files with the focused rule set.
./jslogic.sh ./target_js_files

# Full scan, with the catch-all regex inventory included.
./jslogic.sh -f ./target_js_files

# Only show ERROR-severity findings, up to 20.
./jslogic.sh -s ERROR -m 20 ./target_js_files

# Custom output path and larger context window.
./jslogic.sh -c 8 -o report.md ./target_js_files
```

---

## Usage

```
jslogic.sh [options] <path-to-js-directory>
```

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `-f` | off | Enable full scan mode (adds the catch-all regex rule). |
| `-o FILE` | `./jslogic__s.txt` or `./jslogic-full__s.txt` | Output report path. |
| `-r FILE` | *(mode-dependent)* | Use a custom Semgrep rule file. Overrides `-f`. |
| `-c N` | `4` | Number of context lines above and below each finding. |
| `-s LEVEL` | `INFO` | Minimum severity to report: `INFO`, `WARNING`, or `ERROR`. |
| `-m N` | `0` (unlimited) | Stop after N findings. |
| `--no-context` | off | Print only the finding list, not the surrounding code. |
| `-q` | off | Quiet. Suppress progress messages. |
| `-v` | off | Verbose. Log each finding as it is written. |
| `--version` | — | Print version and exit. |
| `-h`, `--help` | — | Print usage and exit. |

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | Scan completed. Report written (possibly empty). |
| 1 | Invalid arguments, missing dependency, or missing input directory. |
| 130 | Interrupted by the user (Ctrl-C). |

---

## Modes

### Focused mode (default)

Uses `rules/routing-logic.yaml`. Contains three rules covering the
validation, DOM-routing, and network-request categories. This is the
mode to run first: it is fast, low-noise, and targets the findings most
likely to be exploitable.

### Full mode (`-f`)

Uses `rules/routing-logic-full.yaml`. Adds two catch-all rules that
surface every regex literal and every regex API call in the codebase.

This is intentionally noisy. A medium-sized bundle produces hundreds of
regex hits, the vast majority of which are benign. The mode is useful
when the target has an unusual amount of custom regex-based validation,
or when you want a complete inventory rather than targeted findings.

---

## How it works

The pipeline has four stages.

### 1. Semgrep scan

Semgrep runs over every `.js`, `.ts`, `.jsx`, and `.tsx` file under the
target directory. HTML is excluded on purpose: it inflates the run time
without adding much signal, and the JS it contains is already covered
by the `src` attributes.

Semgrep's output is captured as JSON.

### 2. Filtering and deduplication

The JSON is filtered by severity and deduplicated by
`(file, line, rule)`. Deduplication matters because a rule with multiple
`pattern-either` branches can report the same logical hit more than once.

### 3. Context extraction

For each surviving finding, the script computes a window of
`±context` lines around the reported line, reads the file with `awk`,
and formats the result as a Markdown code block.

The window is clamped at line 1 so that findings near the top of a file
still produce a valid range.

### 4. Report assembly

Each finding is written to the output file with a banner, a metadata
block, and the code context. The result is a single text file that can
be reviewed top to bottom or grepped for specific rules.

---

## Rule anatomy

Every rule in `rules/routing-logic.yaml` follows the same shape:

```yaml
- id: jslogic-validation-logic
  languages: [javascript, typescript]
  severity: WARNING
  message: >-
    A routing-shaped variable is used in a check. ...
  patterns:
    - pattern-either:
        - pattern: $VAR.startsWith(...)
        - pattern: $VAR.includes(...)
        # ...
    - metavariable-regex:
        metavariable: $VAR
        regex: (?i).*(url|redirect|next|callback|...).*
```

The two halves work together:

- **`pattern-either`** describes *what the code does* — the shape of the
  operation that interests us.
- **`metavariable-regex`** describes *what the variable means* — the
  naming convention that suggests it carries user input.

Either half alone produces a useless report. The combination is what
makes the rule high-signal: a `.startsWith` call on a variable named
`url` or `redirect` or `next` is very likely to be a validation check
worth reading.

The variable-name list is deliberately broad because applications name
their parameters inconsistently. It includes `url`, `uri`, `redirect`,
`target`, `dest`, `destination`, `next`, `callback`, `path`, `href`,
`api`, `endpoint`, `route`, `page`, `file`, `src`, `link`, `query`,
`param`, `input`, `host`, `hostname`, `domain`, `site`, `return`.

---

## Output format

The report is plain text with a Markdown-friendly layout:

```
==================================================
File:     /abs/path/to/bundle.js
Line:     4127
Severity: ERROR
Rule:     jslogic-dom-routing-sink
==================================================
```javascript
    const target = new URLSearchParams(location.search).get("next");
    if (target) {
        location.href = target;
    }
```
```

Metadata is laid out one field per line so the file can be grepped:

```bash
grep '^Rule:'     report.txt | sort | uniq -c   # rule distribution
grep '^Severity:' report.txt | sort | uniq -c   # severity distribution
grep '^File:'     report.txt | sort | uniq -c   # files with most hits
```

---

## Examples

### 1. Standard focused scan

```bash
./jslogic.sh ./target_js_files
```

Writes `./jslogic__s.txt`.

### 2. Full scan with larger context

```bash
./jslogic.sh -f -c 10 ./target_js_files
```

Writes `./jslogic-full__s.txt` with 10 lines of context per finding.

### 3. Only the highest-severity findings, limit 20

```bash
./jslogic.sh -s ERROR -m 20 ./target_js_files
```

Useful when triaging a bundle for the first time and you want to see the
most likely exploitable hits first.

### 4. Just the finding list, no context

```bash
./jslogic.sh --no-context ./target_js_files | grep '^File:'
```

Produces a compact list of (file, line) pairs for use with an editor or
a spreadsheet.

### 5. Custom rule file

```bash
./jslogic.sh -r ./my-custom-rules.yaml ./target_js_files
```

### 6. In a pipeline with a fuzzer

```bash
./jslogic.sh --no-context ./target_js_files \
    | grep -oE '/[^ ]+\.js:[0-9]+' \
    | sort -u \
    | while read -r hit; do
          file="${hit%:*}"; line="${hit##*:}"
          sed -n "$((line-3)),$((line+3))p" "$file"
      done
```

### 7. Sanity check before running

```bash
./install.sh --check
```

Exits 0 if Semgrep and jq are both present, non-zero otherwise.

---

## Extending the rules

The rules are plain Semgrep YAML, so any Semgrep feature works. Adding a
new category of finding is a matter of copying an existing rule and
changing the pattern:

```yaml
  - id: jslogic-postmessage-sink
    languages: [javascript, typescript]
    severity: WARNING
    message: >-
      [Cross-Window Sink] A message is posted to a window whose origin
      is not verified. Potential XSS via postMessage.
    patterns:
      - pattern: |
          $WINDOW.postMessage($MSG, $ORIGIN, ...)
      - metavariable-regex:
          metavariable: $ORIGIN
          regex: (?i).*(\*|wildcard).*
```

Save it as `rules/extra.yaml`, then:

```bash
./jslogic.sh -r rules/extra.yaml ./target_js_files
```

To add a rule to the default profile, append it to
`rules/routing-logic.yaml`.

Two conventions keep the rules consistent:

1. Every rule id starts with `jslogic-`.
2. Every rule's message starts with a `[Category]` tag in brackets, so
   the report can be grepped by category.

---

## Performance

On a modern laptop with SSD storage, Semgrep processes roughly 1 MB of
minified JS per second per core. The context extraction stage adds a few
milliseconds per finding and is negligible in comparison.

Approximate wall-clock times:

| Input | Focused mode | Full mode |
|-------|--------------|-----------|
| 1 MB of JS (small SPA) | 1–3 s | 2–4 s |
| 10 MB of JS (medium SPA) | 10–20 s | 20–40 s |
| 100 MB of JS (large SPA + vendors) | 2–4 min | 4–8 min |

The dominant cost is Semgrep itself. If you are scanning a bundle that
includes large vendor chunks, consider excluding them first:

```bash
# Remove vendor chunks before scanning.
mkdir -p /tmp/clean
find ./target_js_files -name '*.js' \
    ! -name 'vendor*' ! -name 'chunk-vendors*' \
    -exec cp {} /tmp/clean/ \;
./jslogic.sh /tmp/clean
```

---

## Contributing

Contributions are welcome. Before opening a PR:

1. Run `shellcheck jslogic.sh` — it should be clean.
2. Run `semgrep --validate --config rules/*.yaml` — rules should parse.
3. Test the change against a real bundle if possible, and mention in the
   PR description what the new behavior is.
4. Keep the diff focused — one rule or one fix per PR.

If you are adding a rule, include a small test case (a few lines of JS
that the rule should match) in the PR description so reviewers can
verify the rule does what it claims.

---
