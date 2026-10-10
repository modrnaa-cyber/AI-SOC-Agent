# Contributions

## Add-on: Security Alert Analyzer

**Author:** Azzam Abdulkarim Alharbi
**Scope:** a new, self-contained add-on. No source file of the original platform
was modified; the upstream documentation was reorganised (see "Files moved" and
"Files modified" below).
**Branch:** `feat/security-alert-analyzer`

This document describes exactly what was added, by whom, and what was actually
tested. It deliberately does not claim authorship of the original platform.

---

## What the original project is

The upstream project — the SamiGPT AI security investigation and incident
response platform — was created and is maintained by **M507**
(<https://github.com/M507/AI-SOC-Agent>) under the MIT License. The platform,
its architecture, its integrations, and its existing tests are the work of the
original author. Nothing in this contribution transfers or dilutes that
authorship, and the original copyright notice in `LICENSE` is unchanged.

## What I contributed

An independent add-on that analyses JSON security alerts. It is a separate
Python package that imports nothing from the rest of the repository, so it can
be reviewed, reused, or removed without touching the original code.

### Files added

| Path | What it is |
|---|---|
| `src/security_alert_analyzer/__init__.py` | Package entry point and public API. |
| `src/security_alert_analyzer/schema.py` | Strict schema validation of incoming alerts. |
| `src/security_alert_analyzer/severity.py` | Explainable, rule-based severity classification. |
| `src/security_alert_analyzer/report.py` | JSON and Markdown report rendering. |
| `src/security_alert_analyzer/__main__.py` | Command-line entry point. |
| `src/security_alert_analyzer/examples/sample_alerts.json` | Synthetic alerts covering the full severity range. |
| `src/security_alert_analyzer/examples/invalid_alert.json` | Synthetic malformed alert. |
| `src/security_alert_analyzer/examples/README.md` | Explanation of the sample data. |
| `tests/security_alert_analyzer/test_schema.py` | Validation tests. |
| `tests/security_alert_analyzer/test_severity.py` | Classification tests. |
| `tests/security_alert_analyzer/test_report.py` | Report rendering tests. |
| `tests/security_alert_analyzer/test_cli.py` | CLI and edge-case tests. |
| `docs/security-alert-analyzer.md` | Full add-on documentation. |
| `SECURITY.md` | Scope, reporting process, and known limitations. |
| `CONTRIBUTIONS.md` | This file. |

### Files moved (original content relocated, not rewritten)

| Path | What happened |
|---|---|
| `ORIGINAL_PLATFORM.md` | The **original author's** upstream README content, relocated verbatim out of `README.md` so that the add-on leads the main README. This file is not new writing: it is M507's own documentation, preserved intact for reference, with a short header added to state that it documents the upstream project. |

### Files modified

| Path | Change |
|---|---|
| `README.md` | Replaced the upstream platform README with a README for the add-on. The original platform documentation was **moved** to `ORIGINAL_PLATFORM.md`, not deleted. The new README keeps attribution to M507, a link to the upstream repository, and a reference to the unchanged MIT license. |

**In plain terms:** the upstream `README.md` was not left untouched. Its
platform documentation and release history were relocated into
`ORIGINAL_PLATFORM.md` so the add-on is what a reader sees first. Nothing from
the original author was discarded in the process, with two deliberate edits,
both recorded here:

1. A short header was added to `ORIGINAL_PLATFORM.md` noting that the file
   documents the upstream project and naming its author.
2. The `"v0.1 — Black Hat version"` changelog entry was removed, together with
   its performance and cost figures (`~ $0.18 per alert`,
   `~ 50 seconds to investigate an alert`). Those figures were the upstream
   author's; this branch does not restate them, and no equivalent claim is made
   anywhere in this contribution.

**No source file of the original platform was modified.** The add-on uses the
Python standard library only and adds no dependency. `LICENSE` and the original
copyright notice are unchanged.

## What the add-on does

1. **Receives** JSON alerts — one object, an array, or `{"alerts": [...]}`.
2. **Validates** them against a documented schema and rejects anything that
   does not match, with a clear reason and a non-zero exit code.
3. **Classifies** severity with a transparent rule set that returns the ordered
   reasons behind the score.
4. **Recommends** an action appropriate to the severity.
5. **Reports** the result as JSON and Markdown.

It does **not** use an LLM, does **not** query a SIEM, and performs **no**
automatic response. See `docs/security-alert-analyzer.md`.

## Development method

The add-on was built test-first. Each behaviour was written as a failing test,
observed to fail, and only then implemented. This produced the following real
failures that were fixed during development, rather than being papered over:

- A severity test used an RFC 5737 documentation address (`198.51.100.7`) and
  expected it to count as external egress. The test was wrong: that range is a
  placeholder. The implementation was tightened to `ipaddress.is_global` and a
  second test was added to pin the corrected behaviour.
- The CLI rejected the common `{"alerts": [...]}` feed wrapper. A failing test
  was added first, then the wrapper was supported.

## Tests actually run and their results

Commands and outcomes below are from real runs, not estimates.

### Add-on test suite

```
$ python3 -m pytest tests/security_alert_analyzer/ -q
30 passed in 0.04s
```

30 tests cover the success path, invalid input, and edge cases: missing and
empty required fields, malformed timestamps, unknown top-level and nested keys,
malformed IP addresses and indicators, non-object input, the `{"alerts": [...]}`
wrapper, a missing input file, invalid JSON, and an unwritable output directory.

### Command-line verification

```
$ python3 -m src.security_alert_analyzer \
    src/security_alert_analyzer/examples/sample_alerts.json \
    --json-out /tmp/report.json --md-out /tmp/report.md
LAB-0001: informational (score 0)
LAB-0002: medium (score 35)
LAB-0003: high (score 50)
LAB-0004: critical (score 100)
LAB-0005: informational (score 0)
exit=0
```

Invalid input is rejected as designed:

```
$ python3 -m src.security_alert_analyzer \
    src/security_alert_analyzer/examples/invalid_alert.json --json-out /tmp/bad.json
error: Field 'timestamp' must be an ISO 8601 datetime, got 'not-a-date'.
exit=2
```

### Regression check against the original test suite

The add-on must not break anything that already worked.

```
Before my changes (pristine clone of the upstream repository):
    27 failed, 312 passed, 5 skipped, 2 errors

After my changes (this branch):
    27 failed, 342 passed, 5 skipped, 2 errors
```

The pass count rises by exactly 30 — the new add-on tests — and **the same 27
pre-existing failures remain**. To confirm they were not caused by this work,
the identical suite was run on a fresh clone of the upstream repository with no
changes applied, and it produced the same 27 failures. They are pre-existing
issues in the upstream project (dependency-version drift in the web/auth test
fixtures), unrelated to this add-on.

## Honest statement of scope

- I did **not** build the original platform.
- I did **not** fix the 27 pre-existing upstream test failures; they are out of
  scope for this add-on and were left untouched.
- I did **not** run this inside Docker: the environment provided had no Docker
  daemon. The application was run directly with Python on `127.0.0.1` and
  verified over HTTPS.
- No performance numbers, benchmark figures, or success-rate claims are made
  anywhere, because none were measured.

## License and attribution

This contribution is made under the same **MIT License** as the original
project. The original copyright notice in `LICENSE` is preserved in full and
must remain with any copy or substantial portion of the software, per the
license terms.
