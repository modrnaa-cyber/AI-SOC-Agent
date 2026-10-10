# Security Policy

## Scope

This policy covers the **Security Alert Analyzer add-on** contributed to this
repository (`src/security_alert_analyzer/`, `tests/security_alert_analyzer/`,
`docs/security-alert-analyzer.md`). For vulnerabilities in the original SamiGPT
platform — its web console, MCP listener, integrations, or TLS handling — please
contact the upstream maintainer of the original project, not this add-on. The
upstream project's own documentation is preserved in `ORIGINAL_PLATFORM.md`.

## What the add-on does and does not do

Understanding the boundary matters when judging a report:

| Capability | Status |
|---|---|
| Reads a local JSON file | Yes |
| Validates alerts against a fixed schema | Yes |
| Classifies severity with a transparent rule set | Yes |
| Writes JSON and Markdown reports to a local path | Yes |
| Opens a network connection | **No** |
| Calls an LLM or any external API | **No** |
| Queries a SIEM, EDR, case manager, or threat-intel service | **No** |
| Executes a response action (isolate, disable, block) | **No** |
| Stores credentials or secrets | **No** |

The add-on is offline by construction. It has no network client, no API token,
and no configuration file. Its only inputs are the JSON file path and the
output paths given on the command line.

## Reporting a vulnerability

If you find a vulnerability **in this add-on**, please report it privately
rather than opening a public issue:

1. Open a private security advisory on the repository (GitHub → Security →
   Advisories → "Report a vulnerability"), or
2. Contact the add-on author: **Azzam Abdulkarim Alharbi** —
   `Azzamcyber404@gmail.com`.

Please include: affected file and version, a minimal reproduction (a small
alert JSON and the exact command), and the impact you believe it has.

You can expect an acknowledgement, an assessment of severity, and a fix or a
documented decision within a reasonable time. This is a personal contribution
maintained on a best-effort basis; there is no SLA.

## Known limitations that are not vulnerabilities

These are documented behaviours, not bugs:

- **A malformed alert is rejected, not partially analysed.** Validation is
  strict by design. A feed with an unexpected key fails with a non-zero exit.
- **`indicators` are trusted as labelled.** The add-on does not verify whether
  an indicator is actually malicious; a benign IP placed in `indicators`
  produces a `critical` verdict. This is intended and documented.
- **A high score is not proof of compromise.** The rule set produces false
  positives and false negatives. See the "Limitations" section of
  `docs/security-alert-analyzer.md`.
- **The tool never acts on its own.** No host is isolated and no account is
  disabled. It only produces a report.

## Handling data safely

The examples under `src/security_alert_analyzer/examples/` are **synthetic**.
They use documentation IP ranges (RFC 5737: `192.0.2.0/24`, `198.51.100.0/24`,
`203.0.113.0/24`) and invented host and account names. No real indicator, no
personal data, and no credential appears in the examples or the tests.

Do not feed production alerts containing personal data or secrets into a
shared report without reviewing the output first.
