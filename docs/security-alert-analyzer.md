# Security Alert Analyzer — add-on documentation

An independent, self-contained add-on for this project. It takes JSON security
alerts, validates them against a documented schema, classifies severity with an
**explainable rule set**, and writes a structured report as JSON and Markdown.

The add-on is a plain Python package under `src/security_alert_analyzer/`. It
imports nothing from the rest of the repository, so it can be tested, reused,
or deleted without touching the original code base.

## What it is not

Stated plainly so nothing here is over-claimed:

- **No AI / no LLM.** Severity comes from a fixed rule set. There is no model,
  no prompt, and no inference call.
- **No SIEM integration.** It does not query Elastic, TheHive, IRIS, Velociraptor,
  or any external service. It reads a local JSON file and writes a local file.
- **No automatic response.** It never isolates a host, disables an account, or
  opens a case. It only produces a report for a human to read.
- **No network access at all.** The analyzer is offline by construction.

## Input schema

One alert object, a JSON array of alerts, or an object of the form
`{"alerts": [ ... ]}`.

### Required fields

| Field | Type | Notes |
|---|---|---|
| `alert_id` | string | Non-empty. Identifier from the source system. |
| `timestamp` | string | ISO 8601 datetime. Naive values are treated as UTC. |
| `rule_name` | string | Non-empty. Name of the detection rule that fired. |

### Optional fields

| Field | Type | Notes |
|---|---|---|
| `source` | object | `ip`, `host`, `user`, `port` — all optional. `ip` must parse as an IP address. |
| `event` | object | `category`, `action`, `outcome`, `process`, `command_line`, `file_path`, `destination_ip`, `destination_port`. |
| `indicators` | array | List of IP addresses. |
| `description` | string | Free text. |
| `tags` | array | List of strings. |

**Unknown top-level keys are rejected.** Unknown keys inside `source` or
`event` are rejected too. The contract is strict on purpose: a feed that
changed shape fails loudly instead of being scored as if it were valid.

## Severity rules

Each rule adds a fixed number of points and appends a human-readable reason.
The final score is the sum; the band is the first threshold the score reaches.

| Rule | Points | Reason text |
|---|---|---|
| Source user is a privileged account (`root`, `administrator`, `admin`, `system`, `localsystem`, `nt authority\system`) | +50 | "Privileged account … is involved." |
| `event.destination_ip` is globally routable (`ipaddress.is_global`) | +20 | "Connection to external address …" |
| `event.destination_port` is in the attacker-tooling set (4444, 1337, 31337, 445, 3389, 5900, 6667, 9001) | +15 | "Destination port … is commonly used by attacker tooling." |
| Any `indicators` present | +100 | "N indicator(s) treated as known-bad: …" |

### Bands

| Score | Severity |
|---|---|
| ≥ 75 | critical |
| ≥ 50 | high |
| ≥ 25 | medium |
| ≥ 1 | low |
| 0 | informational |

If no rule matches, the reason list says so explicitly rather than being empty.

> **On `indicators`:** the +100 weight reflects that the *caller* already
> decided these are known-bad. The analyzer does **not** perform threat-intel
> lookups; it trusts the label it was given. Feeding it a benign IP in
> `indicators` will produce a `critical` verdict — that is intended behaviour
> and is documented here so it cannot be mistaken for enrichment.

## Install

No new dependencies. The add-on uses the Python standard library only.

```bash
# From the repository root. Nothing to install.
python3 -c "import src.security_alert_analyzer as a; print(a.__version__)"
```

## Run

```bash
# Report to both formats
python3 -m src.security_alert_analyzer \
    src/security_alert_analyzer/examples/sample_alerts.json \
    --json-out report.json --md-out report.md

# Print Markdown to stdout
python3 -m src.security_alert_analyzer src/security_alert_analyzer/examples/sample_alerts.json

# A malformed alert is rejected with a non-zero exit and a message on stderr
python3 -m src.security_alert_analyzer src/security_alert_analyzer/examples/invalid_alert.json --json-out /tmp/x.json
# error: Field 'timestamp' must be an ISO 8601 datetime, got 'not-a-date'.
# exit code 2
```

### Library use

```python
from src.security_alert_analyzer import analyze_alert, render_markdown, validate_alert

alert = validate_alert({"alert_id": "A-1", "timestamp": "2026-01-15T02:14:00Z",
                        "rule_name": "Rule", "source": {"user": "root"}})
report = analyze_alert(alert)
print(report["severity"], report["reasons"])
print(render_markdown(report))
```

## Test

```bash
python3 -m pytest tests/security_alert_analyzer/ -v
```

30 tests cover the success path, invalid input, and edge cases: missing and
empty fields, bad timestamps, unknown keys, malformed IPs and indicators,
non-object input, the `{"alerts": [...]}` wrapper, unreadable input, and an
unwritable output directory.

## Limitations and risk of wrong verdicts

This is triage input, not a conclusion.

- **False positives.** A benign privileged login on a hardened host scores
  `high`. A legitimate service calling a public API on port 4444 scores
  `medium`. Neither is evidence of compromise.
- **False negatives.** The rule set only sees the fields in the schema. A real
  intrusion that does not use a privileged account, a public destination, a
  listed port, or a caller-supplied indicator scores `informational`.
- **No correlation.** Each alert is scored alone. Ten `low` alerts about the
  same host are not combined into one `high`.
- **Trusted inputs.** `indicators` and `source.user` are taken at face value.
  A feed that mislabels data produces a confident but wrong score.
- **Fixed rules.** The thresholds and port list are constants in
  `severity.py`. They are a starting point, not a tuned detection model, and
  they have not been validated against a labelled dataset.

The report itself carries this caveat in a `limits` field so a downstream
reader cannot consume the verdict without seeing it.
