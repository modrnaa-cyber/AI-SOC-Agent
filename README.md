# Security Alert Analyzer

**Author: Azzam Abdulkarim Alharbi**

An independent, self-contained add-on for triaging JSON security alerts: it
validates them against a documented schema, classifies severity with an
**explainable rule set**, and emits a structured report as JSON and Markdown.

> **This README documents the add-on.** For the original upstream platform
> (SamiGPT) and its release history, see
> [ORIGINAL_PLATFORM.md](ORIGINAL_PLATFORM.md).

---

## Attribution

| | |
|---|---|
| **Add-on author** | Azzam Abdulkarim Alharbi |
| **Add-on code** | `src/security_alert_analyzer/` |
| **Original platform** | SamiGPT (AI-SOC-Agent) |
| **Original author** | **M507** — <https://github.com/M507/AI-SOC-Agent> |
| **License** | MIT (unchanged — see [LICENSE](LICENSE)) |

The **Security Alert Analyzer is developed by Azzam Abdulkarim Alharbi**. The
original platform **SamiGPT is the work of M507** and is not claimed here. The
add-on is a separate Python package that imports nothing from the rest of the
repository, so it can be reviewed, reused, or removed without touching the
original code. The original copyright notice in `LICENSE` is preserved in full.

---

## Goal

Security analysts receive more alerts than they can read. This add-on answers
one narrow question for each alert — *how much does this deserve attention, and
why?* — and returns an auditable answer instead of an opaque score.

It is deliberately small and offline. It exists to be read, checked, and
disagreed with.

## What it is not

Stated plainly, so nothing here is over-claimed:

- **No AI / no LLM.** Severity comes from a fixed rule set. There is no model,
  no prompt, and no inference call.
- **No SIEM integration.** It does not query Elastic, TheHive, IRIS,
  Velociraptor, or any external service.
- **No automatic response.** It never isolates a host, disables an account, or
  opens a case.
- **No network access at all.** The analyzer is offline by construction.
- **No new dependency.** Python standard library only.

## Features

1. **Strict schema validation** — required fields, types, timestamps, IP
   addresses, and unknown keys are all checked. Invalid input is rejected with
   a clear reason and a non-zero exit code, never a silent success.
2. **Explainable severity classification** — fixed-weight rules that return the
   ordered list of reasons behind the score, so every verdict can be audited.
3. **Structured reports in two formats** — JSON for machines, Markdown for
   humans, carrying the same analysis.
4. **Built-in caveat** — every report embeds its own false-positive /
   false-negative warning, so a reader cannot consume a verdict without seeing it.
5. **Synthetic sample data** — safe to run anywhere; no personal data or secrets.

---

## Important: how to read the output

**Severity is a rule-based signal, not a confirmed verdict.**

- A high score does **not** mean a breach occurred. A benign privileged login on
  a hardened host scores `high`; a legitimate service calling a public API on
  port 4444 scores `medium`. Neither is evidence of compromise.
- A low score does **not** mean an alert is safe. The rule set only sees the
  fields in the schema. A real intrusion that avoids those signals scores
  `informational`.
- **Indicators are taken at face value.** Any IP listed in the `indicators`
  field is treated as known-bad *because the caller labelled it so*. The add-on
  performs **no threat-intelligence lookup**. Putting a benign IP in
  `indicators` will produce a `critical` verdict — this is intended behaviour of
  the rule set, and it is why the field must be trusted before it is used.
- **Every result requires human review.** This is triage input to prioritise
  attention, not a conclusion to act on automatically.

The report itself carries this caveat in a `limits` field.

---

## Install

No dependencies to install — the standard library only.

```bash
# From the repository root
python3 -c "import src.security_alert_analyzer as a; print(a.__version__)"
```

Requires Python 3.10+ (the repository's existing minimum).

## Run

```bash
# Report to both formats
python3 -m src.security_alert_analyzer \
    src/security_alert_analyzer/examples/sample_alerts.json \
    --json-out report.json --md-out report.md

# Print Markdown to stdout
python3 -m src.security_alert_analyzer \
    src/security_alert_analyzer/examples/sample_alerts.json

# A malformed alert is rejected with a non-zero exit and a message on stderr
python3 -m src.security_alert_analyzer \
    src/security_alert_analyzer/examples/invalid_alert.json --json-out /tmp/x.json
# error: Field 'timestamp' must be an ISO 8601 datetime, got 'not-a-date'.
# exit code 2
```

### Library use

```python
from src.security_alert_analyzer import analyze_alert, render_markdown, validate_alert

alert = validate_alert({
    "alert_id": "A-1",
    "timestamp": "2026-01-15T02:14:00Z",
    "rule_name": "Rule",
    "source": {"user": "root"},
})
report = analyze_alert(alert)
print(report["severity"], report["reasons"])
print(render_markdown(report))
```

## Test

```bash
python3 -m pytest tests/security_alert_analyzer/ -v
```

**30 tests**, covering the success path, invalid input, and edge cases:

| File | Tests | Covers |
|---|---|---|
| `tests/security_alert_analyzer/test_schema.py` | 9 | Required/empty fields, bad timestamps, unknown keys, malformed IPs, non-object input |
| `tests/security_alert_analyzer/test_severity.py` | 8 | Each rule, reason text, determinism, documentation-range handling |
| `tests/security_alert_analyzer/test_report.py` | 5 | JSON validity, Markdown content, recommendation presence, caveat |
| `tests/security_alert_analyzer/test_cli.py` | 8 | Both output formats, `{"alerts": [...]}` wrapper, missing file, bad JSON, bad output dir |

---

## Severity rules

Each rule adds a fixed number of points and appends a reason. The score is the
sum; the band is the first threshold the score reaches.

| Rule | Points |
|---|---|
| Source user is a privileged account (`root`, `administrator`, `admin`, `system`, `localsystem`, `nt authority\system`) | +50 |
| `event.destination_ip` is globally routable (`ipaddress.is_global`) | +20 |
| `event.destination_port` is in the attacker-tooling set (4444, 1337, 31337, 445, 3389, 5900, 6667, 9001) | +15 |
| Any `indicators` present (treated as known-bad by assumption) | +100 |

| Score | Severity |
|---|---|
| ≥ 75 | critical |
| ≥ 50 | high |
| ≥ 25 | medium |
| ≥ 1 | low |
| 0 | informational |

Full schema, weights, and limitations: [docs/security-alert-analyzer.md](docs/security-alert-analyzer.md).

## Repository layout (add-on)

```
src/security_alert_analyzer/
├── __init__.py        # Public API
├── schema.py          # Strict alert validation
├── severity.py        # Explainable rule-based classification
├── report.py          # JSON and Markdown rendering
├── __main__.py        # Command-line entry point
└── examples/
    ├── sample_alerts.json   # Synthetic alerts, full severity range
    ├── invalid_alert.json   # Synthetic malformed alert
    └── README.md            # What the sample data is

tests/security_alert_analyzer/   # 30 tests
docs/security-alert-analyzer.md  # Full documentation
SECURITY.md                      # Scope and vulnerability reporting
CONTRIBUTIONS.md                 # What was added and what was tested
```

---

## Documentation

| File | Purpose |
|---|---|
| [docs/security-alert-analyzer.md](docs/security-alert-analyzer.md) | Full schema, rules, thresholds, and limitations |
| [SECURITY.md](SECURITY.md) | Scope, vulnerability reporting, safe data handling |
| [CONTRIBUTIONS.md](CONTRIBUTIONS.md) | Exactly what was added and the tests that were run |
| [ORIGINAL_PLATFORM.md](ORIGINAL_PLATFORM.md) | Upstream SamiGPT documentation (original author's content) |

## License

MIT — the same license as the original project. See [LICENSE](LICENSE).
The original copyright notice is unchanged and must remain with any copy or
substantial portion of the software.

## Credits

- **SamiGPT (AI-SOC-Agent)** — original platform by **M507**:
  <https://github.com/M507/AI-SOC-Agent>
- **Security Alert Analyzer add-on** — Azzam Abdulkarim Alharbi
