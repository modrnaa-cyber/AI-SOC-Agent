# Sample data

Everything in this folder is **synthetic**. It exists so the analyzer can be
run and understood without touching real telemetry.

## Files

| File | Purpose |
|---|---|
| `sample_alerts.json` | Five alerts that exercise the full severity range, from `informational` to `critical`. |
| `invalid_alert.json` | One alert with a bad `timestamp`, used to demonstrate that invalid input is rejected. |

## How the samples were built

- **IP addresses** are from the documentation ranges reserved by RFC 5737
  (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`), plus one public
  resolver address (`8.8.8.8`) used to trigger the "external destination"
  rule. None of these is an attacker indicator.
- **Host names** (`lab-web-01`, `lab-dc-01`, `lab-app-02`, `lab-file-01`) and
  **accounts** (`alice`, `root`, `svc-backup`, `svc-deploy`, `svc-task`) are
  invented for the demo.
- **No personal data, no credentials, no API keys, and no real indicators**
  appear in any file here.

## What each sample demonstrates

| Alert | Signal | Expected severity |
|---|---|---|
| `LAB-0001` | Failed authentication, unprivileged account | informational |
| `LAB-0002` | Egress to a public IP on port 4444 | medium |
| `LAB-0003` | Privileged account (`root`) login | high |
| `LAB-0004` | Caller-supplied indicator present | critical |
| `LAB-0005` | Routine scheduled task, no signal | informational |

## Run the samples

```bash
# From the repository root
python3 -m src.security_alert_analyzer \
    src/security_alert_analyzer/examples/sample_alerts.json \
    --json-out report.json --md-out report.md

# Show that invalid input is rejected (exits non-zero)
python3 -m src.security_alert_analyzer \
    src/security_alert_analyzer/examples/invalid_alert.json --json-out /tmp/x.json
```

## Adapting the samples

To test your own feed, copy `sample_alerts.json` and replace the values. Keep
the field names from the schema in `docs/security-alert-analyzer.md`; the
validator rejects unknown keys on purpose so a typo surfaces immediately.
