"""Report rendering for the analyzer.

One analysis is produced once and rendered twice: JSON for machines and
Markdown for humans. The Markdown deliberately restates the limits of the
tool (it is rule-based and can be wrong in both directions) so a reader
never mistakes a verdict for a confirmed fact.
"""

from __future__ import annotations

import json
from typing import Any, Dict

_FALSE_POSITIVE_NOTE = (
    "This verdict is produced by a fixed rule set, not a model and not a live "
    "SIEM query. It can be wrong in both directions: a benign alert can score "
    "high (false positive) and a real intrusion can score low if it lacks the "
    "signals the rules look for (false negative). Treat it as triage input, "
    "not as a conclusion."
)


def analyze_alert(alert: Dict[str, Any]) -> Dict[str, Any]:
    """Combine a validated alert with its classification into one report."""
    from .severity import classify_severity

    classification = classify_severity(alert)
    return {**alert, **classification, "limits": _FALSE_POSITIVE_NOTE}


def render_json(report: Dict[str, Any]) -> str:
    """Render one report (or a list of reports) as pretty JSON."""
    return json.dumps(report, indent=2, ensure_ascii=False, sort_keys=False)


def render_markdown(report: Dict[str, Any]) -> str:
    """Render one report as a human-readable Markdown document."""
    if isinstance(report, list):
        return "\n\n---\n\n".join(render_markdown(item) for item in report)

    source = report.get("source") or {}
    event = report.get("event") or {}
    lines = [
        f"# Security Alert Analysis — {report.get('alert_id', 'unknown')}",
        "",
        f"- **Rule:** {report.get('rule_name', 'unknown')}",
        f"- **Timestamp:** {report.get('timestamp', 'unknown')}",
        f"- **Severity:** {str(report.get('severity', '')).upper()} (score {report.get('score', 0)})",
    ]
    if source:
        lines.append(f"- **Source:** {json.dumps(source, ensure_ascii=False)}")
    if event:
        lines.append(f"- **Event:** {json.dumps(event, ensure_ascii=False)}")

    lines += ["", "## Why this severity", ""]
    for reason in report.get("reasons", []):
        lines.append(f"- {reason}")

    lines += [
        "",
        "## Recommended action",
        "",
        report.get("recommendation", "No recommendation available."),
        "",
        "## Limits (false positive / false negative)",
        "",
        report.get("limits", _FALSE_POSITIVE_NOTE),
        "",
    ]
    return "\n".join(lines)
