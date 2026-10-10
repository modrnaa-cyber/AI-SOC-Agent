"""Report rendering tests.

The analyzer emits the same analysis as JSON (for machines) and Markdown
(for humans). Both must carry the severity, the reasons, and a recommended
action, and the Markdown must never claim more than the data supports.
"""

import json

from src.security_alert_analyzer import analyze_alert, render_json, render_markdown, validate_alert


def _alert(**overrides):
    alert = {
        "alert_id": "A-77",
        "timestamp": "2026-01-15T02:14:00Z",
        "rule_name": "Suspicious login",
        "source": {"ip": "203.0.113.10", "host": "web-01", "user": "root"},
        "event": {"category": "authentication", "action": "login", "outcome": "failure"},
        "indicators": [],
    }
    alert.update(overrides)
    return validate_alert(alert)


def test_json_report_is_valid_json_with_expected_keys():
    report = analyze_alert(_alert())
    payload = json.loads(render_json(report))
    assert payload["alert_id"] == "A-77"
    assert "severity" in payload
    assert "reasons" in payload
    assert "recommendation" in payload


def test_markdown_report_contains_severity_and_recommendation():
    report = analyze_alert(_alert())
    md = render_markdown(report)
    assert "A-77" in md
    assert report["severity"].upper() in md.upper()
    assert report["recommendation"] in md


def test_recommendation_is_present_for_every_severity():
    for user in ("alice", "root"):
        report = analyze_alert(_alert(source={"ip": "203.0.113.10", "user": user}))
        assert report["recommendation"].strip()


def test_markdown_lists_every_reason():
    report = analyze_alert(_alert())
    md = render_markdown(report)
    for reason in report["reasons"]:
        assert reason in md


def test_report_includes_false_positive_note():
    report = analyze_alert(_alert())
    md = render_markdown(report)
    assert "false positive" in md.lower()
