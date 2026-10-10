"""CLI and edge-case tests for the Security Alert Analyzer.

The command line entry point reads a JSON alert (single object or a list)
and writes JSON and/or Markdown. Invalid input must exit non-zero with a
message on stderr, never a traceback and never a silent success.
"""

import json
from pathlib import Path

from src.security_alert_analyzer.__main__ import main


def _write(tmp_path: Path, name: str, data) -> Path:
    path = tmp_path / name
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


VALID = {
    "alert_id": "A-9",
    "timestamp": "2026-01-15T02:14:00Z",
    "rule_name": "Suspicious login",
    "source": {"ip": "203.0.113.10", "user": "root"},
    "event": {"category": "authentication", "action": "login", "outcome": "failure"},
    "indicators": [],
}


def test_cli_writes_json_report(tmp_path, capsys):
    alert_path = _write(tmp_path, "alert.json", VALID)
    out = tmp_path / "out.json"
    code = main([str(alert_path), "--json-out", str(out)])
    assert code == 0
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["alert_id"] == "A-9"


def test_cli_writes_markdown_report(tmp_path):
    alert_path = _write(tmp_path, "alert.json", VALID)
    out = tmp_path / "out.md"
    code = main([str(alert_path), "--md-out", str(out)])
    assert code == 0
    assert "A-9" in out.read_text(encoding="utf-8")


def test_cli_handles_a_list_of_alerts(tmp_path):
    alert_path = _write(tmp_path, "alerts.json", [VALID, {**VALID, "alert_id": "A-10"}])
    out = tmp_path / "out.json"
    code = main([str(alert_path), "--json-out", str(out)])
    assert code == 0
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert isinstance(payload, list)
    assert len(payload) == 2


def test_cli_accepts_alerts_wrapper_object(tmp_path):
    """A feed commonly wraps the batch in an 'alerts' key."""
    alert_path = _write(tmp_path, "feed.json", {"alerts": [VALID, {**VALID, "alert_id": "A-11"}]})
    out = tmp_path / "out.json"
    code = main([str(alert_path), "--json-out", str(out)])
    assert code == 0
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert [r["alert_id"] for r in payload] == ["A-9", "A-11"]


def test_cli_rejects_invalid_json(tmp_path, capsys):
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    code = main([str(bad), "--json-out", str(tmp_path / "o.json")])
    assert code != 0
    err = capsys.readouterr().err.lower()
    assert "json" in err


def test_cli_rejects_schema_violation(tmp_path, capsys):
    alert_path = _write(tmp_path, "alert.json", {"alert_id": "A-1"})
    code = main([str(alert_path), "--json-out", str(tmp_path / "o.json")])
    assert code != 0
    assert "timestamp" in capsys.readouterr().err


def test_cli_missing_file_exits_nonzero(tmp_path, capsys):
    code = main([str(tmp_path / "nope.json"), "--json-out", str(tmp_path / "o.json")])
    assert code != 0


def test_cli_rejects_unknown_output_directory(tmp_path, capsys):
    alert_path = _write(tmp_path, "alert.json", VALID)
    code = main([str(alert_path), "--json-out", str(tmp_path / "missing_dir" / "o.json")])
    assert code != 0
