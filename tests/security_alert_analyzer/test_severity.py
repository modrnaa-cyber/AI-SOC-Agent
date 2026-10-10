"""Severity classification tests.

Every classification must be explainable: the analyzer returns the ordered
list of reasons that produced the score, so an analyst can audit the verdict
instead of trusting a black box.
"""

from src.security_alert_analyzer import classify_severity, validate_alert


def _alert(**overrides):
    alert = {
        "alert_id": "A-1",
        "timestamp": "2026-01-15T02:14:00Z",
        "rule_name": "Rule",
        "source": {"ip": "203.0.113.10", "host": "web-01", "user": "alice"},
        "event": {"category": "authentication", "action": "login", "outcome": "failure"},
        "indicators": [],
    }
    alert.update(overrides)
    return validate_alert(alert)


def test_benign_alert_is_informational():
    result = classify_severity(_alert())
    assert result["severity"] == "informational"
    assert result["score"] == 0


def test_privileged_account_raises_severity():
    result = classify_severity(_alert(source={"ip": "203.0.113.10", "user": "root"}))
    assert result["severity"] in ("high", "critical")
    assert any("privileged" in reason.lower() for reason in result["reasons"])


def test_outbound_connection_to_external_ip_is_a_reason():
    result = classify_severity(
        _alert(event={"category": "network", "action": "connection", "outcome": "success", "destination_ip": "8.8.8.8"})
    )
    assert result["score"] > 0
    assert any("external" in reason.lower() for reason in result["reasons"])


def test_documentation_range_is_not_treated_as_external():
    """RFC 5737 ranges are placeholders, not real egress targets."""
    result = classify_severity(
        _alert(event={"category": "network", "action": "connection", "outcome": "success", "destination_ip": "198.51.100.7"})
    )
    assert not any("external" in reason.lower() for reason in result["reasons"])


def test_known_malicious_indicator_is_critical():
    result = classify_severity(_alert(indicators=["198.51.100.7"]))
    assert result["severity"] == "critical"


def test_reasons_are_always_a_list_of_strings():
    result = classify_severity(_alert())
    assert isinstance(result["reasons"], list)
    assert all(isinstance(reason, str) for reason in result["reasons"])


def test_score_is_deterministic():
    alert = _alert(source={"ip": "203.0.113.10", "user": "root"})
    assert classify_severity(alert)["score"] == classify_severity(alert)["score"]


def test_encrypted_or_rare_port_adds_reason():
    result = classify_severity(
        _alert(event={"category": "network", "action": "connection", "outcome": "success", "destination_port": 4444})
    )
    assert any("port" in reason.lower() for reason in result["reasons"])
