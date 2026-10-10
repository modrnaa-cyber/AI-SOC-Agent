"""Schema validation for the Security Alert Analyzer add-on.

The analyzer accepts JSON alerts that follow the documented schema. Anything
that does not match is rejected with a clear reason rather than silently
classified, so a malformed feed cannot produce a confident but wrong verdict.
"""

import pytest

from src.security_alert_analyzer import AlertValidationError, validate_alert


def _valid_alert(**overrides):
    alert = {
        "alert_id": "A-1001",
        "timestamp": "2026-01-15T02:14:00Z",
        "rule_name": "Suspicious login",
        "source": {"ip": "203.0.113.10", "host": "web-01", "user": "alice"},
        "event": {"category": "authentication", "action": "login", "outcome": "failure"},
        "indicators": [],
    }
    alert.update(overrides)
    return alert


def test_valid_alert_is_accepted():
    result = validate_alert(_valid_alert())
    assert result["alert_id"] == "A-1001"
    assert result["rule_name"] == "Suspicious login"


def test_missing_required_field_is_rejected():
    alert = _valid_alert()
    del alert["rule_name"]
    with pytest.raises(AlertValidationError) as exc:
        validate_alert(alert)
    assert "rule_name" in str(exc.value)


def test_empty_required_string_is_rejected():
    with pytest.raises(AlertValidationError) as exc:
        validate_alert(_valid_alert(alert_id="   "))
    assert "alert_id" in str(exc.value)


def test_bad_timestamp_is_rejected():
    with pytest.raises(AlertValidationError) as exc:
        validate_alert(_valid_alert(timestamp="yesterday"))
    assert "timestamp" in str(exc.value)


def test_unknown_top_level_key_is_rejected():
    with pytest.raises(AlertValidationError) as exc:
        validate_alert(_valid_alert(surprise="boom"))
    assert "surprise" in str(exc.value)


def test_invalid_source_type_is_rejected():
    with pytest.raises(AlertValidationError) as exc:
        validate_alert(_valid_alert(source="203.0.113.10"))
    assert "source" in str(exc.value)


def test_invalid_indicator_ip_is_rejected():
    with pytest.raises(AlertValidationError) as exc:
        validate_alert(_valid_alert(indicators=["999.1.1.1"]))
    assert "999.1.1.1" in str(exc.value)


def test_non_dict_alert_is_rejected():
    with pytest.raises(AlertValidationError):
        validate_alert(["not", "an", "object"])


def test_minimal_alert_without_optionals_is_accepted():
    minimal = {
        "alert_id": "A-2",
        "timestamp": "2026-01-15T10:00:00+00:00",
        "rule_name": "Beacon",
    }
    result = validate_alert(minimal)
    assert result["source"] == {}
    assert result["indicators"] == []
