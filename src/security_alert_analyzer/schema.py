"""Alert schema validation.

This module defines the documented input contract for the analyzer. It is
deliberately strict: unknown top-level keys, wrong types, and malformed
indicators are rejected so a broken feed fails loudly instead of being
scored as if it were a valid alert.
"""

from __future__ import annotations

import ipaddress
from datetime import datetime, timezone
from typing import Any, Dict, List


class AlertValidationError(ValueError):
    """Raised when an alert does not match the documented schema."""


REQUIRED_FIELDS = ("alert_id", "timestamp", "rule_name")
OPTIONAL_FIELDS = ("source", "event", "indicators", "description", "tags")
ALLOWED_FIELDS = set(REQUIRED_FIELDS) | set(OPTIONAL_FIELDS)
SOURCE_FIELDS = {"ip", "host", "user", "port"}
EVENT_FIELDS = {
    "category",
    "action",
    "outcome",
    "destination_ip",
    "destination_port",
    "process",
    "command_line",
    "file_path",
}


def _require_non_empty_string(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise AlertValidationError(f"Field '{field}' must be a string.")
    if not value.strip():
        raise AlertValidationError(f"Field '{field}' must not be empty.")
    return value.strip()


def _parse_timestamp(value: Any) -> str:
    text = _require_non_empty_string(value, "timestamp")
    candidate = text[:-1] + "+00:00" if text.endswith("Z") else text
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError as exc:
        raise AlertValidationError(
            f"Field 'timestamp' must be an ISO 8601 datetime, got '{text}'."
        ) from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _validate_ip(value: Any, field: str) -> str:
    text = _require_non_empty_string(value, field)
    try:
        ipaddress.ip_address(text)
    except ValueError as exc:
        raise AlertValidationError(f"Field '{field}' is not a valid IP address: '{text}'.") from exc
    return text


def _validate_source(value: Any) -> Dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise AlertValidationError("Field 'source' must be an object.")
    unknown = set(value) - SOURCE_FIELDS
    if unknown:
        raise AlertValidationError(f"Field 'source' has unknown keys: {sorted(unknown)}.")
    result: Dict[str, Any] = {}
    if "ip" in value and value["ip"] not in (None, ""):
        result["ip"] = _validate_ip(value["ip"], "source.ip")
    for key in ("host", "user"):
        if key in value and value[key] not in (None, ""):
            result[key] = _require_non_empty_string(value[key], f"source.{key}")
    if "port" in value and value["port"] not in (None, ""):
        result["port"] = _validate_port(value["port"], "source.port")
    return result


def _validate_port(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise AlertValidationError(f"Field '{field}' must be an integer port.")
    if not 0 <= value <= 65535:
        raise AlertValidationError(f"Field '{field}' must be between 0 and 65535.")
    return value


def _validate_event(value: Any) -> Dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise AlertValidationError("Field 'event' must be an object.")
    unknown = set(value) - EVENT_FIELDS
    if unknown:
        raise AlertValidationError(f"Field 'event' has unknown keys: {sorted(unknown)}.")
    result: Dict[str, Any] = {}
    if "destination_ip" in value and value["destination_ip"] not in (None, ""):
        result["destination_ip"] = _validate_ip(value["destination_ip"], "event.destination_ip")
    if "destination_port" in value and value["destination_port"] not in (None, ""):
        result["destination_port"] = _validate_port(value["destination_port"], "event.destination_port")
    for key in ("category", "action", "outcome", "process", "command_line", "file_path"):
        if key in value and value[key] not in (None, ""):
            result[key] = _require_non_empty_string(value[key], f"event.{key}")
    return result


def _validate_indicators(value: Any) -> List[str]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise AlertValidationError("Field 'indicators' must be a list.")
    result: List[str] = []
    for item in value:
        text = _require_non_empty_string(item, "indicators[]")
        try:
            ipaddress.ip_address(text)
        except ValueError as exc:
            raise AlertValidationError(f"Indicator is not a valid IP address: '{text}'.") from exc
        result.append(text)
    return result


def validate_alert(alert: Any) -> Dict[str, Any]:
    """Validate one alert and return a normalized copy.

    Raises:
        AlertValidationError: on any schema violation.
    """
    if not isinstance(alert, dict):
        raise AlertValidationError("An alert must be a JSON object.")

    unknown = set(alert) - ALLOWED_FIELDS
    if unknown:
        raise AlertValidationError(f"Unknown top-level keys: {sorted(unknown)}.")

    for field in REQUIRED_FIELDS:
        if field not in alert:
            raise AlertValidationError(f"Missing required field '{field}'.")

    normalized: Dict[str, Any] = {
        "alert_id": _require_non_empty_string(alert["alert_id"], "alert_id"),
        "timestamp": _parse_timestamp(alert["timestamp"]),
        "rule_name": _require_non_empty_string(alert["rule_name"], "rule_name"),
        "source": _validate_source(alert.get("source")),
        "event": _validate_event(alert.get("event")),
        "indicators": _validate_indicators(alert.get("indicators")),
    }
    if alert.get("description") not in (None, ""):
        normalized["description"] = _require_non_empty_string(alert["description"], "description")
    if alert.get("tags") not in (None, ""):
        tags = alert["tags"]
        if not isinstance(tags, list) or not all(isinstance(t, str) for t in tags):
            raise AlertValidationError("Field 'tags' must be a list of strings.")
        normalized["tags"] = [t.strip() for t in tags if t.strip()]
    return normalized
