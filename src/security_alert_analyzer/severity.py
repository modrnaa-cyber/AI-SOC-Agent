"""Explainable severity classification.

The analyzer is a transparent rule set, not a model. Each rule contributes a
fixed number of points and appends a human-readable reason, so the final
severity can always be traced back to the evidence that produced it. The
rules are intentionally conservative: they raise severity on signals an
analyst would also treat as suspicious, and they do not pretend to detect
anything they were not given.
"""

from __future__ import annotations

import ipaddress
from typing import Any, Dict, List

# Accounts that normally carry elevated rights. Matching is case-insensitive
# and exact, so "root" matches but "rootfs" does not.
PRIVILEGED_ACCOUNTS = {
    "root",
    "administrator",
    "admin",
    "system",
    "localsystem",
    "nt authority\\system",
}

# Ports that are common in attacker tooling or lateral movement. Presence is a
# weak signal on its own, so the weight is deliberately small.
SUSPICIOUS_PORTS = {4444, 1337, 31337, 445, 3389, 5900, 6667, 9001}

# Ordered thresholds: the first entry whose minimum the score reaches wins.
_SEVERITY_BANDS = (
    (75, "critical"),
    (50, "high"),
    (25, "medium"),
    (1, "low"),
    (0, "informational"),
)

_RECOMMENDATIONS = {
    "informational": "No action required. Log the alert and close it if the rule is noisy.",
    "low": "Monitor. Correlate this alert with other events for the same host or user.",
    "medium": "Investigate during business hours. Review the account and host history.",
    "high": "Investigate now. Verify the activity and isolate the host if it is confirmed.",
    "critical": "Escalate immediately. Isolate the host, disable the account, and open an incident.",
}


def _is_external(ip: str) -> bool:
    """True when the address is routable on the public internet.

    ``is_global`` is the precise test: it excludes private, loopback,
    link-local, reserved, multicast, and the RFC 5737 documentation ranges
    that a lab feed sometimes uses as placeholders.
    """
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def _severity_for(score: int) -> str:
    for minimum, label in _SEVERITY_BANDS:
        if score >= minimum:
            return label
    return "informational"


def classify_severity(alert: Dict[str, Any]) -> Dict[str, Any]:
    """Score a validated alert and explain the result.

    Returns a dict with ``severity``, ``score``, and the ordered ``reasons``
    that produced the score.
    """
    score = 0
    reasons: List[str] = []

    source = alert.get("source") or {}
    event = alert.get("event") or {}
    indicators = alert.get("indicators") or []

    user = str(source.get("user") or "").strip().lower()
    if user and user in PRIVILEGED_ACCOUNTS:
        score += 50
        reasons.append(f"Privileged account '{source.get('user')}' is involved.")

    destination_ip = event.get("destination_ip")
    if destination_ip and _is_external(str(destination_ip)):
        score += 20
        reasons.append(f"Connection to external address {destination_ip}.")

    destination_port = event.get("destination_port")
    if isinstance(destination_port, int) and destination_port in SUSPICIOUS_PORTS:
        score += 15
        reasons.append(f"Destination port {destination_port} is commonly used by attacker tooling.")

    if indicators:
        score += 100
        reasons.append(
            f"{len(indicators)} indicator(s) treated as known-bad: {', '.join(str(i) for i in indicators)}."
        )

    severity = _severity_for(score)
    if not reasons:
        reasons.append("No rule matched; the alert carries no elevated signal on its own.")

    return {
        "severity": severity,
        "score": score,
        "reasons": reasons,
        "recommendation": _RECOMMENDATIONS[severity],
    }
