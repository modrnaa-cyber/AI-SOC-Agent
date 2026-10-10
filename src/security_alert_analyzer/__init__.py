"""Security Alert Analyzer — an independent add-on for SamiGPT.

This package is intentionally self-contained. It imports nothing from the rest
of the project, so it can be tested, reused, or removed without touching the
original code base. It receives JSON security alerts, validates them against a
documented schema, classifies severity with an explainable rule set, and emits
a structured report as JSON and Markdown.

It does not call an LLM, does not query a SIEM, and does not perform any
response action. See docs/ADDON.md and SECURITY.md for the exact scope.
"""

from .report import analyze_alert, render_json, render_markdown
from .schema import AlertValidationError, validate_alert
from .severity import classify_severity

__all__ = [
    "AlertValidationError",
    "analyze_alert",
    "classify_severity",
    "render_json",
    "render_markdown",
    "validate_alert",
]

__version__ = "1.0.0"
