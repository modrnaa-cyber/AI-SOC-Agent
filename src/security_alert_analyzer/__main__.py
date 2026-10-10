"""Command line entry point for the Security Alert Analyzer.

Usage:
    python -m src.security_alert_analyzer alerts.json --json-out report.json
    python -m src.security_alert_analyzer alerts.json --md-out report.md

The input file holds one alert object or a list of them. Invalid JSON, a
schema violation, or an unwritable output path exits non-zero with a message
on stderr — never a traceback and never a silent success.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, List, Optional

from .report import analyze_alert, render_json, render_markdown
from .schema import AlertValidationError, validate_alert


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="security_alert_analyzer",
        description="Validate, score, and report on JSON security alerts.",
    )
    parser.add_argument("input", help="Path to a JSON file: one alert object or a list of alerts.")
    parser.add_argument("--json-out", help="Write the JSON report to this path.")
    parser.add_argument("--md-out", help="Write the Markdown report to this path.")
    return parser


def _load_alerts(path: Path) -> List[Any]:
    if not path.is_file():
        raise FileNotFoundError(f"Input file not found: {path}")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"Input is not valid JSON: {exc}") from exc
    if isinstance(data, dict) and "alerts" in data:
        data = data["alerts"]
    return data if isinstance(data, list) else [data]


def _write(path_text: str, content: str) -> None:
    path = Path(path_text)
    if not path.parent.is_dir():
        raise NotADirectoryError(f"Output directory does not exist: {path.parent}")
    path.write_text(content, encoding="utf-8")


def main(argv: Optional[List[str]] = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        alerts = _load_alerts(Path(args.input))
        reports = [analyze_alert(validate_alert(alert)) for alert in alerts]
        payload: Any = reports if len(reports) != 1 else reports[0]
        if args.json_out:
            _write(args.json_out, render_json(payload))
        if args.md_out:
            _write(args.md_out, render_markdown(reports) if len(reports) != 1 else render_markdown(reports[0]))
    except (AlertValidationError, ValueError, FileNotFoundError, NotADirectoryError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if not args.json_out and not args.md_out:
        print(render_markdown(reports[0] if len(reports) == 1 else reports))
    else:
        for report in reports:
            print(f"{report['alert_id']}: {report['severity']} (score {report['score']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
