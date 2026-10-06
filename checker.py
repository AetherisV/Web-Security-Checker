#!/usr/bin/env python3
"""CLI entry point for the web-security checker."""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Optional

import requests

from websec import __version__
from websec.client import fetch_url
from websec.html_report import render_html_report
from websec.report import build_report
from websec.validators import normalize_target_url


def _write_output(path: str, payload: dict) -> None:
    output_path = Path(path)
    output_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def _write_html_output(path: str, payload: dict) -> None:
    output_path = Path(path)
    output_path.write_text(render_html_report(payload), encoding="utf-8")


def _build_error_report(input_url: str, message: str, *, final_url: Optional[str] = None) -> dict:
    notes = [
        "Authorization reminder: only inspect targets you own or are explicitly authorized to test.",
        f"Request failed: {message}",
    ]
    return build_report(
        input_url=input_url,
        final_url=final_url or input_url,
        status_code=None,
        response_time_ms=None,
        response_headers={},
        redirect_location=None,
        notes=notes,
    )


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Passive web-security header and cookie inspection for authorized targets.")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("url", help="Target URL to inspect.")
    parser.add_argument("--output", help="Write the JSON report to a file.")
    parser.add_argument("--html-output", metavar="FILE", help="Write a local HTML version of the JSON report.")
    parser.add_argument("--timeout", type=float, default=10.0, help="HTTP timeout in seconds (default: 10).")
    parser.add_argument("--follow-redirects", action="store_true", help="Follow HTTP redirects during the single request flow.")
    parser.add_argument("--verbose", action="store_true", help="Add extra informational notes to the JSON report.")
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    notes = [
        "Authorization reminder: only inspect targets you own or are explicitly authorized to test.",
    ]

    try:
        normalized_url = normalize_target_url(args.url)
    except ValueError as exc:
        report = _build_error_report(args.url, str(exc), final_url=args.url)
        if args.verbose:
            report["notes"].append("Verbose mode enabled.")
        if args.output:
            try:
                _write_output(args.output, report)
            except OSError as write_error:
                print(f"Failed to write output file: {write_error}", file=sys.stderr)
        print(json.dumps(report, indent=2))
        print(f"Invalid target URL: {exc}", file=sys.stderr)
        return 1

    if args.verbose:
        notes.append("Verbose mode enabled.")

    try:
        started_at = time.perf_counter()
        response = fetch_url(normalized_url, timeout=args.timeout, follow_redirects=args.follow_redirects)
        elapsed_ms = int(round((time.perf_counter() - started_at) * 1000))
        final_url = response.url
        redirect_location = response.headers.get("Location")
        report = build_report(
            input_url=normalized_url,
            final_url=final_url,
            status_code=response.status_code,
            response_time_ms=elapsed_ms,
            response_headers=dict(response.headers),
            redirect_location=redirect_location,
            notes=notes,
            cookie_headers=response.raw.headers,
        )
    except (requests.exceptions.RequestException, ValueError, OSError) as exc:
        report = _build_error_report(normalized_url, str(exc), final_url=normalized_url)
        if args.verbose:
            report["notes"].append("Verbose mode enabled.")
        print(f"Request failed: {exc}", file=sys.stderr)

    if args.output:
        try:
            _write_output(args.output, report)
        except OSError as write_error:
            print(f"Failed to write output file: {write_error}", file=sys.stderr)

    if args.html_output:
        try:
            _write_html_output(args.html_output, report)
        except OSError as write_error:
            print(f"Failed to write HTML output file: {write_error}", file=sys.stderr)

    print(json.dumps(report, indent=2))
    return 0 if report["target"]["status_code"] is not None else 1


if __name__ == "__main__":
    raise SystemExit(main())
