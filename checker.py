#!/usr/bin/env python3
"""Command-line interface for the Web Security Checker."""

from __future__ import annotations

import argparse
import html
import json
import sys
from pathlib import Path
from typing import Any, Optional

from websec import __version__
from websec.client import fetch_url
from websec.compare import compare_reports
from websec.policy import evaluate_policy
from websec.report import build_report
from websec.validators import normalize_target_url


EXIT_SUCCESS = 0
EXIT_POLICY_MISMATCH = 1
EXIT_ERROR = 2


def _inspect_report(args: argparse.Namespace) -> dict[str, Any]:
    """Fetch a URL once and build its security report."""
    normalized_url = normalize_target_url(args.url)
    response = fetch_url(
        normalized_url,
        timeout=args.timeout,
        follow_redirects=args.follow_redirects,
    )
    elapsed = getattr(response, "elapsed", None)
    response_time_ms = (
        int(elapsed.total_seconds() * 1000)
        if elapsed is not None and callable(getattr(elapsed, "total_seconds", None))
        else None
    )
    return build_report(
        input_url=normalized_url,
        final_url=response.url,
        status_code=response.status_code,
        response_time_ms=response_time_ms,
        response_headers=response.headers,
        redirect_location=response.headers.get("Location"),
        cookie_headers=getattr(response.raw, "headers", None),
    )


def _load_json(path: str) -> dict[str, Any]:
    """Read a JSON object from a local file."""
    with Path(path).open("r", encoding="utf-8") as input_file:
        data = json.load(input_file)
    if not isinstance(data, dict):
        raise ValueError(f"{path} must contain a JSON object.")
    return data


def _write_json(path: str, data: dict[str, Any]) -> None:
    """Write a JSON object to a local file."""
    with Path(path).open("w", encoding="utf-8") as output_file:
        json.dump(data, output_file, indent=2, ensure_ascii=False)
        output_file.write("\n")


def _write_html(path: str, title: str, data: dict[str, Any]) -> None:
    """Write a minimal HTML page containing an escaped JSON representation."""
    json_text = json.dumps(data, indent=2, ensure_ascii=False)
    page = (
        "<!doctype html>\n"
        '<html lang="en">\n<head>\n<meta charset="utf-8">\n'
        f"<title>{html.escape(title)}</title>\n</head>\n<body>\n"
        f"<h1>{html.escape(title)}</h1>\n"
        f"<pre>{html.escape(json_text)}</pre>\n"
        "</body>\n</html>\n"
    )
    with Path(path).open("w", encoding="utf-8") as output_file:
        output_file.write(page)


def _print_change_names(label: str, changes: dict[str, Any]) -> None:
    for category in ("added", "removed", "changed"):
        names = [entry["name"] for entry in changes.get(category, [])]
        shown_names = ", ".join(names) if names else "none"
        print(f"{label} {category}: {shown_names}")


def _print_compare_summary(result: dict[str, Any]) -> None:
    """Print changed header and cookie names."""
    _print_change_names("Headers", result.get("headers", {}))
    _print_change_names("Cookies", result.get("cookies", {}))


def _print_policy_summary(result: dict[str, Any]) -> None:
    """Print whether the policy matched and any neutral mismatch messages."""
    if result.get("matched"):
        print("Policy matched.")
        return
    for mismatch in result.get("mismatches", []):
        print(mismatch["message"])


def build_parser() -> argparse.ArgumentParser:
    """Create the command-line parser and its subcommands."""
    parser = argparse.ArgumentParser(
        description="Passive web-security header and cookie inspection for authorized targets."
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    inspect_parser = subparsers.add_parser("inspect", help="Inspect a URL.")
    _add_inspection_arguments(inspect_parser)

    compare_parser = subparsers.add_parser("compare", help="Compare two saved reports.")
    compare_parser.add_argument("baseline", help="Baseline report JSON path.")
    compare_parser.add_argument("current", help="Current report JSON path.")
    _add_output_arguments(compare_parser)

    check_parser = subparsers.add_parser("check", help="Inspect a URL against a policy.")
    _add_inspection_arguments(check_parser)
    check_parser.add_argument("--policy", required=True, help="Policy JSON path.")
    check_parser.add_argument(
        "--fail-on-policy-mismatch",
        action="store_true",
        help="Return a nonzero status when the policy does not match.",
    )

    return parser


def _add_output_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--output", metavar="PATH", help="Write JSON output to this path.")
    parser.add_argument(
        "--html-output", metavar="PATH", help="Write HTML output to this path."
    )


def _add_inspection_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("url", help="Target URL to inspect.")
    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="HTTP timeout in seconds (default: 10).",
    )
    parser.add_argument(
        "--follow-redirects",
        action="store_true",
        help="Follow HTTP redirects during the single request flow.",
    )
    _add_output_arguments(parser)


def _write_requested_outputs(args: argparse.Namespace, title: str, data: dict[str, Any]) -> None:
    if args.output:
        _write_json(args.output, data)
    if args.html_output:
        _write_html(args.html_output, title, data)


def _run_inspect(args: argparse.Namespace) -> int:
    report = _inspect_report(args)
    _write_requested_outputs(args, "Web Security Inspection Report", report)
    print(f"Inspection complete: {report['target']['final_url']}")
    return EXIT_SUCCESS


def _run_compare(args: argparse.Namespace) -> int:
    baseline = _load_json(args.baseline)
    current = _load_json(args.current)
    result = compare_reports(baseline, current)
    _write_requested_outputs(args, "Web Security Report Comparison", result)
    _print_compare_summary(result)
    return EXIT_SUCCESS


def _run_check(args: argparse.Namespace) -> int:
    report = _inspect_report(args)
    policy = _load_json(args.policy)
    policy_result = evaluate_policy(report, policy)
    report["policy"] = policy_result
    _write_requested_outputs(args, "Web Security Policy Check", report)
    _print_policy_summary(policy_result)
    if not policy_result.get("matched") and args.fail_on_policy_mismatch:
        return EXIT_POLICY_MISMATCH
    return EXIT_SUCCESS


def run(argv: Optional[list[str]] = None) -> int:
    """Parse arguments, execute the selected command, and report operational errors."""
    args = build_parser().parse_args(argv)
    try:
        if args.command == "inspect":
            return _run_inspect(args)
        if args.command == "compare":
            return _run_compare(args)
        return _run_check(args)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return EXIT_ERROR


def main() -> int:
    """Run the command-line interface."""
    return run()


if __name__ == "__main__":
    raise SystemExit(main())
