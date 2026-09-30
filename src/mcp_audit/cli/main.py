from __future__ import annotations

import argparse
import sys
from pathlib import Path

from mcp_audit import __version__
from mcp_audit.analysis.diff import diff_against_base
from mcp_audit.analysis.scan import scan_path
from mcp_audit.models.finding import Severity
from mcp_audit.policy.evaluator import apply_policy
from mcp_audit.policy.loader import load_policy
from mcp_audit.reporters.json import render_json
from mcp_audit.reporters.manifest import render_manifest
from mcp_audit.reporters.sarif import render_sarif
from mcp_audit.reporters.terminal import render_diff_terminal, render_terminal


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "scan":
            report = scan_path(args.target)
            policy = load_policy(args.policy)
            fail_on = Severity.parse(args.fail_on) if args.fail_on else None
            report = apply_policy(report, policy, fail_on)
            _write(_render(report, args.format), args.output)
            return 1 if report.result == "fail" else 0
        if args.command == "manifest":
            report = scan_path(args.target)
            _write(render_manifest(report), args.output)
            return 0
        if args.command == "diff":
            report = diff_against_base(args.base, args.target)
            policy = load_policy(args.policy)
            fail_on = Severity.parse(args.fail_on) if args.fail_on else None
            report = apply_policy(report, policy, fail_on)
            _write(_render(report, args.format), args.output)
            return 1 if report.result == "fail" else 0
        if args.command == "policy" and args.policy_command == "check":
            policy = load_policy(args.policy)
            expired = policy.expired_suppressions()
            if expired:
                for suppression in expired:
                    print(
                        f"Expired suppression: {suppression.rule_id} "
                        f"({suppression.tool or 'all tools'}) expired {suppression.expires}",
                        file=sys.stderr,
                    )
                return 1
            print(f"Policy OK: {args.policy}")
            return 0
    except Exception as exc:
        print(f"mcp-audit: {exc}", file=sys.stderr)
        return 2
    parser.print_help()
    return 2


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="mcp-audit", description="Security regression scanner for MCP servers.")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subcommands = parser.add_subparsers(dest="command")

    scan = subcommands.add_parser("scan", help="scan local source")
    scan.add_argument("target", nargs="?", default=".")
    _report_options(scan)

    manifest = subcommands.add_parser("manifest", help="generate a capability manifest")
    manifest.add_argument("target", nargs="?", default=".")
    manifest.add_argument("--output")

    diff = subcommands.add_parser("diff", help="compare the current tree with a git baseline")
    diff.add_argument("target", nargs="?", default=".")
    diff.add_argument("--base", required=True)
    _report_options(diff)

    policy = subcommands.add_parser("policy", help="policy utilities")
    policy_subcommands = policy.add_subparsers(dest="policy_command")
    check = policy_subcommands.add_parser("check", help="validate that a policy file can be loaded")
    check.add_argument("policy")
    return parser


def _report_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--format", choices=["terminal", "json", "sarif"], default="terminal")
    parser.add_argument("--output")
    parser.add_argument("--policy")
    parser.add_argument("--fail-on", choices=["low", "medium", "high", "critical"])


def _render(report, fmt: str) -> str:
    if fmt == "json":
        return render_json(report)
    if fmt == "sarif":
        return render_sarif(report)
    if hasattr(report, "base"):
        return render_diff_terminal(report)
    return render_terminal(report)


def _write(text: str, output: str | None) -> None:
    if output:
        Path(output).write_text(text, encoding="utf-8")
    else:
        print(text)
