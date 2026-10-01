from __future__ import annotations

import argparse
import sys
from pathlib import Path

from mcp_audit import __version__
from mcp_audit.analysis.diff import diff_against_base, diff_revisions
from mcp_audit.analysis.scan import scan_path
from mcp_audit.models.finding import Severity
from mcp_audit.policy.evaluator import apply_policy
from mcp_audit.policy.loader import load_policy
from mcp_audit.reporters.json import render_json
from mcp_audit.reporters.markdown import render_diff_markdown
from mcp_audit.reporters.manifest import render_manifest
from mcp_audit.reporters.sarif import render_sarif
from mcp_audit.reporters.terminal import render_diff_terminal, render_terminal


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "scan":
            report = scan_path(args.target, require_tools=not args.allow_empty)
            policy = load_policy(args.policy)
            fail_on = Severity.parse(args.fail_on) if args.fail_on else None
            report = apply_policy(report, policy, fail_on)
            _write(_render(report, args.format), args.output)
            return 1 if report.result == "fail" else 0
        if args.command == "manifest":
            report = scan_path(args.target, require_tools=True)
            _write(render_manifest(report), args.output)
            return 0
        if args.command == "diff":
            report = _diff_report(args)
            policy = load_policy(args.policy)
            fail_on = Severity.parse(args.fail_on) if args.fail_on else None
            report = apply_policy(report, policy, fail_on)
            _write(_render(report, args.format), args.output)
            if args.sarif_output:
                _write(render_sarif(report), args.sarif_output)
            if args.summary_output:
                _write(
                    render_diff_markdown(report, current_label=args.summary_current_label),
                    args.summary_output,
                )
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
    scan.add_argument(
        "--allow-empty",
        action="store_true",
        help="allow a successful scan when no MCP tools are discovered",
    )
    _report_options(scan)

    manifest = subcommands.add_parser("manifest", help="generate a capability manifest")
    manifest.add_argument("target", nargs="?", default=".")
    manifest.add_argument("--output")

    diff = subcommands.add_parser("diff", help="compare MCP security posture across Git revisions")
    diff.add_argument("operands", nargs="*", help="target path, or BASE CURRENT revisions")
    diff.add_argument("--baseline", "--base", dest="baseline")
    diff.add_argument("--current", help="optional current Git revision; defaults to the working tree")
    diff.add_argument("--sarif-output", help="write newly introduced findings as SARIF")
    diff.add_argument("--summary-output", help="write a Markdown CI summary")
    diff.add_argument(
        "--summary-current-label",
        help="display label for the current revision in the Markdown summary",
    )
    _report_options(diff, formats=["terminal", "json", "sarif", "markdown"])

    policy = subcommands.add_parser("policy", help="policy utilities")
    policy_subcommands = policy.add_subparsers(dest="policy_command")
    check = policy_subcommands.add_parser("check", help="validate that a policy file can be loaded")
    check.add_argument("policy")
    return parser


def _report_options(parser: argparse.ArgumentParser, *, formats: list[str] | None = None) -> None:
    parser.add_argument("--format", choices=formats or ["terminal", "json", "sarif"], default="terminal")
    parser.add_argument("--output")
    parser.add_argument("--policy")
    parser.add_argument("--fail-on", choices=["low", "medium", "high", "critical"])


def _render(report, fmt: str) -> str:
    if fmt == "json":
        return render_json(report)
    if fmt == "sarif":
        return render_sarif(report)
    if fmt == "markdown" and hasattr(report, "base"):
        return render_diff_markdown(report)
    if hasattr(report, "base"):
        return render_diff_terminal(report)
    return render_terminal(report)


def _write(text: str, output: str | None) -> None:
    if output:
        Path(output).write_text(text, encoding="utf-8")
    else:
        print(text)


def _diff_report(args):
    if args.baseline:
        if len(args.operands) > 1:
            raise ValueError("diff accepts one target path when --baseline is used")
        target = args.operands[0] if args.operands else "."
        if args.current:
            return diff_revisions(args.baseline, args.current, target)
        return diff_against_base(args.baseline, target)
    if args.current:
        raise ValueError("--current requires --baseline")
    if len(args.operands) == 2:
        return diff_revisions(args.operands[0], args.operands[1])
    raise ValueError("use 'diff --baseline BASE [TARGET]' or 'diff BASE CURRENT'")
