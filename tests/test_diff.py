from __future__ import annotations

import subprocess
from pathlib import Path

from mcp_audit.analysis.diff import diff_against_base
from mcp_audit.reporters.terminal import render_diff_terminal


BASE_SERVER = '''\
import requests
from fastmcp import FastMCP

mcp = FastMCP("diff")

@mcp.tool()
def fetch_status() -> str:
    return requests.get("https://api.example.com/status").text
'''

EXPANDED_SERVER = '''\
import requests
from fastmcp import FastMCP

mcp = FastMCP("diff")

@mcp.tool()
def fetch_status(url: str) -> str:
    return requests.get(url).text
'''


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True)


def test_security_diff_focuses_on_regressions(tmp_path: Path) -> None:
    server = tmp_path / "server.py"
    server.write_text(BASE_SERVER, encoding="utf-8")
    _git(tmp_path, "init")
    _git(tmp_path, "config", "user.email", "tests@example.com")
    _git(tmp_path, "config", "user.name", "MCP Audit Tests")
    _git(tmp_path, "add", "server.py")
    _git(tmp_path, "commit", "-m", "baseline")
    server.write_text(EXPANDED_SERVER, encoding="utf-8")

    report = diff_against_base("HEAD", tmp_path)

    assert report.risk_before == 0
    assert report.risk_after > report.risk_before
    assert report.changed_tools == ["fetch_status"]
    assert any(change.capability == "network" for change in report.capability_changes)
    assert {finding.rule_id for finding in report.new_findings} >= {"MCP003", "MCP007"}
    assert "MCP016" in {finding.rule_id for finding in report.findings}
    output = render_diff_terminal(report)
    assert "MCP SECURITY DIFF" in output
    assert "Risk\n0 ->" in output
    assert "+ MCP003 HIGH" in output


def test_diff_json_uses_diff_schema(tmp_path: Path) -> None:
    server = tmp_path / "server.py"
    server.write_text(BASE_SERVER, encoding="utf-8")
    _git(tmp_path, "init")
    _git(tmp_path, "config", "user.email", "tests@example.com")
    _git(tmp_path, "config", "user.name", "MCP Audit Tests")
    _git(tmp_path, "add", "server.py")
    _git(tmp_path, "commit", "-m", "baseline")
    server.write_text(EXPANDED_SERVER, encoding="utf-8")

    payload = diff_against_base("HEAD", tmp_path).as_dict()
    assert payload["schema_version"] == "1.0"
    assert payload["report_type"] == "diff"
    assert payload["summary"]["new_findings"] >= 2
