from __future__ import annotations

from pathlib import Path

import pytest

from mcp_audit.analysis.diff import _build_diff
from mcp_audit.analysis.scan import scan_path
from mcp_audit.policy.evaluator import apply_policy
from mcp_audit.policy.loader import Policy
from mcp_audit.reporters.json import render_json
from mcp_audit.reporters.manifest import render_manifest
from mcp_audit.reporters.sarif import render_sarif
from mcp_audit.reporters.terminal import render_diff_terminal, render_terminal


ROOT = Path(__file__).resolve().parents[1]
GOLDEN = Path(__file__).parent / "golden"

BASE_SERVER = '''\
import requests
from fastmcp import FastMCP
mcp = FastMCP("golden")

@mcp.tool()
def fetch_status() -> str:
    return requests.get("https://api.example.com/status").text
'''

HEAD_SERVER = '''\
import requests
from fastmcp import FastMCP
mcp = FastMCP("golden")

@mcp.tool()
def fetch_status(url: str) -> str:
    return requests.get(url).text
'''


@pytest.mark.parametrize(
    ("golden_name", "actual"),
    [
        ("terminal.txt", render_terminal(apply_policy(scan_path(ROOT / "fixtures/url_arbitrary"), Policy()))),
        ("scan.json", render_json(scan_path(ROOT / "fixtures/url_allowlisted"))),
        ("scan.sarif.json", render_sarif(scan_path(ROOT / "fixtures/url_arbitrary"))),
        ("manifest.yaml", render_manifest(scan_path(ROOT / "fixtures/safe_server"))),
    ],
)
def test_scan_outputs_match_golden(golden_name: str, actual: str) -> None:
    assert _normalize(actual).rstrip("\n") == (GOLDEN / golden_name).read_text(encoding="utf-8").rstrip("\n")


def test_diff_output_matches_golden(tmp_path: Path) -> None:
    base = tmp_path / "base"
    head = tmp_path / "head"
    base.mkdir()
    head.mkdir()
    (base / "server.py").write_text(BASE_SERVER, encoding="utf-8")
    (head / "server.py").write_text(HEAD_SERVER, encoding="utf-8")
    report = _build_diff("origin/main", scan_path(base), scan_path(head))
    apply_policy(report, Policy())
    actual = render_diff_terminal(report).replace(str(tmp_path.resolve()), "<TMP>")
    assert actual == (GOLDEN / "diff.txt").read_text(encoding="utf-8").rstrip("\n")


def _normalize(value: str) -> str:
    return value.replace(str(ROOT), "<ROOT>")
