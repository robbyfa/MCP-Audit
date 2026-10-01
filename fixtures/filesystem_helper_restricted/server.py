from pathlib import Path

from fastmcp import FastMCP


ROOT = Path("vault").resolve()
mcp = FastMCP("filesystem-helper-restricted")


def _resolve(relative_path: str) -> Path:
    candidate = (ROOT / relative_path).resolve()
    try:
        candidate.relative_to(ROOT)
    except ValueError as exc:
        raise ValueError("path escapes the approved root") from exc
    return candidate


@mcp.tool()
def read_note(path: str) -> str:
    return _resolve(path).read_text(encoding="utf-8")


@mcp.tool()
def search_content(folder: str) -> list[str]:
    base = _resolve(folder)
    return [path.read_text(encoding="utf-8") for path in base.rglob("*.md")]


@mcp.tool()
def delete_note(path: str) -> None:
    _resolve(path).unlink()
