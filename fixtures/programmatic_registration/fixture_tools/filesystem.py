import os
from pathlib import Path
from typing import Literal


ALLOWED_ROOTS = [str(Path("data").resolve())]


def _validate_path(path: str) -> str:
    resolved = os.path.realpath(path)
    for root in ALLOWED_ROOTS:
        prefix = root if root.endswith(os.sep) else root + os.sep
        if resolved == root or resolved.startswith(prefix):
            return resolved
    raise ValueError("path is outside allowed roots")


def read_write_file(path: str, operation: Literal["read", "write"], content: str = "") -> str:
    resolved = _validate_path(path)
    if operation == "read":
        return Path(resolved).read_text(encoding="utf-8")
    Path(resolved).write_text(content, encoding="utf-8")
    return resolved
