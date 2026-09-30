from __future__ import annotations

import ast
from pathlib import Path

from mcp_audit.models.capability import Capability, Parameter, Tool
from mcp_audit.models.finding import Evidence, Location


SENSITIVE_TOKENS = {
    "confidential": {"confidential", "private"},
    "financial": {"invoice", "payment", "payroll", "refund", "charge", "bank"},
    "pii": {"customer", "email", "employee", "person", "user", "pii"},
    "secret": {"secret", "token", "password", "credential", "api_key", "apikey"},
}
NETWORK_CALLS = {
    "requests.get", "requests.post", "requests.put", "requests.patch", "requests.delete",
    "requests.request", "httpx.get", "httpx.post", "httpx.put", "httpx.patch",
    "httpx.delete", "urllib.request.urlopen",
}
NETWORK_WRITES = {
    "requests.post", "requests.put", "requests.patch", "requests.delete",
    "httpx.post", "httpx.put", "httpx.patch", "httpx.delete",
}


def scan_python_sources(root: Path) -> list[Tool]:
    files = [root] if root.is_file() and root.suffix == ".py" else sorted(root.rglob("*.py"))
    tools: list[Tool] = []
    for file_path in files:
        if any(part in {".git", ".venv", "venv", "__pycache__"} for part in file_path.parts):
            continue
        try:
            source_text = file_path.read_text(encoding="utf-8")
            tree = ast.parse(source_text, filename=str(file_path))
        except (SyntaxError, UnicodeDecodeError):
            continue
        context_path = file_path.name if root.is_file() else str(file_path.relative_to(root))
        visitor = FastMCPVisitor(file_path, source_text, context_path)
        visitor.visit(tree)
        tools.extend(visitor.tools)
    return tools


class FastMCPVisitor(ast.NodeVisitor):
    def __init__(self, file_path: Path, source_text: str, context_path: str) -> None:
        self.file_path = file_path
        self.source_text = source_text
        self.context_path = context_path
        self.tools: list[Tool] = []

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        if _is_tool_function(node):
            self.tools.append(_tool_from_function(self.file_path, self.source_text, self.context_path, node))
        self.generic_visit(node)

    visit_AsyncFunctionDef = visit_FunctionDef


def _is_tool_function(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    for decorator in node.decorator_list:
        target = decorator.func if isinstance(decorator, ast.Call) else decorator
        if isinstance(target, ast.Attribute) and target.attr == "tool":
            return True
        if isinstance(target, ast.Name) and target.id in {"tool", "mcp_tool"}:
            return True
    return False


def _tool_from_function(
    file_path: Path,
    source_text: str,
    context_path: str,
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> Tool:
    name = _tool_name(node)
    description = ast.get_docstring(node) or ""
    parameters = [_parameter(arg, node) for arg in node.args.args if arg.arg not in {"self", "cls"}]
    analyzer = FunctionAnalyzer(file_path, source_text, parameters)
    analyzer.visit(node)
    capability = Capability()
    lower_text = f"{name.lower()} {description.lower()}"
    data_classes = _data_classes(lower_text)

    if analyzer.shell_execution:
        capability.execution = "shell"
    if analyzer.arbitrary_code:
        capability.execution = "arbitrary_code"
    if analyzer.filesystem_read:
        capability.filesystem = "allowlisted_files" if analyzer.path_guard else "unrestricted"
        capability.data_access.update(data_classes or {"internal"})
    if analyzer.database_read:
        capability.data_access.update(data_classes or {"internal"})
    if capability.data_access:
        capability.sensitivity = _highest_sensitivity(capability.data_access)
    if analyzer.filesystem_write:
        capability.filesystem = "allowlisted_files" if analyzer.path_guard else "unrestricted"
        capability.side_effect = "local_write"
    if analyzer.network_call:
        capability.network = "allowlisted_hosts" if analyzer.host_guard or analyzer.fixed_network_destination else "unrestricted_outbound"
        capability.network_destination = analyzer.network_destination
        if analyzer.network_write:
            capability.side_effect = "external_write"
    if _looks_external_write(lower_text):
        capability.side_effect = "external_write"
    if _looks_destructive(lower_text):
        capability.destructive = True
        capability.side_effect = "destructive_action"
    if "financial" in data_classes:
        capability.financial = True
        capability.data_access.add("financial")
    capability.requires_approval = _requires_approval(node) or _has_approval_guard(node)
    capability.audit_metadata = any(token in lower_text for token in {"audit", "trace", "request_id"})

    for parameter in parameters:
        if (
            analyzer.host_guard and parameter.name in analyzer.host_guarded_parameters
        ) or (
            analyzer.path_guard and parameter.name in analyzer.path_guarded_parameters
        ):
            parameter.bounded = True

    return Tool(
        name=name,
        source=f"{file_path}:{node.lineno}",
        context=_tool_context(context_path, node),
        description=description,
        parameters=parameters,
        capability=capability,
        evidence=analyzer.evidence,
    )


class FunctionAnalyzer(ast.NodeVisitor):
    def __init__(self, file_path: Path, source_text: str, parameters: list[Parameter]) -> None:
        self.file_path = file_path
        self.source_text = source_text
        self.parameter_names = {parameter.name for parameter in parameters}
        self.aliases: dict[str, set[str]] = {}
        self.host_guarded_parameters: set[str] = set()
        self.path_guarded_parameters: set[str] = set()
        self.shell_execution = False
        self.arbitrary_code = False
        self.filesystem_read = False
        self.filesystem_write = False
        self.database_read = False
        self.network_call = False
        self.network_write = False
        self.path_guard_lines: list[int] = []
        self.host_guard_lines: list[int] = []
        self.filesystem_operation_lines: list[int] = []
        self.network_call_lines: list[int] = []
        self.fixed_network_destination = False
        self.network_destination: str | None = None
        self.evidence: list[Evidence] = []

    def visit_Assign(self, node: ast.Assign) -> None:
        roots = self._parameter_roots(node.value)
        for target in node.targets:
            if isinstance(target, ast.Name) and roots:
                self.aliases[target.id] = roots
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        call_name = _call_name(node.func)
        if call_name in {"eval", "exec", "compile"}:
            self.arbitrary_code = True
            self._record(node, f"Dynamic {call_name}(...) executes model-controlled code.", "execution")
        if call_name in {"subprocess.run", "subprocess.call", "subprocess.Popen", "os.system"}:
            if call_name == "os.system" or _keyword_is_true(node, "shell"):
                self.shell_execution = True
                self._record(node, f"{call_name}(...) invokes a command through a shell.", "execution")
        if call_name in {"open", "read_text", "read_bytes", "Path.open", "Path.read_text", "Path.read_bytes"} or call_name.endswith((".read_text", ".read_bytes")):
            self.filesystem_read = True
            self.filesystem_operation_lines.append(node.lineno)
            self._record(node, "A filesystem read is reachable from this MCP tool.", "filesystem")
        if call_name in {"write_text", "write_bytes", "Path.write_text", "Path.write_bytes"} or call_name.endswith((".write_text", ".write_bytes")):
            self.filesystem_write = True
            self.filesystem_operation_lines.append(node.lineno)
            self._record(node, "A filesystem write is reachable from this MCP tool.", "filesystem")
        if call_name.endswith((".fetchone", ".fetchall", ".fetchmany")) or _is_select_query(node, call_name):
            self.database_read = True
            self._record(node, "A database read returns data through this MCP tool.", "data_access")
        if call_name in NETWORK_CALLS:
            self.network_call = True
            self.network_call_lines.append(node.lineno)
            self.network_write = self.network_write or call_name in NETWORK_WRITES
            argument = node.args[0] if node.args else _keyword_value(node, "url")
            roots = self._parameter_roots(argument)
            if isinstance(argument, ast.Constant) and isinstance(argument.value, str):
                self.fixed_network_destination = True
                self.network_destination = argument.value
            elif roots:
                self.network_destination = "unrestricted external URL"
            self._record(node, f"Tool input {', '.join(sorted(roots)) or 'data'} flows into {call_name}(...).", "network")
        self.generic_visit(node)

    def visit_If(self, node: ast.If) -> None:
        if _rejects_branch(node.body):
            roots = self._parameter_roots(node.test)
            if _is_host_allowlist_guard(node.test) and roots:
                self.host_guard_lines.append(node.lineno)
                self.host_guarded_parameters.update(roots)
                self._record(node.test, "Destination hostname is checked against an explicit allowlist.", "network_guard")
            if _is_path_root_guard(node.test) and roots:
                self.path_guard_lines.append(node.lineno)
                self.path_guarded_parameters.update(roots)
                self._record(node.test, "Resolved path is checked against an approved root.", "filesystem_guard")
            if _is_approval_guard(node.test):
                self._record(node.test, "The operation is rejected unless approval is present.", "approval")
        self.generic_visit(node)

    @property
    def host_guard(self) -> bool:
        return _guard_precedes_operations(self.host_guard_lines, self.network_call_lines)

    @property
    def path_guard(self) -> bool:
        return _guard_precedes_operations(self.path_guard_lines, self.filesystem_operation_lines)

    def _parameter_roots(self, node: ast.AST | None) -> set[str]:
        if node is None:
            return set()
        roots: set[str] = set()
        for child in ast.walk(node):
            if isinstance(child, ast.Name):
                if child.id in self.parameter_names:
                    roots.add(child.id)
                roots.update(self.aliases.get(child.id, set()))
        return roots

    def _record(self, node: ast.AST, message: str, kind: str) -> None:
        snippet = ast.get_source_segment(self.source_text, node)
        self.evidence.append(
            Evidence(
                message=message,
                kind=kind,
                snippet=snippet.strip() if snippet else None,
                location=Location(
                    path=str(self.file_path),
                    line=getattr(node, "lineno", 1),
                    column=getattr(node, "col_offset", 0) + 1,
                    end_line=getattr(node, "end_lineno", None),
                    end_column=(getattr(node, "end_col_offset", 0) + 1) if hasattr(node, "end_col_offset") else None,
                ),
            )
        )


def _tool_name(node: ast.FunctionDef | ast.AsyncFunctionDef) -> str:
    for decorator in node.decorator_list:
        if isinstance(decorator, ast.Call):
            for keyword in decorator.keywords:
                if keyword.arg == "name" and isinstance(keyword.value, ast.Constant):
                    return str(keyword.value.value)
    return node.name


def _tool_context(context_path: str, node: ast.FunctionDef | ast.AsyncFunctionDef) -> str:
    for decorator in node.decorator_list:
        target = decorator.func if isinstance(decorator, ast.Call) else decorator
        if isinstance(target, ast.Attribute) and target.attr == "tool":
            owner = _call_name(target.value) or "mcp"
            return f"{context_path}:{owner}"
    return context_path


def _parameter(arg: ast.arg, node: ast.FunctionDef | ast.AsyncFunctionDef) -> Parameter:
    annotation = ast.unparse(arg.annotation) if arg.annotation else None
    source = ast.unparse(node)
    bounded = any(token in source for token in {f"{arg.arg}.strip", f"len({arg.arg})", "max_length", "constr("})
    return Parameter(name=arg.arg, annotation=annotation, bounded=bounded)


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _call_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    if isinstance(node, ast.Call):
        return _call_name(node.func)
    return ""


def _keyword_is_true(node: ast.Call, name: str) -> bool:
    return any(keyword.arg == name and isinstance(keyword.value, ast.Constant) and keyword.value.value is True for keyword in node.keywords)


def _keyword_value(node: ast.Call, name: str) -> ast.AST | None:
    return next((keyword.value for keyword in node.keywords if keyword.arg == name), None)


def _requires_approval(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    for decorator in node.decorator_list:
        if isinstance(decorator, ast.Call):
            for keyword in decorator.keywords:
                if keyword.arg in {"requires_approval", "approval_required"} and isinstance(keyword.value, ast.Constant):
                    return bool(keyword.value.value)
    return False


def _has_approval_guard(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    return any(isinstance(child, ast.If) and _is_approval_guard(child.test) and _rejects_branch(child.body) for child in ast.walk(node))


def _is_approval_guard(node: ast.AST) -> bool:
    text = ast.unparse(node).lower()
    return any(token in text for token in {"approved", "approval", "confirmed", "confirm"})


def _rejects_branch(body: list[ast.stmt]) -> bool:
    return any(isinstance(child, (ast.Raise, ast.Return)) for statement in body for child in ast.walk(statement))


def _guard_precedes_operations(guard_lines: list[int], operation_lines: list[int]) -> bool:
    return bool(guard_lines and operation_lines) and all(any(guard < operation for guard in guard_lines) for operation in operation_lines)


def _is_host_allowlist_guard(node: ast.AST) -> bool:
    for comparison in (child for child in ast.walk(node) if isinstance(child, ast.Compare)):
        text = ast.unparse(comparison).lower()
        has_host = ".hostname" in text or ".netloc" in text
        has_membership = any(isinstance(operator, (ast.In, ast.NotIn)) for operator in comparison.ops)
        has_allowlist = any(isinstance(child, (ast.Set, ast.List, ast.Tuple)) for child in ast.walk(comparison)) or any(
            isinstance(child, ast.Name) and any(token in child.id.lower() for token in {"allowed", "allowlist", "trusted"})
            for child in ast.walk(comparison)
        )
        if has_host and has_membership and has_allowlist:
            return True
    return False


def _is_path_root_guard(node: ast.AST) -> bool:
    text = ast.unparse(node).lower()
    return (".parents" in text or "relative_to(" in text or "is_relative_to(" in text) and any(
        token in text for token in {"root", "base", "directory", "workspace"}
    )


def _is_select_query(node: ast.Call, call_name: str) -> bool:
    if not call_name.endswith(".execute") or not node.args:
        return False
    query = node.args[0]
    return isinstance(query, ast.Constant) and isinstance(query.value, str) and query.value.lstrip().lower().startswith("select")


def _data_classes(text: str) -> set[str]:
    return {classification for classification, tokens in SENSITIVE_TOKENS.items() if any(token in text for token in tokens)}


def _highest_sensitivity(data_classes: set[str]) -> str:
    for value in ("secret", "pii", "financial", "confidential", "internal"):
        if value in data_classes:
            return value
    return "public"


def _looks_external_write(text: str) -> bool:
    return any(token in text for token in {"send", "email", "slack", "webhook", "publish", "post", "message"})


def _looks_destructive(text: str) -> bool:
    return any(token in text for token in {"delete", "drop", "remove", "revoke", "terminate", "destroy"})
