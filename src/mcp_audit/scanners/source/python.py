from __future__ import annotations

import ast
import os
import re
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

type FunctionNode = ast.FunctionDef | ast.AsyncFunctionDef
type SourceUnit = tuple[str, ast.Module, str, set[str], dict[str, FunctionNode]]


def scan_python_sources(root: Path) -> list[Tool]:
    files = _python_files(root)
    units: dict[Path, SourceUnit] = {}
    module_index: dict[str, Path] = {}

    for file_path in files:
        source_text, tree = _parse_source(file_path)
        context_path = file_path.name if root.is_file() else str(file_path.relative_to(root))
        functions = {
            node.name: node
            for node in tree.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
        units[file_path] = (source_text, tree, context_path, _path_guard_helpers(tree), functions)
        for module_name in _module_names(root, file_path):
            module_index[module_name] = file_path

    tools: list[Tool] = []
    for file_path, (source_text, tree, context_path, path_helpers, _) in units.items():
        visitor = FastMCPVisitor(file_path, source_text, context_path, path_helpers)
        visitor.visit(tree)
        tools.extend(visitor.tools)

    for file_path, unit in units.items():
        source_text, tree, context_path, _, _ = unit
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            registration = _tool_registration(node)
            if registration is None:
                continue
            decorator, target = registration
            resolved = _resolve_registered_function(target, file_path, units, module_index, root)
            if resolved is None:
                snippet = ast.get_source_segment(source_text, node) or ast.unparse(node)
                raise ValueError(f"cannot resolve registered MCP tool in {file_path}:{node.lineno}: {snippet}")
            target_file, function = resolved
            target_source, _, target_context, target_helpers, _ = units[target_file]
            tools.append(
                _tool_from_function(
                    target_file,
                    target_source,
                    target_context,
                    function,
                    path_helpers=target_helpers,
                    registered_decorator=decorator,
                    registered_context=_registered_tool_context(context_path, decorator),
                )
            )

    unique: dict[tuple[str, str, str], Tool] = {}
    for tool in tools:
        unique[(tool.source, tool.context, tool.name)] = tool
    return list(unique.values())


def _parse_source(file_path: Path) -> tuple[str, ast.Module]:
    try:
        source_text = file_path.read_text(encoding="utf-8")
        return source_text, ast.parse(source_text, filename=str(file_path))
    except SyntaxError as exc:
        raise ValueError(f"cannot parse Python source {file_path}:{exc.lineno}: {exc.msg}") from exc
    except UnicodeDecodeError as exc:
        raise ValueError(f"Python source is not UTF-8: {file_path}") from exc
    except OSError as exc:
        raise OSError(exc.errno, f"cannot read Python source {file_path}: {exc.strerror}", str(file_path)) from exc


def _python_files(root: Path) -> list[Path]:
    try:
        root.stat()
    except FileNotFoundError as exc:
        raise FileNotFoundError(f"scan target does not exist: {root}") from exc
    except OSError as exc:
        raise OSError(exc.errno, f"cannot access scan target {root}: {exc.strerror}", str(root)) from exc

    if root.is_file():
        if root.suffix != ".py":
            raise ValueError(f"scan target is not a Python file: {root}")
        return [root]
    if not root.is_dir():
        raise ValueError(f"scan target is not a file or directory: {root}")

    files: list[Path] = []

    def raise_walk_error(error: OSError) -> None:
        raise OSError(error.errno, f"cannot traverse scan target: {error.strerror}", error.filename) from error

    for directory, dirnames, filenames in os.walk(root, onerror=raise_walk_error):
        dirnames[:] = [name for name in dirnames if name not in {".git", ".venv", "venv", "__pycache__"}]
        base = Path(directory)
        files.extend(base / name for name in filenames if name.endswith(".py"))
    return sorted(files)


def _module_names(root: Path, file_path: Path) -> set[str]:
    relative = Path(file_path.name) if root.is_file() else file_path.relative_to(root)
    parts = list(relative.with_suffix("").parts)
    if parts and parts[-1] == "__init__":
        parts.pop()
    if not parts:
        return set()
    names = {".".join(parts)}
    if parts[0] in {"src", "lib"} and len(parts) > 1:
        names.add(".".join(parts[1:]))
    return names


def _tool_registration(node: ast.Call) -> tuple[ast.Call, ast.AST] | None:
    if not isinstance(node.func, ast.Call) or not node.args:
        return None
    decorator = node.func
    target = decorator.func
    if isinstance(target, ast.Attribute) and target.attr == "tool":
        return decorator, node.args[0]
    if isinstance(target, ast.Name) and target.id in {"tool", "mcp_tool"}:
        return decorator, node.args[0]
    return None


def _resolve_registered_function(
    target: ast.AST,
    registration_file: Path,
    units: dict[Path, SourceUnit],
    module_index: dict[str, Path],
    root: Path,
) -> tuple[Path, FunctionNode] | None:
    _, tree, _, _, local_functions = units[registration_file]
    if isinstance(target, ast.Name) and target.id in local_functions:
        return registration_file, local_functions[target.id]

    current_modules = _module_names(root, registration_file)
    current_module = min(current_modules, key=lambda value: (value.count("."), len(value)), default="")
    imported_functions: dict[str, tuple[str, str]] = {}
    module_aliases: dict[str, str] = {}
    for statement in tree.body:
        if isinstance(statement, ast.ImportFrom):
            module_name = _absolute_import_module(current_module, statement.module, statement.level)
            for alias in statement.names:
                imported_functions[alias.asname or alias.name] = (module_name, alias.name)
        elif isinstance(statement, ast.Import):
            for alias in statement.names:
                module_aliases[alias.asname or alias.name.split(".")[0]] = alias.name

    module_name = ""
    function_name = ""
    if isinstance(target, ast.Name) and target.id in imported_functions:
        module_name, function_name = imported_functions[target.id]
    elif isinstance(target, ast.Attribute):
        qualified = _call_name(target)
        if "." in qualified:
            owner, function_name = qualified.rsplit(".", 1)
            module_name = module_aliases.get(owner, owner)
    if not module_name or not function_name:
        return None
    target_file = module_index.get(module_name)
    if target_file is None:
        suffix_matches = {
            path
            for indexed_name, path in module_index.items()
            if indexed_name.endswith(f".{module_name}")
        }
        if len(suffix_matches) == 1:
            target_file = suffix_matches.pop()
    if target_file is None:
        return None
    function = units[target_file][4].get(function_name)
    return (target_file, function) if function is not None else None


def _absolute_import_module(current_module: str, imported_module: str | None, level: int) -> str:
    if level == 0:
        return imported_module or ""
    package = current_module.split(".")[:-1]
    keep = max(0, len(package) - (level - 1))
    prefix = package[:keep]
    if imported_module:
        prefix.extend(imported_module.split("."))
    return ".".join(prefix)


def _registered_tool_context(context_path: str, decorator: ast.Call) -> str:
    target = decorator.func
    if isinstance(target, ast.Attribute) and target.attr == "tool":
        owner = _call_name(target.value) or "mcp"
        return f"{context_path}:{owner}"
    return context_path


def _path_guard_helpers(tree: ast.Module) -> set[str]:
    helpers: set[str] = set()
    for node in tree.body:
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        text = ast.unparse(node).lower()
        has_resolution = any(token in text for token in {".resolve(", "realpath(", "abspath("})
        has_boundary_check = any(token in text for token in {"relative_to(", "is_relative_to("}) or (
            ".startswith(" in text
            and any(token in text for token in {"root", "vault", "base", "directory", "workspace", "allowed"})
        )
        has_rejection = any(isinstance(child, ast.Raise) for child in ast.walk(node)) or any(
            token in text for token in {"outside allowed", "path_violation", "path escapes", "return none"}
        )
        if has_resolution and has_boundary_check and has_rejection:
            helpers.add(node.name)
    return helpers


class FastMCPVisitor(ast.NodeVisitor):
    def __init__(self, file_path: Path, source_text: str, context_path: str, path_helpers: set[str]) -> None:
        self.file_path = file_path
        self.source_text = source_text
        self.context_path = context_path
        self.path_helpers = path_helpers
        self.tools: list[Tool] = []

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        if _is_tool_function(node):
            self.tools.append(
                _tool_from_function(
                    self.file_path,
                    self.source_text,
                    self.context_path,
                    node,
                    path_helpers=self.path_helpers,
                )
            )
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
    *,
    path_helpers: set[str] | None = None,
    registered_decorator: ast.Call | None = None,
    registered_context: str | None = None,
) -> Tool:
    name = _tool_name(node, registered_decorator)
    description = ast.get_docstring(node) or ""
    parameters = [_parameter(arg, node) for arg in node.args.args if arg.arg not in {"self", "cls"}]
    analyzer = FunctionAnalyzer(file_path, source_text, parameters, path_helpers or set())
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
    if _looks_external_write(name):
        capability.side_effect = "external_write"
        analyzer.evidence.append(
            Evidence(
                message="Tool name or description indicates an external write.",
                kind="side_effect",
                location=_function_location(file_path, node),
            )
        )
    if _looks_destructive(name, description):
        capability.destructive = True
        capability.side_effect = "destructive_action"
        analyzer.evidence.append(
            Evidence(
                message="Tool name or description indicates a destructive action.",
                kind="destructive",
                location=_function_location(file_path, node),
            )
        )
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
        context=registered_context or _tool_context(context_path, node),
        description=description,
        parameters=parameters,
        capability=capability,
        evidence=analyzer.evidence,
    )


class FunctionAnalyzer(ast.NodeVisitor):
    def __init__(
        self,
        file_path: Path,
        source_text: str,
        parameters: list[Parameter],
        path_helpers: set[str],
    ) -> None:
        self.file_path = file_path
        self.source_text = source_text
        self.parameter_names = {parameter.name for parameter in parameters}
        self.path_objects = {
            parameter.name
            for parameter in parameters
            if parameter.annotation and parameter.annotation.rsplit(".", 1)[-1] == "Path"
        }
        self.path_helpers = path_helpers
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
        self.inline_path_guard_lines: list[int] = []
        self.host_guard_lines: list[int] = []
        self.filesystem_operation_lines: list[int] = []
        self.network_call_lines: list[int] = []
        self.fixed_network_destination = False
        self.network_destination: str | None = None
        self.evidence: list[Evidence] = []

    def visit_Assign(self, node: ast.Assign) -> None:
        roots = self._parameter_roots(node.value)
        for target in node.targets:
            if isinstance(target, ast.Name):
                if roots:
                    self.aliases[target.id] = roots
                if _is_path_expression(node.value, self.path_objects):
                    self.path_objects.add(target.id)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        roots = self._parameter_roots(node.value)
        if isinstance(node.target, ast.Name):
            if roots:
                self.aliases[node.target.id] = roots
            annotation = ast.unparse(node.annotation).rsplit(".", 1)[-1]
            if annotation == "Path" or _is_path_expression(node.value, self.path_objects):
                self.path_objects.add(node.target.id)
        self.generic_visit(node)

    def visit_For(self, node: ast.For) -> None:
        roots = self._parameter_roots(node.iter)
        if isinstance(node.target, ast.Name) and roots:
            self.aliases[node.target.id] = roots
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        call_name = _call_name(node.func)
        if call_name.rsplit(".", 1)[-1] in self.path_helpers:
            roots = set().union(*(self._parameter_roots(argument) for argument in node.args))
            roots.update(
                set().union(*(self._parameter_roots(keyword.value) for keyword in node.keywords))
                if node.keywords
                else set()
            )
            if roots:
                self.path_guard_lines.append(node.lineno)
                self.path_guarded_parameters.update(roots)
                self._record(node, f"Tool input is constrained by approved-root helper {call_name}(...).", "filesystem_guard")
        if call_name in {"eval", "exec", "compile"}:
            self.arbitrary_code = True
            self._record(node, f"Dynamic {call_name}(...) executes model-controlled code.", "execution")
        if call_name in {"subprocess.run", "subprocess.call", "subprocess.Popen", "os.system"}:
            if call_name == "os.system" or _keyword_is_true(node, "shell"):
                self.shell_execution = True
                self._record(node, f"{call_name}(...) invokes a command through a shell.", "execution")
            elif call_name.startswith("subprocess.") and _has_model_controlled_executable(node, self._parameter_roots):
                self.shell_execution = True
                self._record(node, f"{call_name}(...) uses a model-controlled executable or interpreter payload.", "execution")
        if call_name in {"pexpect.spawn", "pexpect.spawnu"} and _has_model_controlled_executable(
            node, self._parameter_roots
        ):
            self.shell_execution = True
            self._record(node, f"{call_name}(...) starts a model-controlled interactive process.", "execution")
        open_access = _file_open_access(node, call_name)
        if open_access is not None:
            reads, writes = open_access
            if reads:
                self.filesystem_read = True
                self._record(node, "A filesystem read is reachable from this MCP tool.", "filesystem")
            if writes:
                self.filesystem_write = True
                self._record(node, "A filesystem write is reachable from this MCP tool.", "filesystem")
            self.filesystem_operation_lines.append(node.lineno)
            self._mark_inline_path_guard(node)
        if call_name in {"read_text", "read_bytes", "Path.read_text", "Path.read_bytes"} or call_name.endswith((".read_text", ".read_bytes")):
            self.filesystem_read = True
            self.filesystem_operation_lines.append(node.lineno)
            self._mark_inline_path_guard(node)
            self._record(node, "A filesystem read is reachable from this MCP tool.", "filesystem")
        if call_name in {"write_text", "write_bytes", "Path.write_text", "Path.write_bytes"} or call_name.endswith((".write_text", ".write_bytes")):
            self.filesystem_write = True
            self.filesystem_operation_lines.append(node.lineno)
            self._mark_inline_path_guard(node)
            self._record(node, "A filesystem write is reachable from this MCP tool.", "filesystem")
        if call_name in {
            "os.mkdir",
            "os.makedirs",
            "os.remove",
            "os.unlink",
            "os.rename",
            "os.replace",
            "shutil.copy",
            "shutil.copy2",
            "shutil.copyfile",
            "shutil.move",
            "shutil.rmtree",
        } or call_name.endswith((".mkdir", ".unlink", ".rename")) or _is_path_replace(
            node, call_name, self.path_objects
        ):
            self.filesystem_write = True
            self.filesystem_operation_lines.append(node.lineno)
            self._mark_inline_path_guard(node)
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
        return bool(self.path_guard_lines and self.filesystem_operation_lines) and all(
            any(guard < operation for guard in self.path_guard_lines)
            or operation in self.inline_path_guard_lines
            for operation in self.filesystem_operation_lines
        )

    def _mark_inline_path_guard(self, operation: ast.Call) -> None:
        for child in ast.walk(operation):
            if not isinstance(child, ast.Call) or child is operation:
                continue
            call_name = _call_name(child.func)
            if call_name.rsplit(".", 1)[-1] not in self.path_helpers:
                continue
            roots = set().union(*(self._parameter_roots(argument) for argument in child.args))
            if roots:
                self.inline_path_guard_lines.append(operation.lineno)
                self.path_guarded_parameters.update(roots)

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


def _tool_name(node: ast.FunctionDef | ast.AsyncFunctionDef, registered_decorator: ast.Call | None = None) -> str:
    decorators = ([registered_decorator] if registered_decorator is not None else []) + list(node.decorator_list)
    for decorator in decorators:
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


def _file_open_access(node: ast.Call, call_name: str) -> tuple[bool, bool] | None:
    if call_name != "open" and not call_name.endswith(".open"):
        return None
    mode_index = 1 if call_name == "open" else 0
    mode_node = node.args[mode_index] if len(node.args) > mode_index else _keyword_value(node, "mode")
    if mode_node is None:
        mode = "r"
    elif isinstance(mode_node, ast.Constant) and isinstance(mode_node.value, str):
        mode = mode_node.value
    else:
        return True, True
    writes = any(flag in mode for flag in "wax") or "+" in mode
    reads = "r" in mode or "+" in mode or not writes
    return reads, writes


def _is_path_expression(node: ast.AST | None, path_objects: set[str]) -> bool:
    if node is None:
        return False
    if isinstance(node, ast.Name):
        return node.id in path_objects
    if isinstance(node, ast.Call):
        call_name = _call_name(node.func)
        if call_name in {"Path", "pathlib.Path"}:
            return True
        if isinstance(node.func, ast.Attribute) and node.func.attr in {
            "absolute",
            "expanduser",
            "resolve",
            "with_name",
            "with_stem",
            "with_suffix",
        }:
            return _is_path_expression(node.func.value, path_objects)
    return False


def _is_path_replace(node: ast.Call, call_name: str, path_objects: set[str]) -> bool:
    if call_name in {"os.replace", "Path.replace", "pathlib.Path.replace"}:
        return True
    return (
        isinstance(node.func, ast.Attribute)
        and node.func.attr == "replace"
        and _is_path_expression(node.func.value, path_objects)
    )


def _has_model_controlled_executable(node: ast.Call, roots_for) -> bool:
    if not node.args:
        return False
    command = node.args[0]
    roots = roots_for(command)
    if not roots:
        return False
    if isinstance(command, (ast.List, ast.Tuple)) and command.elts:
        executable = command.elts[0]
        if isinstance(executable, ast.Constant) and isinstance(executable.value, str):
            return executable.value in {"bash", "sh", "zsh", "cmd", "powershell", "pwsh", "python", "python3"}
        return bool(roots_for(executable))
    return True


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
        token in text for token in {"root", "vault", "base", "directory", "workspace", "allowed"}
    )


def _is_select_query(node: ast.Call, call_name: str) -> bool:
    if not call_name.endswith(".execute") or not node.args:
        return False
    query = node.args[0]
    return isinstance(query, ast.Constant) and isinstance(query.value, str) and query.value.lstrip().lower().startswith("select")


def _data_classes(text: str) -> set[str]:
    return {classification for classification, tokens in SENSITIVE_TOKENS.items() if any(token in text for token in tokens)}


def _function_location(file_path: Path, node: ast.FunctionDef | ast.AsyncFunctionDef) -> Location:
    return Location(
        path=str(file_path),
        line=node.lineno,
        column=node.col_offset + 1,
        end_line=node.end_lineno,
        end_column=(node.end_col_offset + 1) if node.end_col_offset is not None else None,
    )


def _semantic_tokens(text: str) -> set[str]:
    return set(_semantic_words(text))


def _semantic_words(text: str) -> list[str]:
    return re.findall(r"[a-z0-9]+", text.lower())


def _highest_sensitivity(data_classes: set[str]) -> str:
    for value in ("secret", "pii", "financial", "confidential", "internal"):
        if value in data_classes:
            return value
    return "public"


def _looks_external_write(text: str) -> bool:
    words = _semantic_words(text)
    if words and words[0] in {"get", "list", "read", "search", "show", "monitor"}:
        return False
    return bool(set(words) & {"send", "forward", "publish", "post", "notify", "upload"})


def _looks_destructive(name: str, description: str) -> bool:
    name_words = _semantic_words(name)
    name_tokens = set(name_words)
    if name_words and name_words[0] in {"get", "list", "read", "search", "show", "monitor"}:
        return False
    destructive = {"delete", "drop", "remove", "revoke", "terminate", "destroy"}
    if name_tokens & destructive:
        return True
    normalized_description = " ".join(description.lower().split())
    if any(
        phrase in normalized_description
        for phrase in {"does not execute", "doesn't execute", "read-only", "strictly prohibited", "monitor only"}
    ):
        return False
    declares_destructive_action = bool(
        re.match(
            r"^(?:this tool\s+)?(?:delete|deletes|drop|drops|remove|removes|revoke|revokes|terminate|terminates|destroy|destroys)\b",
            normalized_description,
        )
    )
    execution_tool_describes_destructive_sql = bool(
        name_tokens & {"execute", "run", "apply"}
        and _semantic_tokens(normalized_description) & destructive
    )
    return declares_destructive_action or execution_tool_describes_destructive_sql
