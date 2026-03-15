"""Elixir-specific AST analysis using tree-sitter."""

from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING

from diffguard.ast.python import Import
from diffguard.ast.scope import Scope

if TYPE_CHECKING:
    from pathlib import Path

    from tree_sitter import Node, Tree

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Scope detection
# ---------------------------------------------------------------------------

_SCOPE_DEF_TYPES: frozenset[str] = frozenset(
    {
        "defmodule",
        "def",
        "defp",
        "defmacro",
        "defmacrop",
        "defguard",
        "defguardp",
        "defprotocol",
        "defimpl",
    }
)

_DEF_TO_SCOPE_TYPE: dict[str, str] = {
    "defmodule": "module",
    "def": "function",
    "defp": "function",
    "defmacro": "macro",
    "defmacrop": "macro",
    "defguard": "guard",
    "defguardp": "guard",
    "defprotocol": "protocol",
    "defimpl": "implementation",
}


def find_elixir_scope(tree: Tree, line: int) -> Scope | None:
    """Find the innermost Elixir scope containing a 1-indexed line."""
    row = line - 1
    node = _find_innermost_scope_node(tree.root_node, row)
    if node is None:
        return None
    return _node_to_scope(node)


def _find_innermost_scope_node(root: Node, row: int) -> Node | None:
    """Walk the AST depth-first to find the innermost scope node containing the row."""
    best: Node | None = None

    for child in root.children:
        if not (child.start_point.row <= row <= child.end_point.row):
            continue

        if _is_elixir_scope_node(child) or child.type == "anonymous_function":
            best = child
            deeper = _find_innermost_scope_node(child, row)
            if deeper is not None:
                best = deeper
        else:
            deeper = _find_innermost_scope_node(child, row)
            if deeper is not None:
                best = deeper

    return best


def _is_elixir_scope_node(node: Node) -> bool:
    """Check if a node represents an Elixir scope definition (defmodule, def, etc.)."""
    if node.type != "call":
        return False
    target = node.child_by_field_name("target")
    if target is None or target.type != "identifier":
        return False
    return _node_text(target) in _SCOPE_DEF_TYPES


def _node_to_scope(node: Node) -> Scope:
    """Convert a tree-sitter scope node to a Scope dataclass."""
    if node.type == "anonymous_function":
        return Scope(
            type="anonymous_function",
            name="<fn>",
            start_line=int(node.start_point.row) + 1,
            end_line=int(node.end_point.row) + 1,
        )

    target = node.child_by_field_name("target")
    def_type = _node_text(target) if target is not None else ""
    scope_type = _DEF_TO_SCOPE_TYPE.get(def_type, "function")
    name = _get_scope_name(node, def_type)
    start_line = int(node.start_point.row) + 1
    end_line = int(node.end_point.row) + 1
    return Scope(type=scope_type, name=name, start_line=start_line, end_line=end_line)


def _get_scope_name(node: Node, def_type: str) -> str:
    """Extract the name from an Elixir scope node.

    For defmodule/defprotocol/defimpl: first argument is an alias node.
    For def/defp/defmacro: first argument is identifier (no-arg) or call (with args).
    For defguard: first argument is binary_operator (name(args) when guard_clause).
    """
    args_node = _get_arguments_node(node)
    if args_node is None:
        return "<anonymous>"

    first_arg = _first_named_child(args_node)
    if first_arg is None:
        return "<anonymous>"

    # Module/protocol/impl definitions use the alias directly
    if def_type in ("defmodule", "defprotocol", "defimpl"):
        return _node_text(first_arg)

    # Guard definitions: extract name from binary_operator or call
    if def_type in ("defguard", "defguardp"):
        return _extract_guard_name(first_arg)

    # Function/macro definitions: identifier or call(target=name)
    return _extract_callable_name(first_arg)


def _extract_guard_name(first_arg: Node) -> str:
    """Extract the guard name from a defguard's first argument."""
    # defguard is_positive(value) when ... → binary_operator with call on left
    if first_arg.type == "binary_operator":
        left = first_arg.child_by_field_name("left")
        if left is not None and left.type == "call":
            return _extract_callable_name(left)
    return _extract_callable_name(first_arg)


def _extract_callable_name(node: Node) -> str:
    """Extract the function/macro name from a def argument node."""
    if node.type == "identifier":
        return _node_text(node)
    if node.type == "call":
        target = node.child_by_field_name("target")
        if target is not None:
            return _node_text(target)
    return "<anonymous>"


def _get_arguments_node(node: Node) -> Node | None:
    """Get the arguments node from a call node."""
    for child in node.children:
        if child.type == "arguments":
            return child
    return None


def _first_named_child(node: Node) -> Node | None:
    """Get the first named child of a node."""
    for child in node.named_children:
        return child
    return None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _node_text(node: Node) -> str:
    """Get the UTF-8 text of a tree-sitter node."""
    if node.text is None:
        return ""
    return str(node.text, "utf-8")


def _camel_to_snake(name: str) -> str:
    """Convert CamelCase to snake_case.

    Examples: Accounts → accounts, UserRole → user_role, HTTPClient → http_client
    """
    name = re.sub(r"([A-Z\d]+)([A-Z][a-z])", r"\1_\2", name)
    name = re.sub(r"([a-z\d])([A-Z])", r"\1_\2", name)
    return name.lower()


def _module_to_path(module: str) -> str:
    """Convert an Elixir module name to a relative file path.

    MyApp.Accounts.User → my_app/accounts/user
    """
    parts = module.split(".")
    return "/".join(_camel_to_snake(part) for part in parts)


# ---------------------------------------------------------------------------
# Import extraction
# ---------------------------------------------------------------------------

_IMPORT_DIRECTIVES: frozenset[str] = frozenset({"alias", "import", "require", "use"})


def extract_elixir_imports(tree: Tree) -> list[Import]:
    """Extract all alias/import/require/use directives from a parsed Elixir AST."""
    imports: list[Import] = []
    _walk_imports(tree.root_node, imports)
    return imports


def _walk_imports(node: Node, imports: list[Import]) -> None:
    """Recursively walk the AST to find import directives."""
    for child in node.children:
        if child.type == "call":
            target = child.child_by_field_name("target")
            if target is not None and target.type == "identifier":
                directive = _node_text(target)
                if directive in _IMPORT_DIRECTIVES:
                    _parse_import_directive(child, directive, imports)
                    continue
        _walk_imports(child, imports)


def _parse_import_directive(node: Node, directive: str, imports: list[Import]) -> None:
    """Parse an alias/import/require/use call node into Import objects."""
    args_node = _get_arguments_node(node)
    if args_node is None:
        return

    first_arg = _first_named_child(args_node)
    if first_arg is None:
        return

    if directive == "alias":
        _parse_alias_directive(first_arg, args_node, imports)
    elif directive == "import":
        _parse_import_import_directive(first_arg, args_node, imports)
    elif directive in ("require", "use"):
        module = _node_text(first_arg)
        if module:
            imports.append(Import(module=module))


def _parse_alias_directive(first_arg: Node, args_node: Node, imports: list[Import]) -> None:
    """Parse an alias directive, handling both simple and multi-alias syntax."""
    if first_arg.type == "alias":
        # Simple alias: alias MyApp.Accounts.User
        module = _node_text(first_arg)
        alias_name = _extract_as_option(args_node)
        imports.append(Import(module=module, alias=alias_name))
    elif first_arg.type == "dot":
        # Multi-alias: alias MyApp.Accounts.{User, Role}
        left = first_arg.child_by_field_name("left")
        right = first_arg.child_by_field_name("right")
        if left is not None and right is not None and right.type == "tuple":
            base_module = _node_text(left)
            for child in right.named_children:
                if child.type == "alias":
                    sub_name = _node_text(child)
                    imports.append(Import(module=f"{base_module}.{sub_name}"))


def _parse_import_import_directive(first_arg: Node, args_node: Node, imports: list[Import]) -> None:
    """Parse an import directive, extracting only: option if present."""
    module = _node_text(first_arg)
    if not module:
        return

    only_names = _extract_only_option(args_node)
    if only_names is not None:
        imports.append(Import(module=module, names=only_names))
    else:
        imports.append(Import(module=module, is_star=True))


def _extract_as_option(args_node: Node) -> str | None:
    """Extract the `as:` option from a directive's keyword arguments."""
    for child in args_node.named_children:
        if child.type == "keywords":
            for pair in child.named_children:
                if pair.type == "pair":
                    key = pair.child_by_field_name("key")
                    if key is not None and _node_text(key).rstrip(": ") == "as":
                        value = pair.child_by_field_name("value")
                        if value is not None:
                            return _node_text(value)
    return None


def _extract_only_option(args_node: Node) -> list[str] | None:
    """Extract the `only:` option from an import directive's keyword arguments."""
    for child in args_node.named_children:
        if child.type == "keywords":
            for pair in child.named_children:
                if pair.type == "pair":
                    key_node = pair.child_by_field_name("key")
                    if key_node is None:
                        continue
                    key_text = _node_text(key_node).rstrip(": ")
                    if key_text == "only":
                        value = pair.child_by_field_name("value")
                        if value is not None and value.type == "list":
                            return _extract_keyword_names(value)
    return None


def _extract_keyword_names(list_node: Node) -> list[str]:
    """Extract function names from an only: keyword list like [from: 2, where: 2]."""
    names: list[str] = []
    for child in list_node.named_children:
        if child.type == "keywords":
            for pair in child.named_children:
                if pair.type == "pair":
                    key_node = pair.child_by_field_name("key")
                    if key_node is not None:
                        name = _node_text(key_node).rstrip(": ")
                        if name:
                            names.append(name)
    return names


# ---------------------------------------------------------------------------
# Symbol usage detection
# ---------------------------------------------------------------------------

_ELIXIR_BUILTINS: frozenset[str] = frozenset(
    {
        # Elixir stdlib modules
        "Kernel",
        "Enum",
        "Map",
        "List",
        "String",
        "IO",
        "File",
        "Path",
        "Agent",
        "GenServer",
        "Supervisor",
        "Task",
        "Logger",
        "Process",
        "Tuple",
        "Keyword",
        "MapSet",
        "Range",
        "Stream",
        "Regex",
        "Integer",
        "Float",
        "Atom",
        "Port",
        "System",
        "Code",
        "Macro",
        "Module",
        "Access",
        "Date",
        "DateTime",
        "Time",
        "NaiveDateTime",
        "Calendar",
        "URI",
        "Base",
        "Bitwise",
        "Exception",
        "Protocol",
        "Inspect",
        "Collectable",
        "Enumerable",
        "Application",
        "Config",
        "Mix",
        "ExUnit",
        # Erlang modules (atom form)
        ":erlang",
        ":ets",
        ":crypto",
        ":timer",
        ":gen_server",
        ":supervisor",
    }
)


def find_elixir_used_symbols(
    tree: Tree,
    start_line: int,
    end_line: int,
    *,
    exclude_builtins: bool = False,
) -> set[str]:
    """Find externally-referenced symbols in a line range (1-indexed, inclusive)."""
    defined: set[str] = set()
    used: set[str] = set()
    start_row = start_line - 1
    end_row = end_line - 1

    _collect_elixir_symbols(tree.root_node, start_row, end_row, defined, used)

    result = used - defined
    if exclude_builtins:
        result -= _ELIXIR_BUILTINS
    return result


def _collect_elixir_symbols(
    node: Node,
    start_row: int,
    end_row: int,
    defined: set[str],
    used: set[str],
) -> None:
    """Recursively collect defined and used symbols within a row range."""
    if node.end_point.row < start_row or node.start_point.row > end_row:
        return

    if node.type == "alias" and start_row <= node.start_point.row <= end_row:
        name = _node_text(node)
        # Module references like User, Repo — take first segment for dotted names
        top_module = name.split(".")[0]
        if _is_elixir_definition_site(node):
            defined.add(top_module)
        else:
            used.add(top_module)
    elif node.type == "identifier" and start_row <= node.start_point.row <= end_row:
        name = _node_text(node)
        if _is_elixir_def_name(node):
            defined.add(name)

    for child in node.children:
        _collect_elixir_symbols(child, start_row, end_row, defined, used)


def _is_elixir_definition_site(node: Node) -> bool:
    """Check if an alias node is in a definition position (defmodule, defprotocol, etc.)."""
    parent = node.parent
    if parent is None:
        return False
    # alias node as first argument to defmodule/defprotocol/defimpl
    if parent.type == "arguments":
        grandparent = parent.parent
        if grandparent is not None and grandparent.type == "call":
            target = grandparent.child_by_field_name("target")
            if target is not None and _node_text(target) in ("defmodule", "defprotocol", "defimpl"):
                # Only the first alias argument is the definition name
                first = _first_named_child(parent)
                return first == node
    return False


def _is_elixir_def_name(node: Node) -> bool:
    """Check if an identifier is the name in a def/defp/defmacro declaration."""
    parent = node.parent
    if parent is None:
        return False
    # Pattern: def list_users do ... → identifier is first child of arguments of a call(target=def)
    if parent.type == "arguments":
        grandparent = parent.parent
        if grandparent is not None and grandparent.type == "call":
            target = grandparent.child_by_field_name("target")
            if target is not None and _node_text(target) in _SCOPE_DEF_TYPES:
                first = _first_named_child(parent)
                return first == node
    # Pattern: def validate_attrs(data) → identifier is target of a call inside arguments
    if parent.type == "call":
        target = parent.child_by_field_name("target")
        if target == node:
            grandparent = parent.parent
            if grandparent is not None and grandparent.type == "arguments":
                great_grandparent = grandparent.parent
                if great_grandparent is not None and great_grandparent.type == "call":
                    gg_target = great_grandparent.child_by_field_name("target")
                    if gg_target is not None and _node_text(gg_target) in _SCOPE_DEF_TYPES:
                        return True
    return False


# ---------------------------------------------------------------------------
# mix.exs parsing and first-party detection
# ---------------------------------------------------------------------------

_mix_cache: dict[Path, tuple[str | None, set[str] | None]] = {}

_APP_NAME_RE = re.compile(r"app:\s*:(\w+)")
_DEP_NAME_RE = re.compile(r"""\{:(\w+)\s*,""")


def _load_mix_exs(project_root: Path) -> tuple[str | None, set[str] | None]:
    """Parse mix.exs to extract app name and dependency names.

    Returns (app_name, dep_names) tuple. Either may be None if not found.
    """
    if project_root in _mix_cache:
        return _mix_cache[project_root]

    mix_path = project_root / "mix.exs"
    result: tuple[str | None, set[str] | None] = (None, None)

    if mix_path.is_file():
        try:
            content = mix_path.read_text(encoding="utf-8")
            app_match = _APP_NAME_RE.search(content)
            app_name = app_match.group(1) if app_match else None

            deps: set[str] = set()
            # Find deps inside the deps function block
            deps_block = _extract_deps_block(content)
            if deps_block:
                for dep_match in _DEP_NAME_RE.finditer(deps_block):
                    deps.add(dep_match.group(1))

            result = (app_name, deps if deps else None)
        except OSError:
            pass

    _mix_cache[project_root] = result
    return result


def _extract_deps_block(content: str) -> str | None:
    """Extract the deps function body from mix.exs content."""
    # Find `defp deps do` or `def deps do` block
    match = re.search(r"defp?\s+deps\b.*?do\b(.*?)end", content, re.DOTALL)
    if match:
        return match.group(1)
    return None


def _app_name_to_namespace(app_name: str) -> str:
    """Convert a Mix app name to its Elixir namespace.

    :my_app → MyApp
    """
    return "".join(part.capitalize() for part in app_name.split("_"))


def clear_caches() -> None:
    """Clear mix.exs cache (useful for testing)."""
    _mix_cache.clear()


def is_first_party_elixir(
    module_or_path: str,
    project_root: Path,
    third_party_patterns: list[str] | None = None,
    *,
    is_relative: bool = False,
) -> bool:
    """Determine whether an Elixir module reference is first-party project code."""
    if is_relative:
        return True

    # Erlang atom modules and stdlib are never first-party
    if module_or_path.startswith(":") or module_or_path in _ELIXIR_BUILTINS:
        return False

    # Check against third-party patterns
    patterns = third_party_patterns if third_party_patterns is not None else []
    if any(pattern in module_or_path for pattern in patterns):
        return False

    # Load mix.exs info and check deps/project namespace
    app_name, dep_names = _load_mix_exs(project_root)
    return _is_project_module(module_or_path, app_name, dep_names)


def _is_project_module(module_or_path: str, app_name: str | None, dep_names: set[str] | None) -> bool:
    """Check if a module belongs to the project (not a dependency)."""
    # Check if module matches a known dependency
    if dep_names is not None:
        module_root = module_or_path.split(".")[0]
        for dep in dep_names:
            if module_root == _app_name_to_namespace(dep):
                return False

    # Check if module matches the project namespace
    if app_name is not None:
        project_namespace = _app_name_to_namespace(app_name)
        return module_or_path.startswith(project_namespace)

    return False


# ---------------------------------------------------------------------------
# Symbol resolution
# ---------------------------------------------------------------------------


def resolve_elixir_symbol(
    symbol: str,
    imports: list[Import],
    project_root: Path,
    _current_file: Path | None = None,
) -> Path | None:
    """Resolve an Elixir module name to a file path in the project."""
    # First, check if symbol matches an aliased import
    full_module = _resolve_alias(symbol, imports)

    # If no alias resolved it, use symbol directly
    if full_module is None:
        full_module = symbol

    # Try convention-based resolution: MyApp.Accounts.User → lib/my_app/accounts/user.ex
    rel_path = _module_to_path(full_module)

    candidate = project_root / "lib" / f"{rel_path}.ex"
    if candidate.is_file():
        return candidate

    # Umbrella project: check apps/*/lib/
    apps_dir = project_root / "apps"
    if apps_dir.is_dir():
        for app_dir in apps_dir.iterdir():
            if app_dir.is_dir():
                candidate = app_dir / "lib" / f"{rel_path}.ex"
                if candidate.is_file():
                    return candidate

    # Try project root directly
    candidate = project_root / f"{rel_path}.ex"
    if candidate.is_file():
        return candidate

    return None


def _resolve_alias(symbol: str, imports: list[Import]) -> str | None:
    """Resolve a short symbol name via alias imports.

    If `alias MyApp.Accounts.User` is in imports, symbol `User` resolves to
    `MyApp.Accounts.User`.
    """
    for imp in imports:
        # Explicit alias: alias MyApp.Accounts.User, as: U
        if imp.alias == symbol:
            return imp.module

        # Implicit alias: alias MyApp.Accounts.User → makes `User` available
        module_parts = imp.module.split(".")
        if module_parts and module_parts[-1] == symbol:
            return imp.module

    return None
