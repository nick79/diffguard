"""JavaScript-specific AST analysis using tree-sitter."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import TYPE_CHECKING

from diffguard.ast.python import Import
from diffguard.ast.scope import Scope

if TYPE_CHECKING:
    from tree_sitter import Node, Tree

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Scope detection
# ---------------------------------------------------------------------------

_SCOPE_NODE_TYPES: frozenset[str] = frozenset(
    {
        "function_declaration",
        "generator_function_declaration",
        "arrow_function",
        "function_expression",
        "class_declaration",
        "method_definition",
    }
)

_NODE_TYPE_TO_SCOPE_TYPE: dict[str, str] = {
    "function_declaration": "function",
    "generator_function_declaration": "generator",
    "arrow_function": "arrow_function",
    "function_expression": "function",
    "class_declaration": "class",
    "method_definition": "method",
}

_WRAPPER_TYPES: frozenset[str] = frozenset({"variable_declaration", "lexical_declaration"})


def find_javascript_scope(tree: Tree, line: int) -> Scope | None:
    """Find the innermost JavaScript scope containing a 1-indexed line."""
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

        if child.type in _SCOPE_NODE_TYPES:
            best = child
            deeper = _find_innermost_scope_node(child, row)
            if deeper is not None:
                best = deeper
        elif child.type in _WRAPPER_TYPES:
            inner = _scope_from_wrapper(child)
            if inner is not None and inner.start_point.row <= row <= inner.end_point.row:
                best = inner
                deeper = _find_innermost_scope_node(inner, row)
                if deeper is not None:
                    best = deeper
        else:
            deeper = _find_innermost_scope_node(child, row)
            if deeper is not None:
                best = deeper

    return best


def _scope_from_wrapper(node: Node) -> Node | None:
    """Extract a scope node from a variable/lexical declaration wrapper."""
    for child in node.children:
        if child.type == "variable_declarator":
            value = child.child_by_field_name("value")
            if value is not None and value.type in _SCOPE_NODE_TYPES:
                return value
    return None


def _node_to_scope(node: Node) -> Scope:
    """Convert a tree-sitter scope node to a Scope dataclass."""
    scope_type = _NODE_TYPE_TO_SCOPE_TYPE[node.type]
    name = _get_scope_name(node)
    start_line, end_line = _get_effective_line_range(node)
    return Scope(type=scope_type, name=name, start_line=start_line, end_line=end_line)


def _get_scope_name(node: Node) -> str:
    """Extract the name from a scope node."""
    name_node = node.child_by_field_name("name")
    if name_node is not None and name_node.text is not None:
        return str(name_node.text, "utf-8")

    # Arrow functions / function expressions: get name from parent variable_declarator
    if node.type in ("arrow_function", "function_expression"):
        parent = node.parent
        if parent is not None and parent.type == "variable_declarator":
            var_name = parent.child_by_field_name("name")
            if var_name is not None and var_name.text is not None:
                return str(var_name.text, "utf-8")
    return "<anonymous>"


def _get_effective_line_range(node: Node) -> tuple[int, int]:
    """Get the 1-indexed line range for a scope node, including wrapper declarations."""
    start_node = node

    # For arrow_function / function_expression assigned via variable_declarator,
    # include the full variable/lexical declaration
    if node.type in ("arrow_function", "function_expression"):
        parent = node.parent
        if parent is not None and parent.type == "variable_declarator":
            grandparent = parent.parent
            if grandparent is not None and grandparent.type in _WRAPPER_TYPES:
                start_node = grandparent

    start_row = int(start_node.start_point.row)
    end_row = int(node.end_point.row)
    return (start_row + 1, end_row + 1)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _node_text(node: Node) -> str:
    """Get the UTF-8 text of a tree-sitter node."""
    if node.text is None:
        return ""
    return str(node.text, "utf-8")


# ---------------------------------------------------------------------------
# Import extraction
# ---------------------------------------------------------------------------


def extract_javascript_imports(tree: Tree) -> list[Import]:
    """Extract all import statements from a parsed JavaScript AST."""
    imports: list[Import] = []
    _walk_imports(tree.root_node, imports)
    return imports


def _walk_imports(node: Node, imports: list[Import]) -> None:
    """Recursively walk the AST to find import statements and require calls."""
    for child in node.children:
        if child.type == "import_statement":
            imp = _parse_es6_import(child)
            if imp is not None:
                imports.append(imp)
        elif child.type in _WRAPPER_TYPES:
            _extract_require_from_declaration(child, imports)
        elif child.type == "expression_statement":
            _extract_dynamic_import(child, imports)
        else:
            _walk_imports(child, imports)


def _parse_es6_import(node: Node) -> Import | None:
    """Parse an ES6 import statement."""
    source_node = node.child_by_field_name("source")
    if source_node is None:
        return None

    module = _strip_quotes(_node_text(source_node))
    is_relative = module.startswith("./") or module.startswith("../")

    names: list[str] = []
    name_aliases: list[tuple[str, str]] = []
    alias: str | None = None
    is_star = False

    for child in node.children:
        if child.type == "import_clause":
            _parse_import_clause(child, names, name_aliases)
            # Check for default import (identifier directly under import_clause)
            for clause_child in child.children:
                if clause_child.type == "identifier":
                    alias = _node_text(clause_child)
            # Check for namespace import
            for clause_child in child.children:
                if clause_child.type == "namespace_import":
                    is_star = True
                    for ns_child in clause_child.children:
                        if ns_child.type == "identifier":
                            alias = _node_text(ns_child)

    return Import(
        module=module,
        names=names if names else None,
        alias=alias,
        name_aliases=name_aliases,
        is_star=is_star,
        is_relative=is_relative,
    )


def _parse_import_clause(node: Node, names: list[str], name_aliases: list[tuple[str, str]]) -> None:
    """Parse the import clause to extract named imports."""
    for child in node.children:
        if child.type == "named_imports":
            for specifier in child.children:
                if specifier.type == "import_specifier":
                    name_node = specifier.child_by_field_name("name")
                    alias_node = specifier.child_by_field_name("alias")
                    if name_node is not None:
                        original = _node_text(name_node)
                        if alias_node is not None:
                            name_aliases.append((original, _node_text(alias_node)))
                        else:
                            names.append(original)


def _extract_require_from_declaration(node: Node, imports: list[Import]) -> None:
    """Extract require() calls from variable/lexical declarations."""
    for child in node.children:
        if child.type != "variable_declarator":
            continue
        imp = _parse_require_declarator(child)
        if imp is not None:
            imports.append(imp)


def _parse_require_declarator(declarator: Node) -> Import | None:
    """Parse a single variable_declarator that may contain a require() call."""
    module = _extract_require_module(declarator)
    if module is None:
        return None

    name_node = declarator.child_by_field_name("name")
    if name_node is None:
        return None

    is_relative = module.startswith("./") or module.startswith("../")
    if name_node.type == "object_pattern":
        return _parse_destructured_require(name_node, module, is_relative)

    alias = _node_text(name_node)
    return Import(module=module, alias=alias, is_relative=is_relative)


def _extract_require_module(declarator: Node) -> str | None:
    """Extract the module string from a require() call in a variable declarator."""
    value = declarator.child_by_field_name("value")
    if value is None or value.type != "call_expression":
        return None

    func = value.child_by_field_name("function")
    if func is None or _node_text(func) != "require":
        return None

    args = value.child_by_field_name("arguments")
    if args is None:
        return None

    return _extract_string_arg(args)


def _parse_destructured_require(pattern: Node, module: str, is_relative: bool) -> Import:
    """Parse destructured require: const { a, b } = require('...')."""
    names: list[str] = []
    name_aliases: list[tuple[str, str]] = []
    for child in pattern.children:
        if child.type == "shorthand_property_identifier_pattern":
            names.append(_node_text(child))
        elif child.type == "pair_pattern":
            key_node = child.child_by_field_name("key")
            value_node = child.child_by_field_name("value")
            if key_node is not None and value_node is not None:
                name_aliases.append((_node_text(key_node), _node_text(value_node)))
    return Import(
        module=module,
        names=names if names else None,
        name_aliases=name_aliases,
        is_relative=is_relative,
    )


def _extract_dynamic_import(node: Node, imports: list[Import]) -> None:
    """Extract dynamic import() expressions."""
    for child in node.children:
        if child.type == "call_expression":
            func = child.child_by_field_name("function")
            if func is not None and func.type == "import":
                args = child.child_by_field_name("arguments")
                if args is not None:
                    module = _extract_string_arg(args)
                    if module is not None:
                        is_relative = module.startswith("./") or module.startswith("../")
                        imports.append(Import(module=module, is_relative=is_relative))


def _extract_string_arg(args_node: Node) -> str | None:
    """Extract the first string literal argument from an arguments node."""
    for child in args_node.children:
        if child.type == "string":
            return _strip_quotes(_node_text(child))
    return None


def _strip_quotes(s: str) -> str:
    """Remove surrounding quotes from a string."""
    if len(s) >= 2 and s[0] in ("'", '"', "`") and s[-1] == s[0]:
        return s[1:-1]
    return s


# ---------------------------------------------------------------------------
# Symbol usage detection
# ---------------------------------------------------------------------------

_JS_BUILTINS: frozenset[str] = frozenset(
    {
        "console",
        "window",
        "document",
        "process",
        "global",
        "globalThis",
        "undefined",
        "NaN",
        "Infinity",
        "null",
        "true",
        "false",
        "Object",
        "Array",
        "String",
        "Number",
        "Boolean",
        "Symbol",
        "BigInt",
        "Map",
        "Set",
        "WeakMap",
        "WeakSet",
        "Promise",
        "Proxy",
        "Reflect",
        "RegExp",
        "Date",
        "Error",
        "TypeError",
        "RangeError",
        "ReferenceError",
        "SyntaxError",
        "URIError",
        "EvalError",
        "JSON",
        "Math",
        "parseInt",
        "parseFloat",
        "isNaN",
        "isFinite",
        "encodeURI",
        "decodeURI",
        "encodeURIComponent",
        "decodeURIComponent",
        "setTimeout",
        "setInterval",
        "clearTimeout",
        "clearInterval",
        "require",
        "module",
        "exports",
        "__dirname",
        "__filename",
        "Buffer",
        "fetch",
        "URL",
        "URLSearchParams",
        "TextEncoder",
        "TextDecoder",
        "AbortController",
        "AbortSignal",
        "FormData",
        "Headers",
        "Request",
        "Response",
        "Event",
        "EventTarget",
        "ReadableStream",
        "WritableStream",
        "TransformStream",
        "Blob",
        "File",
        "FileReader",
        "queueMicrotask",
        "structuredClone",
        "atob",
        "btoa",
    }
)

_JS_DEF_FIELD_LOOKUP: dict[str, str] = {
    "variable_declarator": "name",
    "function_declaration": "name",
    "generator_function_declaration": "name",
    "class_declaration": "name",
    "assignment_expression": "left",
}

_JS_ALWAYS_DEF_TYPES: frozenset[str] = frozenset(
    {
        "formal_parameters",
        "shorthand_property_identifier_pattern",
    }
)


def find_javascript_used_symbols(
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

    _collect_js_symbols(tree.root_node, start_row, end_row, defined, used)

    result = used - defined
    if exclude_builtins:
        result -= _JS_BUILTINS
    return result


def _collect_js_symbols(
    node: Node,
    start_row: int,
    end_row: int,
    defined: set[str],
    used: set[str],
) -> None:
    """Recursively collect defined and used identifiers within a row range."""
    if node.end_point.row < start_row or node.start_point.row > end_row:
        return

    if node.type == "identifier" and start_row <= node.start_point.row <= end_row:
        name = _node_text(node)
        if _is_js_definition_site(node):
            defined.add(name)
        elif not _is_js_attribute_access_field(node):
            used.add(name)

    for child in node.children:
        _collect_js_symbols(child, start_row, end_row, defined, used)


def _is_js_definition_site(node: Node) -> bool:
    """Check if an identifier node is in a name-definition position in JS."""
    parent = node.parent
    if parent is None:
        return False

    ptype = parent.type
    if ptype in _JS_ALWAYS_DEF_TYPES:
        return True
    field_name = _JS_DEF_FIELD_LOOKUP.get(ptype)
    if field_name is not None:
        return parent.child_by_field_name(field_name) == node
    return False


def _is_js_attribute_access_field(node: Node) -> bool:
    """Check if an identifier is the property part of member_expression (not the root object)."""
    parent = node.parent
    if parent is None or parent.type != "member_expression":
        return False
    return parent.child_by_field_name("property") == node


# ---------------------------------------------------------------------------
# First-party detection
# ---------------------------------------------------------------------------

_package_json_cache: dict[Path, dict[str, object] | None] = {}


def _load_package_json(project_root: Path) -> dict[str, object] | None:
    """Load and cache package.json from project root."""
    if project_root in _package_json_cache:
        return _package_json_cache[project_root]

    pkg_path = project_root / "package.json"
    result: dict[str, object] | None = None
    if pkg_path.is_file():
        try:
            raw = pkg_path.read_text(encoding="utf-8")
            data = json.loads(raw)
            if isinstance(data, dict):
                result = data
        except (OSError, json.JSONDecodeError):
            pass

    _package_json_cache[project_root] = result
    return result


def clear_package_json_cache() -> None:
    """Clear the package.json cache (useful for testing)."""
    _package_json_cache.clear()


_DEFAULT_JS_THIRD_PARTY_PATTERNS: list[str] = [
    "node_modules/",
    "bower_components/",
]


def is_first_party_js(
    module_or_path: str,
    project_root: Path,
    third_party_patterns: list[str] | None = None,
    *,
    is_relative: bool = False,
) -> bool:
    """Determine whether a JS import is first-party project code."""
    if is_relative:
        return True

    if _matches_package_json(module_or_path, project_root):
        return True

    patterns = third_party_patterns if third_party_patterns is not None else _DEFAULT_JS_THIRD_PARTY_PATTERNS

    # If it looks like a file path, check against patterns
    if "/" in module_or_path or "\\" in module_or_path:
        if any(pattern in module_or_path for pattern in patterns):
            return False
        try:
            return Path(module_or_path).resolve().is_relative_to(project_root.resolve())
        except (OSError, ValueError):
            return False

    # Bare specifier not matching package name → third-party
    return False


def _matches_package_json(module: str, project_root: Path) -> bool:
    """Check if a module matches the package.json name or workspaces."""
    pkg = _load_package_json(project_root)
    if pkg is None:
        return False

    pkg_name = pkg.get("name")
    if isinstance(pkg_name, str) and module == pkg_name:
        return True

    workspaces = pkg.get("workspaces")
    if isinstance(workspaces, list):
        return any(isinstance(ws, str) and module == ws for ws in workspaces)

    return False


# ---------------------------------------------------------------------------
# Symbol resolution
# ---------------------------------------------------------------------------

_JS_EXTENSIONS: list[str] = [".js", ".mjs", ".cjs", ".jsx"]


def resolve_javascript_symbol(
    symbol: str,
    imports: list[Import],
    project_root: Path,  # noqa: ARG001
    current_file: Path | None = None,
) -> Path | None:
    """Resolve an imported symbol name to a file path in the project."""
    source_import = _find_import_for_symbol(symbol, imports)
    if source_import is None:
        return None

    if source_import.is_relative:
        if current_file is None:
            return None
        return _resolve_relative_js_import(source_import.module, current_file)

    # Bare specifier — cannot resolve to a file without node_modules
    return None


def _find_import_for_symbol(symbol: str, imports: list[Import]) -> Import | None:
    """Find which import statement brings a symbol into scope."""
    for imp in imports:
        if imp.names is not None and symbol in imp.names:
            return imp
        for _original, alias_name in imp.name_aliases:
            if alias_name == symbol:
                return imp
        if imp.alias == symbol:
            return imp
        if imp.alias is None and imp.names is None and imp.module == symbol:
            return imp
    return None


def _resolve_relative_js_import(module: str, current_file: Path) -> Path | None:
    """Resolve a relative JS import to a file path."""
    base_dir = current_file.parent
    # Remove ./ or ../ prefix handled by Path resolution
    target = (base_dir / module).resolve()

    # Try exact path first
    if target.is_file():
        return target

    # Try with extensions
    for ext in _JS_EXTENSIONS:
        candidate = target.with_suffix(ext)
        if candidate.is_file():
            return candidate

    # Try index.js convention
    if target.is_dir():
        for ext in _JS_EXTENSIONS:
            candidate = target / f"index{ext}"
            if candidate.is_file():
                return candidate

    return None
