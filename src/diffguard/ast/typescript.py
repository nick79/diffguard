"""TypeScript-specific AST analysis using tree-sitter."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from diffguard.ast.javascript import (
    _JS_BUILTINS,
    _extract_dynamic_import,
    _extract_require_from_declaration,
    _find_import_for_symbol,
    _get_effective_line_range,
    _get_scope_name,
    _node_text,
    _scope_from_wrapper,
    _strip_quotes,
    is_first_party_js,
)
from diffguard.ast.python import Import
from diffguard.ast.scope import Scope

if TYPE_CHECKING:
    from pathlib import Path

    from tree_sitter import Node, Tree

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Scope detection
# ---------------------------------------------------------------------------

# TypeScript reuses all JS scope types plus TS-specific ones
_TS_SCOPE_NODE_TYPES: frozenset[str] = frozenset(
    {
        "function_declaration",
        "generator_function_declaration",
        "arrow_function",
        "function_expression",
        "class_declaration",
        "method_definition",
        "internal_module",
    }
)

_TS_NODE_TYPE_TO_SCOPE_TYPE: dict[str, str] = {
    "function_declaration": "function",
    "generator_function_declaration": "generator",
    "arrow_function": "arrow_function",
    "function_expression": "function",
    "class_declaration": "class",
    "method_definition": "method",
    "internal_module": "namespace",
}

_TS_WRAPPER_TYPES: frozenset[str] = frozenset({"variable_declaration", "lexical_declaration", "expression_statement"})


def find_typescript_scope(tree: Tree, line: int) -> Scope | None:
    """Find the innermost TypeScript scope containing a 1-indexed line."""
    row = line - 1
    node = _find_ts_innermost_scope_node(tree.root_node, row)
    if node is None:
        return None
    return _ts_node_to_scope(node)


def _find_ts_innermost_scope_node(root: Node, row: int) -> Node | None:
    """Walk the AST depth-first to find the innermost scope node containing the row."""
    best: Node | None = None

    for child in root.children:
        if not (child.start_point.row <= row <= child.end_point.row):
            continue

        if child.type in _TS_SCOPE_NODE_TYPES:
            best = child
            deeper = _find_ts_innermost_scope_node(child, row)
            if deeper is not None:
                best = deeper
        elif child.type in _TS_WRAPPER_TYPES:
            inner = _ts_scope_from_wrapper(child)
            if inner is not None and inner.start_point.row <= row <= inner.end_point.row:
                best = inner
                deeper = _find_ts_innermost_scope_node(inner, row)
                if deeper is not None:
                    best = deeper
            else:
                deeper = _find_ts_innermost_scope_node(child, row)
                if deeper is not None:
                    best = deeper
        else:
            deeper = _find_ts_innermost_scope_node(child, row)
            if deeper is not None:
                best = deeper

    return best


def _ts_scope_from_wrapper(node: Node) -> Node | None:
    """Extract a scope node from a wrapper (variable/lexical declaration or expression_statement)."""
    if node.type == "expression_statement":
        for child in node.children:
            if child.type in _TS_SCOPE_NODE_TYPES:
                return child
        return None
    return _scope_from_wrapper(node)


def _ts_node_to_scope(node: Node) -> Scope:
    """Convert a tree-sitter scope node to a Scope dataclass."""
    scope_type = _TS_NODE_TYPE_TO_SCOPE_TYPE[node.type]
    name = _get_scope_name(node)
    start_line, end_line = _get_effective_line_range(node)
    return Scope(type=scope_type, name=name, start_line=start_line, end_line=end_line)


# ---------------------------------------------------------------------------
# Import extraction
# ---------------------------------------------------------------------------


def extract_typescript_imports(tree: Tree) -> list[Import]:
    """Extract all import statements from a parsed TypeScript AST.

    Handles ES6 imports (including type-only and inline type imports),
    require() calls, and dynamic import() expressions.
    """
    imports: list[Import] = []
    _walk_ts_imports(tree.root_node, imports)
    return imports


def _walk_ts_imports(node: Node, imports: list[Import]) -> None:
    """Recursively walk the AST to find import statements and require calls."""
    for child in node.children:
        if child.type == "import_statement":
            imp = _parse_ts_import(child)
            if imp is not None:
                imports.append(imp)
        elif child.type in ("variable_declaration", "lexical_declaration"):
            _extract_require_from_declaration(child, imports)
        elif child.type == "expression_statement":
            _extract_dynamic_import(child, imports)
        else:
            _walk_ts_imports(child, imports)


def _parse_ts_import(node: Node) -> Import | None:
    """Parse a TypeScript import statement, including type-only imports."""
    source_node = node.child_by_field_name("source")
    if source_node is None:
        return None

    module = _strip_quotes(_node_text(source_node))
    is_relative = module.startswith("./") or module.startswith("../")

    # Check for top-level `import type { ... }` — the "type" keyword is a direct child
    is_type_only = any(child.type == "type" for child in node.children)

    names: list[str] = []
    name_aliases: list[tuple[str, str]] = []
    alias: str | None = None
    is_star = False

    for child in node.children:
        if child.type == "import_clause":
            _parse_ts_import_clause(child, names, name_aliases, is_type_only)
            for clause_child in child.children:
                if clause_child.type == "identifier":
                    alias = _node_text(clause_child)
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


def _parse_ts_import_clause(
    node: Node,
    names: list[str],
    name_aliases: list[tuple[str, str]],
    is_type_only: bool,
) -> None:
    """Parse the import clause to extract named imports, handling inline type specifiers."""
    if is_type_only:
        # Entire import is type-only — no runtime names to extract
        return

    for child in node.children:
        if child.type == "named_imports":
            for specifier in child.children:
                if specifier.type == "import_specifier":
                    # Check if this specifier has a "type" modifier (inline type import)
                    has_type_modifier = any(sc.type == "type" for sc in specifier.children)
                    if has_type_modifier:
                        # Skip type-only specifiers — they don't bring runtime values
                        continue

                    name_node = specifier.child_by_field_name("name")
                    alias_node = specifier.child_by_field_name("alias")
                    if name_node is not None:
                        original = _node_text(name_node)
                        if alias_node is not None:
                            name_aliases.append((original, _node_text(alias_node)))
                        else:
                            names.append(original)


# ---------------------------------------------------------------------------
# Symbol usage detection
# ---------------------------------------------------------------------------

# TypeScript adds a few built-in type names/globals on top of JS
_TS_EXTRA_BUILTINS: frozenset[str] = frozenset(
    {
        "unknown",
        "never",
        "void",
        "any",
        "Readonly",
        "Partial",
        "Required",
        "Pick",
        "Omit",
        "Record",
        "Exclude",
        "Extract",
        "NonNullable",
        "ReturnType",
        "Parameters",
        "ConstructorParameters",
        "InstanceType",
        "ThisType",
        "Awaited",
        "keyof",
        "typeof",
        "infer",
    }
)

_TS_BUILTINS: frozenset[str] = _JS_BUILTINS | _TS_EXTRA_BUILTINS


_TS_ALWAYS_DEF_TYPES: frozenset[str] = frozenset(
    {
        "formal_parameters",
        "shorthand_property_identifier_pattern",
        "required_parameter",
        "optional_parameter",
    }
)


def find_typescript_used_symbols(
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

    _collect_ts_symbols(tree.root_node, start_row, end_row, defined, used)

    result = used - defined
    if exclude_builtins:
        result -= _TS_BUILTINS
    return result


def _collect_ts_symbols(
    node: Node,
    start_row: int,
    end_row: int,
    defined: set[str],
    used: set[str],
) -> None:
    """Recursively collect defined and used identifiers within a row range.

    Extends JS collection with TypeScript-specific definition sites
    (required_parameter, optional_parameter for typed function params).
    """
    if node.end_point.row < start_row or node.start_point.row > end_row:
        return

    if node.type == "identifier" and start_row <= node.start_point.row <= end_row:
        name = _node_text(node)
        if _is_ts_definition_site(node):
            defined.add(name)
        elif not _is_ts_attribute_access_field(node) and not _is_type_position(node):
            used.add(name)

    for child in node.children:
        _collect_ts_symbols(child, start_row, end_row, defined, used)


def _is_ts_definition_site(node: Node) -> bool:
    """Check if an identifier node is in a name-definition position in TS."""
    parent = node.parent
    if parent is None:
        return False

    from diffguard.ast.javascript import _JS_DEF_FIELD_LOOKUP  # noqa: PLC0415

    ptype = parent.type
    if ptype in _TS_ALWAYS_DEF_TYPES:
        return True
    field_name = _JS_DEF_FIELD_LOOKUP.get(ptype)
    if field_name is not None:
        return parent.child_by_field_name(field_name) == node
    return False


def _is_ts_attribute_access_field(node: Node) -> bool:
    """Check if an identifier is the property part of member_expression."""
    parent = node.parent
    if parent is None or parent.type != "member_expression":
        return False
    return parent.child_by_field_name("property") == node


def _is_type_position(node: Node) -> bool:
    """Check if an identifier is in a type annotation position (not a runtime value)."""
    parent = node.parent
    if parent is None:
        return False
    return parent.type in ("type_annotation", "type_arguments", "type_parameters", "constraint")


# ---------------------------------------------------------------------------
# First-party detection (delegates to JavaScript)
# ---------------------------------------------------------------------------


def is_first_party_ts(
    module_or_path: str,
    project_root: Path,
    third_party_patterns: list[str] | None = None,
    *,
    is_relative: bool = False,
) -> bool:
    """Determine whether a TS import is first-party project code.

    Delegates to JavaScript first-party detection since TypeScript
    uses the same ecosystem (package.json, node_modules, etc.).
    """
    return is_first_party_js(module_or_path, project_root, third_party_patterns, is_relative=is_relative)


# ---------------------------------------------------------------------------
# Symbol resolution
# ---------------------------------------------------------------------------

_TS_EXTENSIONS: list[str] = [".ts", ".tsx", ".mts", ".cts", ".js", ".mjs", ".cjs", ".jsx"]


def resolve_typescript_symbol(
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
        return _resolve_relative_ts_import(source_import.module, current_file)

    # Bare specifier — cannot resolve to a file without node_modules
    return None


def _resolve_relative_ts_import(module: str, current_file: Path) -> Path | None:
    """Resolve a relative TypeScript import to a file path."""
    base_dir = current_file.parent
    target = (base_dir / module).resolve()

    # Try exact path first
    if target.is_file():
        return target

    # Try with extensions (TS extensions first, then JS for interop)
    for ext in _TS_EXTENSIONS:
        candidate = target.with_suffix(ext)
        if candidate.is_file():
            return candidate

    # Try index convention
    if target.is_dir():
        for ext in _TS_EXTENSIONS:
            candidate = target / f"index{ext}"
            if candidate.is_file():
                return candidate

    return None
