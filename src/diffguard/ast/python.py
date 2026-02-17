"""Python-specific AST analysis using tree-sitter."""

from __future__ import annotations

import builtins
import logging
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from diffguard.ast.scope import Scope

if TYPE_CHECKING:
    from tree_sitter import Node, Tree

logger = logging.getLogger(__name__)

_STDLIB_MODULES: frozenset[str] = frozenset(sys.stdlib_module_names)
_BUILTIN_NAMES: frozenset[str] = frozenset(dir(builtins))

_SCOPE_NODE_TYPES: frozenset[str] = frozenset({"function_definition", "class_definition"})

_NODE_TYPE_TO_SCOPE_TYPE: dict[str, str] = {
    "function_definition": "function",
    "class_definition": "class",
}


def find_python_scope(tree: Tree, line: int) -> Scope | None:
    """Find the innermost Python scope containing a 1-indexed line.

    Handles regular functions, async functions, classes, methods, nested
    definitions, and decorated definitions. Lambdas and comprehensions
    are not treated as scopes.
    """
    row = line - 1
    node = _find_innermost_scope_node(tree.root_node, row)
    if node is None:
        return None
    return _node_to_scope(node)


def _find_innermost_scope_node(root: Node, row: int) -> Node | None:
    """Walk the AST depth-first to find the innermost scope node containing the row (0-indexed)."""
    best: Node | None = None

    for child in root.children:
        if not (child.start_point.row <= row <= child.end_point.row):
            continue

        if child.type == "decorated_definition":
            inner = _definition_from_decorated(child)
            if inner is not None:
                best = inner
                # Only recurse deeper if the row is within the definition body itself
                if inner.start_point.row <= row <= inner.end_point.row:
                    deeper = _find_innermost_scope_node(inner, row)
                    if deeper is not None:
                        best = deeper
        elif child.type in _SCOPE_NODE_TYPES:
            best = child
            deeper = _find_innermost_scope_node(child, row)
            if deeper is not None:
                best = deeper
        else:
            deeper = _find_innermost_scope_node(child, row)
            if deeper is not None:
                best = deeper

    return best


def _definition_from_decorated(node: Node) -> Node | None:
    """Extract the function/class definition from a decorated_definition node."""
    for child in node.children:
        if child.type in _SCOPE_NODE_TYPES:
            return child
    return None


def _node_to_scope(node: Node) -> Scope:
    """Convert a tree-sitter scope node to a Scope dataclass."""
    scope_type = _NODE_TYPE_TO_SCOPE_TYPE[node.type]
    name = _get_node_name(node)
    start_line, end_line = _get_effective_line_range(node)
    return Scope(type=scope_type, name=name, start_line=start_line, end_line=end_line)


def _get_node_name(node: Node) -> str:
    """Extract the name identifier from a function or class definition node."""
    name_node = node.child_by_field_name("name")
    if name_node is None or name_node.text is None:
        return "<unknown>"
    return str(name_node.text, "utf-8")


def _get_effective_line_range(node: Node) -> tuple[int, int]:
    """Get the 1-indexed line range for a scope node, including decorators."""
    parent = node.parent
    if parent is not None and parent.type == "decorated_definition":
        start_row = int(parent.start_point.row)
    else:
        start_row = int(node.start_point.row)
    end_row = int(node.end_point.row)
    return (start_row + 1, end_row + 1)


# ---------------------------------------------------------------------------
# Import extraction
# ---------------------------------------------------------------------------


@dataclass
class Import:
    """A parsed Python import statement."""

    module: str
    names: list[str] | None = None
    alias: str | None = None
    name_aliases: list[tuple[str, str]] = field(default_factory=list)
    is_star: bool = False
    is_relative: bool = False
    level: int = 0


def _node_text(node: Node) -> str:
    """Get the UTF-8 text of a tree-sitter node."""
    if node.text is None:
        return ""
    return str(node.text, "utf-8")


def extract_imports(tree: Tree) -> list[Import]:
    """Extract all import statements from a parsed Python AST."""
    imports: list[Import] = []
    for child in tree.root_node.children:
        match child.type:
            case "import_statement":
                imports.extend(_parse_import_statement(child))
            case "import_from_statement":
                imp = _parse_import_from_statement(child)
                if imp is not None:
                    imports.append(imp)
    return imports


def _parse_import_statement(node: Node) -> list[Import]:
    """Parse `import x`, `import x as y`, `import x, y, z`."""
    results: list[Import] = []
    for child in node.children:
        if child.type == "dotted_name":
            results.append(Import(module=_node_text(child)))
        elif child.type == "aliased_import":
            name_node = child.child_by_field_name("name")
            alias_node = child.child_by_field_name("alias")
            if name_node is not None:
                results.append(
                    Import(
                        module=_node_text(name_node),
                        alias=_node_text(alias_node) if alias_node is not None else None,
                    )
                )
    return results


def _parse_import_from_statement(node: Node) -> Import | None:
    """Parse `from x import y`, `from .x import y`, `from x import *`."""
    module_name, level, is_relative = _parse_from_module(node)
    names, name_aliases, is_star = _parse_from_names(node)

    return Import(
        module=module_name,
        names=names if names else None,
        name_aliases=name_aliases,
        is_star=is_star,
        is_relative=is_relative,
        level=level,
    )


def _parse_from_module(node: Node) -> tuple[str, int, bool]:
    """Extract module name, dot level, and relative flag from an import_from_statement."""
    module_node = node.child_by_field_name("module_name")
    if module_node is None:
        return ("", 0, False)

    if module_node.type == "dotted_name":
        return (_node_text(module_node), 0, False)

    if module_node.type != "relative_import":
        return ("", 0, False)

    level = 0
    dotted = ""
    for part in module_node.children:
        if part.type == "import_prefix":
            level = _node_text(part).count(".")
        elif part.type == "dotted_name":
            dotted = _node_text(part)

    module_name = "." * level + dotted if dotted else "." * level
    return (module_name, level, True)


def _parse_from_names(node: Node) -> tuple[list[str], list[tuple[str, str]], bool]:
    """Extract imported names, aliases, and star flag from an import_from_statement."""
    names: list[str] = []
    name_aliases: list[tuple[str, str]] = []
    is_star = False

    past_import_keyword = False
    for child in node.children:
        if child.type == "import":
            past_import_keyword = True
            continue
        if not past_import_keyword:
            continue

        match child.type:
            case "wildcard_import":
                is_star = True
                names.append("*")
            case "dotted_name":
                names.append(_node_text(child))
            case "aliased_import":
                _parse_aliased_from_name(child, names, name_aliases)

    return (names, name_aliases, is_star)


def _parse_aliased_from_name(child: Node, names: list[str], name_aliases: list[tuple[str, str]]) -> None:
    """Parse a single aliased or non-aliased name from a from-import."""
    name_node = child.child_by_field_name("name")
    alias_node = child.child_by_field_name("alias")
    if name_node is None:
        return
    original = _node_text(name_node)
    if alias_node is not None:
        name_aliases.append((original, _node_text(alias_node)))
    else:
        names.append(original)


# ---------------------------------------------------------------------------
# Symbol usage detection
# ---------------------------------------------------------------------------

_DEFINITION_PARENT_TYPES: frozenset[str] = frozenset(
    {
        "function_definition",
        "class_definition",
        "for_statement",
        "with_clause",
        "except_clause",
        "as_pattern",
        "global_statement",
        "nonlocal_statement",
    }
)


def find_used_symbols(
    tree: Tree,
    start_line: int,
    end_line: int,
    *,
    exclude_builtins: bool = False,
) -> set[str]:
    """Find externally-referenced symbols in a line range (1-indexed, inclusive).

    Returns root identifiers only (for `a.b.c`, returns just `a`).
    Excludes names that are defined within the region (local variables).
    """
    defined: set[str] = set()
    used: set[str] = set()
    start_row = start_line - 1
    end_row = end_line - 1

    _collect_symbols(tree.root_node, start_row, end_row, defined, used)

    result = used - defined
    if exclude_builtins:
        result -= _BUILTIN_NAMES
    return result


def _collect_symbols(
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
        if _is_definition_site(node):
            defined.add(name)
        elif not _is_attribute_access_field(node):
            used.add(name)

    for child in node.children:
        _collect_symbols(child, start_row, end_row, defined, used)


_ALWAYS_DEF_TYPES: frozenset[str] = frozenset({"pattern_list", "parameters"})
_LAST_NAMED_CHILD_DEF_TYPES: frozenset[str] = frozenset({"as_pattern", "except_clause"})
_TYPED_PARAM_TYPES: frozenset[str] = frozenset({"typed_parameter", "typed_default_parameter"})

# Maps parent node type → field name to check for definition identity
_DEF_FIELD_LOOKUP: dict[str, str] = {
    "function_definition": "name",
    "class_definition": "name",
    "default_parameter": "name",
    "for_statement": "left",
    "for_in_clause": "left",
    "assignment": "left",
}


def _is_definition_site(node: Node) -> bool:
    """Check if an identifier node is in a name-definition position."""
    parent = node.parent
    if parent is None:
        return False

    ptype = parent.type
    if ptype in _ALWAYS_DEF_TYPES:
        return True
    field_name = _DEF_FIELD_LOOKUP.get(ptype)
    if field_name is not None:
        return parent.child_by_field_name(field_name) == node
    if ptype in _LAST_NAMED_CHILD_DEF_TYPES:
        named = parent.named_children
        return len(named) >= 2 and named[-1] == node
    if ptype in _TYPED_PARAM_TYPES:
        return parent.named_children[0] == node if parent.named_children else False
    return False


def _is_attribute_access_field(node: Node) -> bool:
    """Check if an identifier is the `.attr` part of `obj.attr` (not the root object)."""
    parent = node.parent
    if parent is None or parent.type != "attribute":
        return False
    return parent.child_by_field_name("attribute") == node


# ---------------------------------------------------------------------------
# First-party detection
# ---------------------------------------------------------------------------

_DEFAULT_THIRD_PARTY_PATTERNS: list[str] = [
    "venv/",
    ".venv/",
    "site-packages/",
    "node_modules/",
]


def is_first_party(
    module_or_path: str,
    project_root: Path,
    third_party_patterns: list[str] | None = None,
    *,
    is_relative: bool = False,
) -> bool:
    """Determine whether an import is first-party project code.

    Relative imports are always first-party. Stdlib and third-party imports
    are not first-party.
    """
    if is_relative:
        return True

    top_level = module_or_path.split(".")[0]
    if top_level in _STDLIB_MODULES:
        return False

    patterns = third_party_patterns if third_party_patterns is not None else _DEFAULT_THIRD_PARTY_PATTERNS

    # If it looks like a file path, check against patterns
    if "/" in module_or_path or "\\" in module_or_path:
        return _is_first_party_path(module_or_path, project_root, patterns)

    # Module name: try to find it in the project
    resolved_path = _resolve_module_to_path(module_or_path, project_root)
    if resolved_path is None:
        return False
    return _path_passes_third_party_check(str(resolved_path), patterns)


def _is_first_party_path(path_str: str, project_root: Path, patterns: list[str]) -> bool:
    """Check whether a file path is first-party (not matching third-party patterns)."""
    if not _path_passes_third_party_check(path_str, patterns):
        return False
    try:
        return Path(path_str).resolve().is_relative_to(project_root.resolve())
    except (OSError, ValueError):
        return False


def _path_passes_third_party_check(path_str: str, patterns: list[str]) -> bool:
    """Return True if the path does not match any third-party pattern."""
    return all(pattern not in path_str for pattern in patterns)


# ---------------------------------------------------------------------------
# Symbol resolution
# ---------------------------------------------------------------------------


def resolve_symbol_definition(
    symbol: str,
    imports: list[Import],
    project_root: Path,
    current_file: Path | None = None,
) -> Path | None:
    """Resolve an imported symbol name to a file path in the project.

    Looks through the import list to find which import provides the symbol,
    then resolves the module to a file on disk.
    """
    source_import = _find_import_for_symbol(symbol, imports)
    if source_import is None:
        return None

    if source_import.is_relative:
        if current_file is None:
            return None
        return _resolve_relative_import(source_import, current_file)

    return _resolve_module_to_path(source_import.module, project_root)


def _find_import_for_symbol(symbol: str, imports: list[Import]) -> Import | None:
    """Find which import statement brings a symbol into scope."""
    for imp in imports:
        # `from x import symbol`
        if imp.names is not None and symbol in imp.names:
            return imp
        # `from x import original as symbol`
        for _original, alias in imp.name_aliases:
            if alias == symbol:
                return imp
        # `import x as symbol`
        if imp.alias == symbol:
            return imp
        # `import symbol` (bare import, symbol == module name)
        if imp.alias is None and imp.names is None and imp.module == symbol:
            return imp
        # `import x.y.z` and symbol matches top-level
        if imp.alias is None and imp.names is None and imp.module.split(".")[0] == symbol:
            return imp
    return None


def _resolve_module_to_path(module: str, project_root: Path) -> Path | None:
    """Resolve a dotted module name to a file path relative to the project root."""
    parts = module.split(".")
    relative = Path(*parts)

    # Try module.py
    candidate = project_root / relative.with_suffix(".py")
    if candidate.is_file():
        return candidate

    # Try package/__init__.py
    candidate = project_root / relative / "__init__.py"
    if candidate.is_file():
        return candidate

    # Try under src/ layout
    candidate = project_root / "src" / relative.with_suffix(".py")
    if candidate.is_file():
        return candidate

    candidate = project_root / "src" / relative / "__init__.py"
    if candidate.is_file():
        return candidate

    return None


def _resolve_relative_import(imp: Import, current_file: Path) -> Path | None:
    """Resolve a relative import to a file path."""
    base_dir = current_file.parent
    # Go up (level - 1) directories: level=1 means current package
    for _ in range(imp.level - 1):
        base_dir = base_dir.parent

    # Extract the module part without the dots
    module_part = imp.module.lstrip(".")
    if module_part:
        parts = module_part.split(".")
        target_dir = base_dir / Path(*parts)
    else:
        target_dir = base_dir

    # Try as a module file
    candidate = target_dir.with_suffix(".py")
    if candidate.is_file():
        return candidate

    # Try as a package
    candidate = target_dir / "__init__.py"
    if candidate.is_file():
        return candidate

    return None
