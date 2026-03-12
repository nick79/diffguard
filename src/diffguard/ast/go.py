"""Go-specific AST analysis using tree-sitter."""

from __future__ import annotations

import logging
import re
from functools import lru_cache
from pathlib import Path  # noqa: TC003
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
        "method_declaration",
        "func_literal",
    }
)

_NODE_TYPE_TO_SCOPE_TYPE: dict[str, str] = {
    "function_declaration": "function",
    "method_declaration": "method",
    "func_literal": "function",
}


def find_go_scope(tree: Tree, line: int) -> Scope | None:
    """Find the innermost Go scope containing a 1-indexed line."""
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
        else:
            deeper = _find_innermost_scope_node(child, row)
            if deeper is not None:
                best = deeper

    return best


def _node_to_scope(node: Node) -> Scope:
    """Convert a tree-sitter scope node to a Scope dataclass."""
    scope_type = _NODE_TYPE_TO_SCOPE_TYPE[node.type]
    name = _get_scope_name(node)
    start_line = int(node.start_point.row) + 1
    end_line = int(node.end_point.row) + 1
    return Scope(type=scope_type, name=name, start_line=start_line, end_line=end_line)


def _get_scope_name(node: Node) -> str:
    """Extract the name from a scope node."""
    name_node = node.child_by_field_name("name")
    if name_node is not None and name_node.text is not None:
        return str(name_node.text, "utf-8")
    if node.type == "func_literal":
        return "<anonymous>"
    return "<anonymous>"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _node_text(node: Node) -> str:
    """Get the UTF-8 text of a tree-sitter node."""
    if node.text is None:
        return ""
    return str(node.text, "utf-8")


def _strip_quotes(s: str) -> str:
    """Strip surrounding double quotes from a Go import path."""
    if len(s) >= 2 and s[0] == '"' and s[-1] == '"':
        return s[1:-1]
    return s


# ---------------------------------------------------------------------------
# Import extraction
# ---------------------------------------------------------------------------


def extract_go_imports(tree: Tree) -> list[Import]:
    """Extract all import statements from a parsed Go AST."""
    imports: list[Import] = []
    for child in tree.root_node.children:
        if child.type == "import_declaration":
            _walk_import_declaration(child, imports)
    return imports


def _walk_import_declaration(node: Node, imports: list[Import]) -> None:
    """Process an import_declaration node (single or grouped)."""
    for child in node.children:
        if child.type == "import_spec":
            imp = _parse_import_spec(child)
            if imp is not None:
                imports.append(imp)
        elif child.type == "import_spec_list":
            for spec in child.children:
                if spec.type == "import_spec":
                    imp = _parse_import_spec(spec)
                    if imp is not None:
                        imports.append(imp)
        elif child.type == "interpreted_string_literal":
            # Single import without spec list: `import "fmt"`
            path = _strip_quotes(_node_text(child))
            if path:
                imports.append(Import(module=path, is_relative=False))


def _parse_import_spec(node: Node) -> Import | None:
    """Parse an import_spec node into an Import."""
    alias: str | None = None
    path: str | None = None

    for child in node.children:
        if child.type == "interpreted_string_literal":
            path = _strip_quotes(_node_text(child))
        elif child.type in ("package_identifier", "blank_identifier", "dot"):
            alias = _node_text(child)

    if not path:
        return None

    return Import(module=path, alias=alias, is_relative=False)


# ---------------------------------------------------------------------------
# Symbol usage detection
# ---------------------------------------------------------------------------

_GO_BUILTINS: frozenset[str] = frozenset(
    {
        # Built-in functions
        "append",
        "cap",
        "clear",
        "close",
        "complex",
        "copy",
        "delete",
        "imag",
        "len",
        "make",
        "max",
        "min",
        "new",
        "panic",
        "print",
        "println",
        "real",
        "recover",
        # Built-in types
        "bool",
        "byte",
        "comparable",
        "complex64",
        "complex128",
        "error",
        "float32",
        "float64",
        "int",
        "int8",
        "int16",
        "int32",
        "int64",
        "rune",
        "string",
        "uint",
        "uint8",
        "uint16",
        "uint32",
        "uint64",
        "uintptr",
        "any",
        # Constants/zero values
        "true",
        "false",
        "nil",
        "iota",
    }
)

_GO_DEF_FIELD_LOOKUP: dict[str, str] = {
    "function_declaration": "name",
    "method_declaration": "name",
    "type_declaration": "name",
    "type_spec": "name",
    "const_spec": "name",
    "var_spec": "name",
    "field_declaration": "name",
    "parameter_declaration": "name",
}

_GO_ALWAYS_DEF_TYPES: frozenset[str] = frozenset(
    {
        "short_var_declaration",
        "range_clause",
    }
)


def find_go_used_symbols(
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

    _collect_go_symbols(tree.root_node, start_row, end_row, defined, used)

    result = used - defined
    if exclude_builtins:
        result -= _GO_BUILTINS
    return result


def _collect_go_symbols(
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
        if _is_go_definition_site(node):
            defined.add(name)
        elif not _is_go_selector_field(node):
            used.add(name)

    for child in node.children:
        _collect_go_symbols(child, start_row, end_row, defined, used)


def _is_go_definition_site(node: Node) -> bool:
    """Check if an identifier node is in a name-definition position in Go."""
    parent = node.parent
    if parent is None:
        return False

    ptype = parent.type

    # Direct field-name definitions (function name, type name, etc.)
    field_name = _GO_DEF_FIELD_LOOKUP.get(ptype)
    if field_name is not None:
        return parent.child_by_field_name(field_name) == node

    # For short_var_declaration and range_clause, the identifier is inside
    # an expression_list on the left side — walk up to find the defining parent
    return _is_in_left_of_def(node)


def _is_in_left_of_def(node: Node) -> bool:
    """Check if an identifier is in the left-hand side of a short_var_declaration or range_clause."""
    current: Node | None = node.parent
    while current is not None:
        if current.type in _GO_ALWAYS_DEF_TYPES:
            left = current.child_by_field_name("left")
            if left is None:
                return False
            # Check if our original node is a descendant of the left side
            check: Node | None = node
            while check is not None and check != current:
                if check == left:
                    return True
                check = check.parent
            return False
        current = current.parent
    return False


def _is_go_selector_field(node: Node) -> bool:
    """Check if an identifier is the field part of a selector expression (x.Field)."""
    parent = node.parent
    if parent is None:
        return False
    if parent.type == "selector_expression":
        return parent.child_by_field_name("field") == node
    return False


# ---------------------------------------------------------------------------
# First-party detection
# ---------------------------------------------------------------------------

_go_mod_cache: dict[Path, str | None] = {}


def _detect_go_module(project_root: Path) -> str | None:
    """Read the module path from go.mod."""
    if project_root in _go_mod_cache:
        return _go_mod_cache[project_root]

    result = _read_go_mod_module(project_root)
    _go_mod_cache[project_root] = result
    return result


_GO_MOD_MODULE_PATTERN = re.compile(r"^module\s+(\S+)", re.MULTILINE)


def _read_go_mod_module(project_root: Path) -> str | None:
    """Extract module path from go.mod file."""
    go_mod = project_root / "go.mod"
    if not go_mod.is_file():
        return None
    try:
        content = go_mod.read_text(encoding="utf-8")
        match = _GO_MOD_MODULE_PATTERN.search(content)
        if match:
            return match.group(1)
    except OSError:
        pass
    return None


def clear_go_mod_cache() -> None:
    """Clear the go.mod cache (useful for testing)."""
    _go_mod_cache.clear()


@lru_cache(maxsize=1)
def _go_stdlib_packages() -> frozenset[str]:
    """Return a set of known Go stdlib top-level package names."""
    return frozenset(
        {
            "archive",
            "bufio",
            "bytes",
            "cmp",
            "compress",
            "container",
            "context",
            "crypto",
            "database",
            "debug",
            "embed",
            "encoding",
            "errors",
            "expvar",
            "flag",
            "fmt",
            "go",
            "hash",
            "html",
            "image",
            "index",
            "io",
            "iter",
            "log",
            "maps",
            "math",
            "mime",
            "net",
            "os",
            "path",
            "plugin",
            "reflect",
            "regexp",
            "runtime",
            "slices",
            "sort",
            "strconv",
            "strings",
            "structs",
            "sync",
            "syscall",
            "testing",
            "text",
            "time",
            "unicode",
            "unique",
            "unsafe",
            "weak",
        }
    )


def _is_go_stdlib(import_path: str) -> bool:
    """Check if an import path is a Go stdlib package (no dots in path)."""
    # Go stdlib packages have no dots in the path: "fmt", "net/http", "crypto/tls"
    # Third-party packages always have a domain: "github.com/...", "golang.org/x/..."
    return "." not in import_path


def is_first_party_go(
    module_or_path: str,
    project_root: Path,
    third_party_patterns: list[str] | None = None,
    *,
    is_relative: bool = False,  # noqa: ARG001
) -> bool:
    """Determine whether a Go import is first-party project code."""
    # Stdlib is never first-party
    if _is_go_stdlib(module_or_path):
        return False

    patterns = third_party_patterns if third_party_patterns is not None else []
    if any(pattern in module_or_path for pattern in patterns):
        return False

    # Check against go.mod module path
    go_module = _detect_go_module(project_root)
    return go_module is not None and (module_or_path == go_module or module_or_path.startswith(go_module + "/"))


# ---------------------------------------------------------------------------
# Symbol resolution
# ---------------------------------------------------------------------------


def resolve_go_symbol(
    symbol: str,
    imports: list[Import],
    project_root: Path,
    current_file: Path | None = None,  # noqa: ARG001
) -> Path | None:
    """Resolve an imported symbol name to a file path in the project."""
    source_import = _find_import_for_symbol(symbol, imports)
    if source_import is None:
        return None

    return _resolve_import_to_path(source_import.module, project_root)


def _find_import_for_symbol(symbol: str, imports: list[Import]) -> Import | None:
    """Find which import statement brings a symbol into scope.

    In Go, the import path's last segment is the package name, and symbols
    are accessed via that package name (e.g., `fmt.Println` → import "fmt").
    """
    for imp in imports:
        # Skip blank imports
        if imp.alias == "_":
            continue

        # If aliased, the alias is the local name
        if imp.alias and imp.alias != ".":
            if imp.alias == symbol:
                return imp
            continue

        # Dot import — symbols are used directly, but we can't resolve which import
        if imp.alias == ".":
            continue

        # Default: last segment of import path is the package name
        pkg_name = imp.module.rsplit("/", 1)[-1]
        if pkg_name == symbol:
            return imp

    return None


def _resolve_import_to_path(import_path: str, project_root: Path) -> Path | None:
    """Resolve a Go import path to a local directory (returns first .go file)."""
    go_module = _detect_go_module(project_root)
    if go_module is None:
        return None

    if not import_path.startswith(go_module):
        return None

    # Strip the module prefix to get the relative path
    rel_path = "." if import_path == go_module else import_path[len(go_module) + 1 :]

    pkg_dir = project_root / rel_path
    if not pkg_dir.is_dir():
        return None

    # Return the first non-test .go file in the package directory
    for go_file in sorted(pkg_dir.iterdir()):
        if go_file.suffix == ".go" and not go_file.name.endswith("_test.go"):
            return go_file

    return None
