"""PHP-specific AST analysis using tree-sitter."""

from __future__ import annotations

import json
import logging
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
        "function_definition",
        "method_declaration",
        "class_declaration",
        "trait_declaration",
        "interface_declaration",
        "anonymous_function",
        "arrow_function",
    }
)

_NODE_TYPE_TO_SCOPE_TYPE: dict[str, str] = {
    "function_definition": "function",
    "method_declaration": "method",
    "class_declaration": "class",
    "trait_declaration": "trait",
    "interface_declaration": "interface",
    "anonymous_function": "closure",
    "arrow_function": "arrow_function",
}


def find_php_scope(tree: Tree, line: int) -> Scope | None:
    """Find the innermost PHP scope containing a 1-indexed line."""
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
    if node.type in ("anonymous_function", "arrow_function"):
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


# ---------------------------------------------------------------------------
# Import extraction
# ---------------------------------------------------------------------------


def extract_php_imports(tree: Tree) -> list[Import]:
    """Extract all import/use/require statements from a parsed PHP AST."""
    imports: list[Import] = []
    _walk_for_imports(tree.root_node, imports)
    return imports


def _walk_for_imports(node: Node, imports: list[Import]) -> None:
    """Walk the AST to find all import-like statements."""
    for child in node.children:
        if child.type == "namespace_use_declaration":
            _parse_use_declaration(child, imports)
        elif child.type == "expression_statement":
            _check_require_include(child, imports)
        elif child.type in ("namespace_definition", "compound_statement", "declaration_list"):
            _walk_for_imports(child, imports)


def _parse_use_declaration(node: Node, imports: list[Import]) -> None:
    """Parse a namespace_use_declaration into Import objects."""
    # Detect use function / use const
    use_type: str | None = None
    group_prefix: str | None = None

    for child in node.children:
        if child.type == "function":
            use_type = "function"
        elif child.type == "const":
            use_type = "const"
        elif child.type == "namespace_name":
            # This is the group prefix for grouped use: `use App\Models\{...}`
            group_prefix = _node_text(child)
        elif child.type == "namespace_use_clause":
            _parse_use_clause(child, imports, use_type=use_type, group_prefix=None)
        elif child.type == "namespace_use_group":
            _parse_use_group(child, imports, group_prefix=group_prefix or "", use_type=use_type)


def _parse_use_clause(
    node: Node,
    imports: list[Import],
    *,
    use_type: str | None = None,  # noqa: ARG001
    group_prefix: str | None = None,
) -> None:
    """Parse a single namespace_use_clause."""
    module: str | None = None
    alias: str | None = None

    for child in node.children:
        if child.type in ("function", "const"):
            pass  # Modifier keyword — no action needed
        elif child.type == "qualified_name":
            module = _node_text(child)
        elif child.type == "name" and module is None:
            # Simple name (in grouped use)
            module = child.text.decode("utf-8") if child.text else ""

    # Check for alias (field: alias)
    alias_node = node.child_by_field_name("alias")
    if alias_node is not None and alias_node.text is not None:
        alias = str(alias_node.text, "utf-8")

    if not module:
        return

    # Apply group prefix
    if group_prefix:
        module = group_prefix + "\\" + module

    # Extract the short name (last segment)
    short_name = module.rsplit("\\", 1)[-1] if "\\" in module else module
    names = [alias or short_name]

    # Normalize backslashes for module path
    imports.append(
        Import(
            module=module,
            names=names,
            alias=alias,
            is_relative=False,
        )
    )


def _parse_use_group(
    node: Node,
    imports: list[Import],
    *,
    group_prefix: str,
    use_type: str | None = None,
) -> None:
    """Parse a namespace_use_group (grouped use statement)."""
    for child in node.children:
        if child.type == "namespace_use_clause":
            _parse_use_clause(child, imports, use_type=use_type, group_prefix=group_prefix)


def _check_require_include(node: Node, imports: list[Import]) -> None:
    """Check if an expression_statement contains a require/include."""
    for child in node.children:
        if child.type in (
            "require_expression",
            "require_once_expression",
            "include_expression",
            "include_once_expression",
        ):
            path = _extract_string_arg(child)
            if path:
                is_relative = path.startswith("./") or path.startswith("../") or "__DIR__" in _node_text(child)
                imports.append(
                    Import(
                        module=path,
                        names=[],
                        is_relative=is_relative,
                    )
                )


def _extract_string_arg(node: Node) -> str:
    """Extract a string argument from a require/include expression.

    Handles both simple string arguments and binary expressions
    like ``__DIR__ . '/../bootstrap.php'``.
    """
    for child in node.children:
        if child.type == "string":
            return _strip_php_string_quotes(_node_text(child))
        if child.type == "encapsed_string":
            text = _node_text(child)
            if len(text) >= 2:
                return text[1:-1]
        if child.type == "binary_expression":
            # Handle __DIR__ . '/path' concatenation — extract the string part
            result = _extract_string_from_binary(child)
            if result:
                return result
    return ""


def _strip_php_string_quotes(text: str) -> str:
    """Strip surrounding quotes from a PHP string literal."""
    if len(text) >= 2 and text[0] in ("'", '"') and text[-1] in ("'", '"'):
        return text[1:-1]
    return text


def _extract_string_from_binary(node: Node) -> str:
    """Extract the string portion from a binary expression (concatenation)."""
    right = node.child_by_field_name("right")
    if right is not None and right.type == "string":
        return _strip_php_string_quotes(_node_text(right))
    # Try to find any string child recursively
    for child in node.children:
        if child.type == "string":
            return _strip_php_string_quotes(_node_text(child))
    return ""


# ---------------------------------------------------------------------------
# Namespace extraction
# ---------------------------------------------------------------------------


def _extract_namespace(tree: Tree) -> str | None:
    """Extract the namespace declaration from a PHP AST."""
    for child in tree.root_node.children:
        if child.type == "namespace_definition":
            name_node = child.child_by_field_name("name")
            if name_node is not None:
                return _node_text(name_node)
    return None


# ---------------------------------------------------------------------------
# Symbol usage detection
# ---------------------------------------------------------------------------

_PHP_BUILTINS: frozenset[str] = frozenset(
    {
        # Array functions
        "array_map",
        "array_filter",
        "array_reduce",
        "array_merge",
        "array_push",
        "array_pop",
        "array_keys",
        "array_values",
        "array_unique",
        "array_reverse",
        "array_slice",
        "array_search",
        "array_walk",
        "in_array",
        "count",
        "sizeof",
        "sort",
        "usort",
        "ksort",
        "array_combine",
        "array_diff",
        "array_intersect",
        "compact",
        "extract",
        # String functions
        "strlen",
        "strpos",
        "substr",
        "str_replace",
        "strtolower",
        "strtoupper",
        "trim",
        "ltrim",
        "rtrim",
        "explode",
        "implode",
        "sprintf",
        "printf",
        "number_format",
        "str_contains",
        "str_starts_with",
        "str_ends_with",
        "preg_match",
        "preg_replace",
        "preg_split",
        # Type checking
        "isset",
        "unset",
        "empty",
        "is_null",
        "is_string",
        "is_int",
        "is_float",
        "is_bool",
        "is_array",
        "is_object",
        "is_numeric",
        "is_callable",
        "gettype",
        # Type casting
        "intval",
        "floatval",
        "strval",
        "boolval",
        # Output
        "echo",
        "print",
        "var_dump",
        "print_r",
        "var_export",
        # JSON
        "json_encode",
        "json_decode",
        # File I/O
        "file_get_contents",
        "file_put_contents",
        "file_exists",
        "is_file",
        "is_dir",
        # Math
        "abs",
        "ceil",
        "floor",
        "round",
        "max",
        "min",
        "rand",
        "mt_rand",
        "pow",
        # Date/Time
        "date",
        "time",
        "mktime",
        "strtotime",
        # Hashing
        "md5",
        "sha1",
        "hash",
        "password_hash",
        "password_verify",
        # Encoding
        "base64_encode",
        "base64_decode",
        "urlencode",
        "urldecode",
        "htmlspecialchars",
        "htmlentities",
        "html_entity_decode",
        # Class/Object
        "class_exists",
        "function_exists",
        "method_exists",
        "property_exists",
        "get_class",
        "get_object_vars",
        # Control
        "die",
        "exit",
        "header",
        "setcookie",
        # Misc
        "defined",
        "define",
        "constant",
        # PHP keywords/constants treated as identifiers
        "null",
        "true",
        "false",
        "self",
        "static",
        "parent",
        "this",
        "__DIR__",
        "__FILE__",
        "__LINE__",
        "__CLASS__",
        "__FUNCTION__",
        "__METHOD__",
        "__NAMESPACE__",
    }
)

_PHP_DEF_FIELD_LOOKUP: dict[str, str] = {
    "function_definition": "name",
    "method_declaration": "name",
    "class_declaration": "name",
    "trait_declaration": "name",
    "interface_declaration": "name",
}

_PHP_ALWAYS_DEF_TYPES: frozenset[str] = frozenset(
    {
        "simple_parameter",
        "property_promotion_parameter",
        "variadic_parameter",
    }
)


def find_php_used_symbols(
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

    _collect_php_symbols(tree.root_node, start_row, end_row, defined, used)

    result = used - defined
    if exclude_builtins:
        result -= _PHP_BUILTINS
    return result


def _collect_php_symbols(
    node: Node,
    start_row: int,
    end_row: int,
    defined: set[str],
    used: set[str],
) -> None:
    """Recursively collect defined and used identifiers within a row range."""
    if node.end_point.row < start_row or node.start_point.row > end_row:
        return

    if node.type == "name" and start_row <= node.start_point.row <= end_row:
        name = _node_text(node)
        if _is_php_definition_site(node):
            defined.add(name)
        elif not _is_php_member_field(node) and not _is_php_type_position(node):
            used.add(name)

    for child in node.children:
        _collect_php_symbols(child, start_row, end_row, defined, used)


def _is_php_definition_site(node: Node) -> bool:
    """Check if a name node is in a definition position in PHP."""
    parent = node.parent
    if parent is None:
        return False

    ptype = parent.type
    if ptype in _PHP_ALWAYS_DEF_TYPES:
        return True
    field_name = _PHP_DEF_FIELD_LOOKUP.get(ptype)
    if field_name is not None:
        return parent.child_by_field_name(field_name) == node
    # Variable name inside variable_name node (handled separately)
    if ptype == "variable_name":
        return False
    return False


def _is_php_member_field(node: Node) -> bool:
    """Check if a name is a member/property access field (not the root object)."""
    parent = node.parent
    if parent is None:
        return False
    # member_access_expression: $obj->method — the `name` field
    if parent.type == "member_access_expression":
        return parent.child_by_field_name("name") == node
    # member_call_expression: $obj->method(...) — the `name` field
    if parent.type == "member_call_expression":
        return parent.child_by_field_name("name") == node
    # scoped_call_expression: Class::method(...) — the `name` field
    if parent.type == "scoped_call_expression":
        return parent.child_by_field_name("name") == node
    # scoped_property_access_expression: Class::$prop
    if parent.type == "scoped_property_access_expression":
        return parent.child_by_field_name("name") == node
    return False


def _is_php_type_position(node: Node) -> bool:
    """Check if a name is in a type annotation position."""
    parent = node.parent
    if parent is None:
        return False
    return parent.type in (
        "named_type",
        "type_list",
        "union_type",
        "intersection_type",
        "nullable_type",
        "base_clause",
        "class_interface_clause",
        "namespace_aliasing_clause",
    )


# ---------------------------------------------------------------------------
# First-party detection
# ---------------------------------------------------------------------------

_composer_cache: dict[Path, dict[str, str]] = {}


def _detect_psr4_namespaces(project_root: Path) -> dict[str, str]:
    """Read PSR-4 autoload namespaces from composer.json.

    Returns a dict mapping namespace prefixes to directory paths.
    """
    if project_root in _composer_cache:
        return _composer_cache[project_root]

    result = _read_composer_psr4(project_root)
    _composer_cache[project_root] = result
    return result


def _read_composer_psr4(project_root: Path) -> dict[str, str]:
    """Extract PSR-4 namespace mappings from composer.json."""
    composer_path = project_root / "composer.json"
    if not composer_path.is_file():
        return {}
    try:
        content = composer_path.read_text(encoding="utf-8")
        data = json.loads(content)

        result: dict[str, str] = {}

        # Read autoload PSR-4
        autoload = data.get("autoload", {})
        psr4 = autoload.get("psr-4", {})
        for namespace_prefix, directory in psr4.items():
            if isinstance(directory, str):
                result[namespace_prefix] = directory
            elif isinstance(directory, list) and directory:
                result[namespace_prefix] = directory[0]

        # Also check autoload-dev
        autoload_dev = data.get("autoload-dev", {})
        psr4_dev = autoload_dev.get("psr-4", {})
        for namespace_prefix, directory in psr4_dev.items():
            if isinstance(directory, str):
                result[namespace_prefix] = directory
            elif isinstance(directory, list) and directory:
                result[namespace_prefix] = directory[0]

        return result
    except (json.JSONDecodeError, OSError):
        return {}


def clear_composer_cache() -> None:
    """Clear the composer.json cache (useful for testing)."""
    _composer_cache.clear()
    _laravel_project_cache.clear()
    _wordpress_project_cache.clear()


# ---------------------------------------------------------------------------
# Laravel framework support
# ---------------------------------------------------------------------------

_laravel_project_cache: dict[Path, bool] = {}


def _detect_laravel_project(project_root: Path) -> bool:
    """Check if the project root contains an artisan file (Laravel marker)."""
    if project_root in _laravel_project_cache:
        return _laravel_project_cache[project_root]
    result = (project_root / "artisan").is_file()
    _laravel_project_cache[project_root] = result
    return result


_LARAVEL_AUTOLOAD_DIRS: tuple[str, ...] = (
    "app/Models",
    "app/Http/Controllers",
    "app/Http/Middleware",
    "app/Services",
    "app/Providers",
    "app/Jobs",
    "app/Events",
    "app/Listeners",
    "app/Mail",
)


def _resolve_laravel_convention(namespace: str, project_root: Path) -> Path | None:
    """Resolve a PHP namespace to a file using Laravel's App\\ → app/ convention.

    Laravel maps ``App\\Models\\User`` → ``app/Models/User.php``, etc.
    """
    if not namespace.startswith("App\\"):
        return None

    # Strip the App\\ prefix and convert to path
    relative = namespace[len("App\\") :].replace("\\", "/")
    candidate = project_root / "app" / (relative + ".php")
    if candidate.is_file():
        return candidate
    return None


def _resolve_laravel_symbol(symbol: str, project_root: Path) -> Path | None:
    """Search common Laravel directories for a symbol by class name."""
    filename = symbol + ".php"
    for dir_path in _LARAVEL_AUTOLOAD_DIRS:
        candidate = project_root / dir_path / filename
        if candidate.is_file():
            return candidate
    return None


def is_first_party_php(
    module_or_path: str,
    project_root: Path,
    third_party_patterns: list[str] | None = None,
    *,
    is_relative: bool = False,
    current_file: Path | None = None,
) -> bool:
    """Determine whether a PHP import is first-party project code."""
    # Relative require/include paths are first-party
    if is_relative:
        return True

    patterns = third_party_patterns if third_party_patterns is not None else []
    if any(pattern in module_or_path for pattern in patterns):
        return False

    # Check against PSR-4 namespaces from composer.json
    psr4 = _detect_psr4_namespaces(project_root)
    if any(module_or_path.startswith(namespace_prefix) for namespace_prefix in psr4):
        return True

    # Laravel: App\ namespace is always first-party
    if _detect_laravel_project(project_root) and module_or_path.startswith("App\\"):
        return True

    # WordPress: file-path-based first-party detection
    if _detect_wordpress_project(project_root) and current_file is not None:
        return _is_wordpress_first_party(module_or_path, project_root, current_file)

    return False


# ---------------------------------------------------------------------------
# WordPress framework support
# ---------------------------------------------------------------------------

_wordpress_project_cache: dict[Path, bool] = {}

_WP_CORE_DIRS: frozenset[str] = frozenset(
    {
        "wp-includes/",
        "wp-admin/",
    }
)

_WP_EXCLUDED_CONTENT_DIRS: frozenset[str] = frozenset(
    {
        "wp-content/cache/",
        "wp-content/uploads/",
        "wp-content/upgrade/",
    }
)

_WP_PLUGIN_HEADER_MARKER = "Plugin Name:"
_WP_THEME_HEADER_MARKER = "Theme Name:"


def _detect_wordpress_project(project_root: Path) -> bool:
    """Check if the project root is a WordPress project.

    Detects via:
    - ``wp-config.php`` at project root (full WordPress install)
    - Plugin header (``Plugin Name:`` in main PHP file)
    - Theme header (``Theme Name:`` in ``style.css``)
    """
    if project_root in _wordpress_project_cache:
        return _wordpress_project_cache[project_root]

    result = _check_wordpress_markers(project_root)
    _wordpress_project_cache[project_root] = result
    return result


def _check_wordpress_markers(project_root: Path) -> bool:
    """Check for WordPress project markers at the given root."""
    # Full WordPress installation
    if (project_root / "wp-config.php").is_file():
        return True

    # Plugin: check PHP files at root for Plugin Name: header
    for php_file in project_root.glob("*.php"):
        try:
            head = php_file.read_text(encoding="utf-8", errors="replace")[:2048]
            if _WP_PLUGIN_HEADER_MARKER in head:
                return True
        except OSError:
            continue

    # Theme: check style.css for Theme Name: header
    style_css = project_root / "style.css"
    if style_css.is_file():
        try:
            head = style_css.read_text(encoding="utf-8", errors="replace")[:2048]
            if _WP_THEME_HEADER_MARKER in head:
                return True
        except OSError:
            pass

    return False


def _is_wordpress_first_party(
    module_or_path: str,  # noqa: ARG001
    project_root: Path,
    current_file: Path,
) -> bool:
    """Determine if a reference is first-party in a WordPress context.

    In a WordPress plugin/theme, the plugin/theme's own files are first-party.
    ``wp-includes/``, ``wp-admin/``, and other plugins' directories are third-party.
    """
    try:
        rel = current_file.resolve().relative_to(project_root.resolve())
    except ValueError:
        return False

    rel_str = str(rel)

    # Files in wp-includes/ or wp-admin/ are WordPress core — not first-party
    # Files in wp-content/plugins/<name>/ or wp-content/themes/<name>/ are first-party
    return not any(rel_str.startswith(d.rstrip("/")) for d in _WP_CORE_DIRS)


# ---------------------------------------------------------------------------
# Symbol resolution
# ---------------------------------------------------------------------------


def resolve_php_symbol(
    symbol: str,
    imports: list[Import],
    project_root: Path,
    current_file: Path | None = None,  # noqa: ARG001
) -> Path | None:
    """Resolve an imported symbol name to a file path in the project."""
    source_import = _find_import_for_symbol(symbol, imports)
    if source_import is not None:
        result = _resolve_use_to_path(source_import.module, project_root)
        if result is not None:
            return result

    # Laravel fallback: search common directories
    if _detect_laravel_project(project_root):
        return _resolve_laravel_symbol(symbol, project_root)

    return None


def _find_import_for_symbol(symbol: str, imports: list[Import]) -> Import | None:
    """Find which import statement brings a symbol into scope."""
    for imp in imports:
        # Check names list
        if imp.names is not None and symbol in imp.names:
            return imp
        # Check alias
        if imp.alias == symbol:
            return imp
    return None


def _resolve_use_to_path(namespace: str, project_root: Path) -> Path | None:
    """Resolve a PHP namespace to a file path using PSR-4 conventions."""
    psr4 = _detect_psr4_namespaces(project_root)

    for prefix, directory in psr4.items():
        if namespace.startswith(prefix):
            relative = namespace[len(prefix) :].replace("\\", "/")
            candidate = project_root / directory / (relative + ".php")
            if candidate.is_file():
                return candidate

    # Fallback: try direct namespace-to-path mapping under src/
    relative = namespace.replace("\\", "/") + ".php"
    for src_dir in ("src", "app", "lib"):
        candidate = project_root / src_dir / relative
        if candidate.is_file():
            return candidate

    candidate = project_root / relative
    if candidate.is_file():
        return candidate

    return None
