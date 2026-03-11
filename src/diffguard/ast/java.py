"""Java-specific AST analysis using tree-sitter."""

from __future__ import annotations

import logging
import re
import xml.etree.ElementTree as ET
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
        "class_declaration",
        "interface_declaration",
        "enum_declaration",
        "method_declaration",
        "constructor_declaration",
        "lambda_expression",
    }
)

_NODE_TYPE_TO_SCOPE_TYPE: dict[str, str] = {
    "class_declaration": "class",
    "interface_declaration": "interface",
    "enum_declaration": "enum",
    "method_declaration": "method",
    "constructor_declaration": "constructor",
    "lambda_expression": "lambda",
}


def find_java_scope(tree: Tree, line: int) -> Scope | None:
    """Find the innermost Java scope containing a 1-indexed line."""
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
    if node.type == "lambda_expression":
        return "<lambda>"
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


def extract_java_imports(tree: Tree) -> list[Import]:
    """Extract all import statements from a parsed Java AST."""
    imports: list[Import] = []
    for child in tree.root_node.children:
        if child.type == "import_declaration":
            imp = _parse_import_declaration(child)
            if imp is not None:
                imports.append(imp)
    return imports


def _parse_import_declaration(node: Node) -> Import | None:
    """Parse a Java import_declaration node."""
    is_static = False
    is_star = False
    module_parts: list[str] = []

    for child in node.children:
        if child.type == "static":
            is_static = True
        elif child.type == "scoped_identifier":
            module_parts = _flatten_scoped_identifier(child)
        elif child.type == "identifier":
            module_parts = [_node_text(child)]
        elif child.type == "asterisk":
            is_star = True

    if not module_parts:
        return None

    full_module = ".".join(module_parts)

    if is_star:
        return Import(module=full_module, is_star=True, is_relative=False)

    # For named imports, the last part is the imported name
    if is_static:
        # `import static com.example.Utils.formatString` → names=["formatString"], module="com.example.Utils"
        imported_name = module_parts[-1]
        package = ".".join(module_parts[:-1])
        return Import(module=package, names=[imported_name], is_relative=False)

    # `import com.example.MyClass` → names=["MyClass"], module="com.example.MyClass"
    imported_name = module_parts[-1]
    return Import(module=full_module, names=[imported_name], is_relative=False)


def _flatten_scoped_identifier(node: Node) -> list[str]:
    """Flatten a scoped_identifier tree into a list of identifier strings."""
    parts: list[str] = []
    _collect_identifier_parts(node, parts)
    return parts


def _collect_identifier_parts(node: Node, parts: list[str]) -> None:
    """Recursively collect identifier parts from a scoped_identifier."""
    for child in node.children:
        if child.type == "identifier":
            parts.append(_node_text(child))
        elif child.type == "scoped_identifier":
            _collect_identifier_parts(child, parts)


# ---------------------------------------------------------------------------
# Package declaration extraction
# ---------------------------------------------------------------------------


def _extract_package(tree: Tree) -> str | None:
    """Extract the package declaration from a Java AST."""
    for child in tree.root_node.children:
        if child.type == "package_declaration":
            for pkg_child in child.children:
                if pkg_child.type in ("scoped_identifier", "identifier"):
                    return _node_text(pkg_child)
    return None


# ---------------------------------------------------------------------------
# Symbol usage detection
# ---------------------------------------------------------------------------

_JAVA_BUILTINS: frozenset[str] = frozenset(
    {
        # java.lang classes (auto-imported)
        "Object",
        "String",
        "Integer",
        "Long",
        "Double",
        "Float",
        "Boolean",
        "Byte",
        "Short",
        "Character",
        "Void",
        "Number",
        "Math",
        "System",
        "Class",
        "Thread",
        "Runnable",
        "StringBuilder",
        "StringBuffer",
        "Throwable",
        "Exception",
        "RuntimeException",
        "Error",
        "NullPointerException",
        "IllegalArgumentException",
        "IllegalStateException",
        "UnsupportedOperationException",
        "IndexOutOfBoundsException",
        "ClassCastException",
        "ArrayIndexOutOfBoundsException",
        "StackOverflowError",
        "OutOfMemoryError",
        "Override",
        "Deprecated",
        "SuppressWarnings",
        "FunctionalInterface",
        "Iterable",
        "Comparable",
        "Cloneable",
        "AutoCloseable",
        "Enum",
        "Record",
        "ProcessBuilder",
        # Keywords and literals treated as identifiers by tree-sitter
        "this",
        "super",
        "null",
        "true",
        "false",
        "var",
    }
)

_JAVA_DEF_FIELD_LOOKUP: dict[str, str] = {
    "variable_declarator": "name",
    "method_declaration": "name",
    "class_declaration": "name",
    "interface_declaration": "name",
    "enum_declaration": "name",
    "constructor_declaration": "name",
    "enum_constant": "name",
}

_JAVA_ALWAYS_DEF_TYPES: frozenset[str] = frozenset(
    {
        "formal_parameter",
        "catch_formal_parameter",
        "inferred_parameters",
        "spread_parameter",
    }
)


def find_java_used_symbols(
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

    _collect_java_symbols(tree.root_node, start_row, end_row, defined, used)

    result = used - defined
    if exclude_builtins:
        result -= _JAVA_BUILTINS
    return result


def _collect_java_symbols(
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
        if _is_java_definition_site(node):
            defined.add(name)
        elif not _is_java_attribute_access_field(node) and not _is_java_type_position(node):
            used.add(name)

    for child in node.children:
        _collect_java_symbols(child, start_row, end_row, defined, used)


def _is_java_definition_site(node: Node) -> bool:
    """Check if an identifier node is in a name-definition position in Java."""
    parent = node.parent
    if parent is None:
        return False

    ptype = parent.type
    if ptype in _JAVA_ALWAYS_DEF_TYPES:
        return True
    field_name = _JAVA_DEF_FIELD_LOOKUP.get(ptype)
    if field_name is not None:
        return parent.child_by_field_name(field_name) == node
    # Lambda single parameter: `item -> { ... }`
    if ptype == "lambda_expression":
        return parent.children[0] == node
    return False


def _is_java_attribute_access_field(node: Node) -> bool:
    """Check if an identifier is a field in member access (not the root object)."""
    parent = node.parent
    if parent is None:
        return False
    # field_access: `obj.field` — the `field` child
    if parent.type == "field_access":
        return parent.child_by_field_name("field") == node
    # method_invocation: `obj.method(...)` — the `name` child when there's an object
    if parent.type == "method_invocation":
        obj = parent.child_by_field_name("object")
        name = parent.child_by_field_name("name")
        if obj is not None and name == node:
            return True
    return False


def _is_java_type_position(node: Node) -> bool:
    """Check if an identifier is in a type position (not a runtime value reference)."""
    parent = node.parent
    if parent is None:
        return False
    return parent.type in (
        "type_identifier",
        "generic_type",
        "type_arguments",
        "type_parameters",
        "type_bound",
        "annotation",
        "marker_annotation",
        "scoped_type_identifier",
    )


# ---------------------------------------------------------------------------
# First-party detection
# ---------------------------------------------------------------------------

_JAVA_STDLIB_PREFIXES: tuple[str, ...] = (
    "java.",
    "javax.",
    "jdk.",
    "com.sun.",
    "sun.",
    "org.w3c.",
    "org.xml.",
    "org.omg.",
)

_build_config_cache: dict[Path, str | None] = {}


def _detect_base_package(project_root: Path) -> str | None:
    """Detect the base package from pom.xml, build.gradle, or directory structure."""
    if project_root in _build_config_cache:
        return _build_config_cache[project_root]

    result = _detect_from_pom_xml(project_root)
    if result is None:
        result = _detect_from_build_gradle(project_root)
    if result is None:
        result = _detect_from_directory_structure(project_root)

    _build_config_cache[project_root] = result
    return result


def _detect_from_pom_xml(project_root: Path) -> str | None:
    """Extract groupId from pom.xml."""
    pom_path = project_root / "pom.xml"
    if not pom_path.is_file():
        return None
    try:
        tree = ET.parse(pom_path)
        root = tree.getroot()
        # Handle Maven namespace
        ns = ""
        if root.tag.startswith("{"):
            ns = root.tag.split("}")[0] + "}"
        group_id = root.find(f"{ns}groupId")
        if group_id is not None and group_id.text:
            return group_id.text.strip()
    except (ET.ParseError, OSError):
        pass
    return None


_GRADLE_GROUP_PATTERN = re.compile(r"""group\s*=\s*['"]([^'"]+)['"]""")


def _detect_from_build_gradle(project_root: Path) -> str | None:
    """Extract group from build.gradle or build.gradle.kts."""
    for name in ("build.gradle", "build.gradle.kts"):
        gradle_path = project_root / name
        if not gradle_path.is_file():
            continue
        try:
            content = gradle_path.read_text(encoding="utf-8")
            match = _GRADLE_GROUP_PATTERN.search(content)
            if match:
                return match.group(1)
        except OSError:
            pass
    return None


def _detect_from_directory_structure(project_root: Path) -> str | None:
    """Infer base package from src/main/java/ directory structure."""
    java_src = project_root / "src" / "main" / "java"
    if not java_src.is_dir():
        return None

    # Walk down to find the first directory containing .java files or multiple subdirs
    current = java_src
    parts: list[str] = []
    while True:
        subdirs = [d for d in current.iterdir() if d.is_dir() and not d.name.startswith(".")]
        if len(subdirs) != 1:
            break
        java_files = list(current.glob("*.java"))
        if java_files:
            break
        parts.append(subdirs[0].name)
        current = subdirs[0]

    return ".".join(parts) if parts else None


def clear_build_config_cache() -> None:
    """Clear the build config cache (useful for testing)."""
    _build_config_cache.clear()


def is_first_party_java(
    module_or_path: str,
    project_root: Path,
    third_party_patterns: list[str] | None = None,
    *,
    is_relative: bool = False,  # noqa: ARG001
) -> bool:
    """Determine whether a Java import is first-party project code."""
    # Java stdlib packages are never first-party
    if any(module_or_path.startswith(prefix) for prefix in _JAVA_STDLIB_PREFIXES):
        return False

    patterns = third_party_patterns if third_party_patterns is not None else []

    # If it looks like a file path, check against patterns
    if "/" in module_or_path or "\\" in module_or_path:
        return _is_first_party_java_path(module_or_path, project_root, patterns)

    # Package name: check against project base package
    base_package = _detect_base_package(project_root)
    if base_package is not None and module_or_path.startswith(base_package + "."):
        return True

    # Try to resolve the import to a file in the project
    return _resolve_import_to_path(module_or_path, project_root) is not None


def _is_first_party_java_path(path: str, project_root: Path, patterns: list[str]) -> bool:
    """Check whether a Java file path is first-party (not matching third-party patterns)."""
    if any(pattern in path for pattern in patterns):
        return False
    try:
        return Path(path).resolve().is_relative_to(project_root.resolve())
    except (OSError, ValueError):
        return False


# ---------------------------------------------------------------------------
# Symbol resolution
# ---------------------------------------------------------------------------


def resolve_java_symbol(
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
    """Find which import statement brings a symbol into scope."""
    for imp in imports:
        if imp.names is not None and symbol in imp.names:
            return imp
        for _original, alias_name in imp.name_aliases:
            if alias_name == symbol:
                return imp
        if imp.alias == symbol:
            return imp
    return None


def _resolve_import_to_path(module: str, project_root: Path) -> Path | None:
    """Resolve a fully-qualified Java class name to a file path."""
    # Convert dotted path to directory path: com.example.MyClass → com/example/MyClass.java
    parts = module.split(".")
    relative = Path(*parts).with_suffix(".java")

    # Try standard Maven/Gradle layout
    for src_dir in ("src/main/java", "src/test/java", "src"):
        candidate = project_root / src_dir / relative
        if candidate.is_file():
            return candidate

    # Try directly under project root
    candidate = project_root / relative
    if candidate.is_file():
        return candidate

    return None
