"""Ruby-specific AST analysis using tree-sitter."""

from __future__ import annotations

import logging
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

_SCOPE_NODE_TYPES: frozenset[str] = frozenset(
    {
        "method",
        "singleton_method",
        "class",
        "module",
        "lambda",
        "do_block",
        "block",
    }
)

_NODE_TYPE_TO_SCOPE_TYPE: dict[str, str] = {
    "method": "method",
    "singleton_method": "method",
    "class": "class",
    "module": "module",
    "lambda": "lambda",
    "do_block": "block",
    "block": "block",
}


def find_ruby_scope(tree: Tree, line: int) -> Scope | None:
    """Find the innermost Ruby scope containing a 1-indexed line."""
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

        if child.type in _SCOPE_NODE_TYPES and _is_scope_declaration(child):
            best = child
            deeper = _find_innermost_scope_node(child, row)
            if deeper is not None:
                best = deeper
        else:
            deeper = _find_innermost_scope_node(child, row)
            if deeper is not None:
                best = deeper

    return best


def _is_scope_declaration(node: Node) -> bool:
    """Check if a node is an actual scope declaration (not just a keyword token).

    In Ruby's tree-sitter grammar, `module`, `class`, and `def` appear both as
    declaration nodes (with children) and as keyword tokens (leaf nodes). We only
    want the declaration form.
    """
    return node.named_child_count > 0


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
    if node.type == "lambda":
        return "<lambda>"
    if node.type in ("do_block", "block"):
        return "<block>"
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
    """Remove surrounding quotes from a string."""
    if len(s) >= 2 and s[0] in ("'", '"') and s[-1] == s[0]:
        return s[1:-1]
    return s


# ---------------------------------------------------------------------------
# Import extraction
# ---------------------------------------------------------------------------

_IMPORT_METHODS: frozenset[str] = frozenset({"require", "require_relative", "load", "autoload"})


def extract_ruby_imports(tree: Tree) -> list[Import]:
    """Extract all import statements from a parsed Ruby AST."""
    imports: list[Import] = []
    _walk_imports(tree.root_node, imports)
    return imports


def _walk_imports(node: Node, imports: list[Import]) -> None:
    """Recursively walk the AST to find require/load/autoload calls."""
    for child in node.children:
        if child.type == "call":
            imp = _parse_import_call(child)
            if imp is not None:
                imports.append(imp)
                continue
        _walk_imports(child, imports)


def _parse_import_call(node: Node) -> Import | None:
    """Parse a require/require_relative/load/autoload call node."""
    method_node = node.child_by_field_name("method")
    if method_node is None:
        return None

    method_name = _node_text(method_node)
    if method_name not in _IMPORT_METHODS:
        return None

    args_node = node.child_by_field_name("arguments")
    if args_node is None:
        return None

    if method_name == "autoload":
        return _parse_autoload(args_node)

    # require, require_relative, load — first string argument is the module
    module = _extract_string_arg(args_node)
    if module is None:
        return None

    is_relative = method_name == "require_relative" or module.startswith("./") or module.startswith("../")
    return Import(module=module, is_relative=is_relative)


def _parse_autoload(args_node: Node) -> Import | None:
    """Parse autoload :Symbol, 'path' call."""
    module: str | None = None
    for child in args_node.children:
        if child.type == "string":
            module = _strip_quotes(_node_text(child))
            break
    if module is None:
        return None
    return Import(module=module, is_relative=False)


def _extract_string_arg(args_node: Node) -> str | None:
    """Extract the first string literal argument from an argument_list node."""
    for child in args_node.children:
        if child.type == "string":
            # Get string_content child for the actual value
            for sub in child.children:
                if sub.type == "string_content":
                    return _node_text(sub)
            # Fallback: strip quotes from full text
            return _strip_quotes(_node_text(child))
    return None


# ---------------------------------------------------------------------------
# Symbol usage detection
# ---------------------------------------------------------------------------

_RUBY_BUILTINS: frozenset[str] = frozenset(
    {
        # Kernel methods
        "puts",
        "print",
        "p",
        "pp",
        "warn",
        "raise",
        "fail",
        "require",
        "require_relative",
        "load",
        "autoload",
        "open",
        "gets",
        "sleep",
        "exit",
        "abort",
        "at_exit",
        "rand",
        "srand",
        "sprintf",
        "format",
        "loop",
        "lambda",
        "proc",
        "block_given?",
        "caller",
        "catch",
        "throw",
        "binding",
        "eval",
        # Constants / built-in classes
        "Object",
        "Class",
        "Module",
        "Kernel",
        "BasicObject",
        "String",
        "Integer",
        "Float",
        "Symbol",
        "Array",
        "Hash",
        "Range",
        "Regexp",
        "Proc",
        "Method",
        "IO",
        "File",
        "Dir",
        "Time",
        "Date",
        "DateTime",
        "Struct",
        "OpenStruct",
        "Comparable",
        "Enumerable",
        "Enumerator",
        "Encoding",
        "Thread",
        "Mutex",
        "Fiber",
        "NilClass",
        "TrueClass",
        "FalseClass",
        "Numeric",
        "Complex",
        "Rational",
        "BigDecimal",
        "Set",
        "Math",
        "Errno",
        "ENV",
        "ARGV",
        "STDIN",
        "STDOUT",
        "STDERR",
        # Exception classes
        "Exception",
        "StandardError",
        "RuntimeError",
        "TypeError",
        "ArgumentError",
        "NameError",
        "NoMethodError",
        "IOError",
        "SystemExit",
        "SignalException",
        "Interrupt",
        "LoadError",
        "NotImplementedError",
        "RangeError",
        "ZeroDivisionError",
        "IndexError",
        "KeyError",
        "StopIteration",
        "RegexpError",
        "ScriptError",
        "SyntaxError",
        "SecurityError",
        "SystemCallError",
        "SystemStackError",
        "EOFError",
        # Keywords / pseudo-variables
        "self",
        "super",
        "nil",
        "true",
        "false",
        "__FILE__",
        "__LINE__",
        "__dir__",
        "__method__",
    }
)

_RUBY_DEF_FIELD_LOOKUP: dict[str, str] = {
    "method": "name",
    "singleton_method": "name",
    "class": "name",
    "module": "name",
    "assignment": "left",
}

_RUBY_ALWAYS_DEF_TYPES: frozenset[str] = frozenset(
    {
        "method_parameters",
        "block_parameters",
        "lambda_parameters",
        "block_parameter",
        "splat_parameter",
        "hash_splat_parameter",
        "keyword_parameter",
        "optional_parameter",
    }
)


def find_ruby_used_symbols(
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

    _collect_ruby_symbols(tree.root_node, start_row, end_row, defined, used)

    result = used - defined
    if exclude_builtins:
        result -= _RUBY_BUILTINS
    return result


def _collect_ruby_symbols(
    node: Node,
    start_row: int,
    end_row: int,
    defined: set[str],
    used: set[str],
) -> None:
    """Recursively collect defined and used identifiers within a row range."""
    if node.end_point.row < start_row or node.start_point.row > end_row:
        return

    if node.type == "constant" and start_row <= node.start_point.row <= end_row:
        name = _node_text(node)
        if _is_ruby_definition_site(node):
            defined.add(name)
        else:
            used.add(name)
    elif node.type == "identifier" and start_row <= node.start_point.row <= end_row:
        name = _node_text(node)
        if _is_ruby_definition_site(node):
            defined.add(name)
        elif not _is_ruby_method_call_name(node) and not _is_ruby_attribute_access(node):
            used.add(name)

    for child in node.children:
        _collect_ruby_symbols(child, start_row, end_row, defined, used)


def _is_ruby_definition_site(node: Node) -> bool:
    """Check if a node is in a name-definition position in Ruby."""
    parent = node.parent
    if parent is None:
        return False

    ptype = parent.type
    if ptype in _RUBY_ALWAYS_DEF_TYPES:
        return True
    field_name = _RUBY_DEF_FIELD_LOOKUP.get(ptype)
    if field_name is not None:
        return parent.child_by_field_name(field_name) == node
    return False


def _is_ruby_method_call_name(node: Node) -> bool:
    """Check if an identifier is the method name in a call (not the receiver)."""
    parent = node.parent
    if parent is None or parent.type != "call":
        return False
    # The `method` field is the method name being called
    method_node = parent.child_by_field_name("method")
    if method_node == node:
        # But if there's no receiver, the method name IS the used symbol (like `puts`)
        receiver = parent.child_by_field_name("receiver")
        return receiver is not None
    return False


def _is_ruby_attribute_access(node: Node) -> bool:
    """Check if an identifier is a method being called on a receiver (obj.method)."""
    parent = node.parent
    if parent is None or parent.type != "call":
        return False
    method_node = parent.child_by_field_name("method")
    receiver = parent.child_by_field_name("receiver")
    return method_node == node and receiver is not None


# ---------------------------------------------------------------------------
# First-party detection
# ---------------------------------------------------------------------------

_RUBY_STDLIB_MODULES: frozenset[str] = frozenset(
    {
        "abbrev",
        "base64",
        "benchmark",
        "bigdecimal",
        "cgi",
        "csv",
        "date",
        "delegate",
        "digest",
        "drb",
        "erb",
        "etc",
        "fcntl",
        "fiddle",
        "fileutils",
        "find",
        "forwardable",
        "io/console",
        "io/nonblock",
        "io/wait",
        "ipaddr",
        "irb",
        "json",
        "logger",
        "matrix",
        "minitest",
        "monitor",
        "mutex_m",
        "net/ftp",
        "net/http",
        "net/imap",
        "net/pop",
        "net/smtp",
        "nkf",
        "observer",
        "open-uri",
        "open3",
        "openssl",
        "optparse",
        "ostruct",
        "pathname",
        "pp",
        "prettyprint",
        "prime",
        "pstore",
        "psych",
        "racc",
        "rdoc",
        "readline",
        "reline",
        "resolv",
        "ripper",
        "rss",
        "securerandom",
        "set",
        "shellwords",
        "singleton",
        "socket",
        "stringio",
        "strscan",
        "syslog",
        "tempfile",
        "time",
        "timeout",
        "tmpdir",
        "tsort",
        "un",
        "uri",
        "weakref",
        "webrick",
        "yaml",
        "zlib",
    }
)

_gemfile_cache: dict[Path, set[str] | None] = {}


def _load_gemfile_gems(project_root: Path) -> set[str] | None:
    """Load gem names from Gemfile (simple regex parsing)."""
    if project_root in _gemfile_cache:
        return _gemfile_cache[project_root]

    gemfile_path = project_root / "Gemfile"
    result: set[str] | None = None
    if gemfile_path.is_file():
        try:
            content = gemfile_path.read_text(encoding="utf-8")
            import re  # noqa: PLC0415

            gems: set[str] = set()
            for match in re.finditer(r"""gem\s+['"]([^'"]+)['"]""", content):
                gems.add(match.group(1))
            result = gems if gems else None
        except OSError:
            pass

    _gemfile_cache[project_root] = result
    return result


def clear_gemfile_cache() -> None:
    """Clear the Gemfile cache (useful for testing)."""
    _gemfile_cache.clear()


def is_first_party_ruby(
    module_or_path: str,
    project_root: Path,
    third_party_patterns: list[str] | None = None,
    *,
    is_relative: bool = False,
) -> bool:
    """Determine whether a Ruby import is first-party project code."""
    # require_relative is always first-party
    if is_relative:
        return True

    # Check stdlib modules
    if module_or_path in _RUBY_STDLIB_MODULES:
        return False

    patterns = third_party_patterns if third_party_patterns is not None else []

    # If it looks like a file path, check against patterns
    if ("/" in module_or_path or "\\" in module_or_path) and any(pattern in module_or_path for pattern in patterns):
        return False

    # Check if the gem is listed in Gemfile (third-party)
    gems = _load_gemfile_gems(project_root)
    if gems is not None and module_or_path in gems:
        return False

    # Check if a matching file exists locally
    return _resolve_require_to_path(module_or_path, project_root) is not None


def _resolve_require_to_path(module: str, project_root: Path) -> Path | None:
    """Try to resolve a require to a local file."""
    # Try common Ruby project layouts
    candidates = [
        project_root / "lib" / f"{module}.rb",
        project_root / f"{module}.rb",
        project_root / "app" / f"{module}.rb",
        project_root / "lib" / module / "init.rb",
    ]

    # Handle nested paths like 'my_app/helper'
    for candidate in candidates:
        if candidate.is_file():
            return candidate

    return None


# ---------------------------------------------------------------------------
# Symbol resolution
# ---------------------------------------------------------------------------


def resolve_ruby_symbol(
    symbol: str,
    imports: list[Import],
    project_root: Path,
    current_file: Path | None = None,
) -> Path | None:
    """Resolve an imported symbol name to a file path in the project."""
    source_import = _find_import_for_symbol(symbol, imports)
    if source_import is None:
        return None

    if source_import.is_relative:
        if current_file is None:
            return None
        return _resolve_relative_import(source_import.module, current_file)

    return _resolve_require_to_path(source_import.module, project_root)


def _find_import_for_symbol(symbol: str, imports: list[Import]) -> Import | None:
    """Find which import statement brings a symbol into scope."""
    # In Ruby, require brings the whole file into scope.
    # We match symbol against the module path basename.
    symbol_lower = symbol.lower()
    for imp in imports:
        # Direct name match (e.g., `require 'helper'` matches symbol `Helper` via convention)
        module_basename = imp.module.rsplit("/", 1)[-1]
        # Ruby convention: snake_case file → CamelCase class
        if _snake_to_class(module_basename) == symbol or module_basename == symbol_lower:
            return imp
        if imp.names is not None and symbol in imp.names:
            return imp
        if imp.alias == symbol:
            return imp
    return None


def _snake_to_class(name: str) -> str:
    """Convert snake_case to CamelCase (Ruby convention)."""
    return "".join(part.capitalize() for part in name.split("_"))


def _resolve_relative_import(module: str, current_file: Path) -> Path | None:
    """Resolve a require_relative import to a file path."""
    base_dir = current_file.parent
    # Remove ./ prefix if present
    target = (base_dir / module).resolve()

    # Try with .rb extension
    if target.suffix == ".rb" and target.is_file():
        return target

    candidate = target.with_suffix(".rb")
    if candidate.is_file():
        return candidate

    return None
