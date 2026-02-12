"""Python-specific AST analysis using tree-sitter."""

from __future__ import annotations

from typing import TYPE_CHECKING

from diffguard.ast.scope import Scope

if TYPE_CHECKING:
    from tree_sitter import Node, Tree

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
