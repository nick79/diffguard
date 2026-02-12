"""Tests for scope detection and context extraction."""

from __future__ import annotations

from typing import TYPE_CHECKING

from diffguard.ast import Language, parse_file
from diffguard.ast.scope import Scope, extract_scope_context, find_enclosing_scope

if TYPE_CHECKING:
    from tree_sitter import Tree

# ---------------------------------------------------------------------------
# Fixtures — Python source strings for scope tests
# ---------------------------------------------------------------------------

SIMPLE_FUNCTION = """\
x = 1

def foo(a: int, b: int) -> int:
    return a + b

y = 2
"""

ASYNC_FUNCTION = """\
import asyncio

async def fetch(url: str) -> dict:
    async with session.get(url) as response:
        return await response.json()
"""

CLASS_WITH_ATTRIBUTE = """\
class MyClass:
    x = 1

    def method(self):
        pass
"""

NESTED_SCOPES = """\
class MyClass:
    def outer_method(self):
        def inner_function():
            pass
        return inner_function

    def another_method(self):
        pass
"""

LAMBDA_IN_FUNCTION = """\
def process(items):
    result = list(map(lambda x: x * 2, items))
    return result
"""

MODULE_LEVEL_ONLY = """\
x = 1
y = 2
print(x + y)
"""

DECORATED_SINGLE = """\
@my_decorator
def decorated_func():
    pass
"""

DECORATED_MULTIPLE = """\
@decorator1
@decorator2(arg=True)
@decorator3
def my_function():
    pass
"""

DECORATED_CLASS = """\
@dataclass
class Config:
    name: str
    value: int
"""

STATIC_CLASS_PROPERTY = """\
class Service:
    @staticmethod
    def static_method():
        pass

    @classmethod
    def class_method(cls):
        pass

    @property
    def my_property(self):
        return self._value
"""

COMPREHENSION_IN_FUNCTION = """\
def process(items):
    result = [x * 2 for x in items if x > 0]
    return result
"""

EMPTY_FUNCTION = """\
def empty():
    pass
"""

MULTILINE_SIGNATURE = """\
def complex_function(
    arg1: int,
    arg2: str,
    arg3: float,
    arg4: bool = True,
) -> dict:
    x = 1
    y = 2
    return {"a": x, "b": y}
"""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _parse(source: str) -> Tree:
    """Parse Python source and return a tree-sitter Tree."""
    tree = parse_file(source, Language.PYTHON)
    assert tree is not None
    return tree


# ---------------------------------------------------------------------------
# TestFindEnclosingScope
# ---------------------------------------------------------------------------


class TestFindEnclosingScope:
    """Tests for find_enclosing_scope()."""

    def test_simple_function(self) -> None:
        tree = _parse(SIMPLE_FUNCTION)
        scope = find_enclosing_scope(tree, 4, Language.PYTHON)
        assert scope is not None
        assert scope.type == "function"
        assert scope.name == "foo"
        assert scope.start_line == 3
        assert scope.end_line == 4

    def test_async_function(self) -> None:
        tree = _parse(ASYNC_FUNCTION)
        scope = find_enclosing_scope(tree, 4, Language.PYTHON)
        assert scope is not None
        assert scope.type == "function"
        assert scope.name == "fetch"
        assert scope.start_line == 3
        assert scope.end_line == 5

    def test_class_scope_outside_method(self) -> None:
        tree = _parse(CLASS_WITH_ATTRIBUTE)
        # Line 2 is `x = 1` — inside class but not in any method
        scope = find_enclosing_scope(tree, 2, Language.PYTHON)
        assert scope is not None
        assert scope.type == "class"
        assert scope.name == "MyClass"
        assert scope.start_line == 1
        assert scope.end_line == 5

    def test_method_scope_innermost(self) -> None:
        tree = _parse(NESTED_SCOPES)
        # Line 5 is `return inner_function` — in outer_method, not inner_function
        scope = find_enclosing_scope(tree, 5, Language.PYTHON)
        assert scope is not None
        assert scope.type == "function"
        assert scope.name == "outer_method"

    def test_nested_function_scope(self) -> None:
        tree = _parse(NESTED_SCOPES)
        # Line 4 is `pass` inside inner_function
        scope = find_enclosing_scope(tree, 4, Language.PYTHON)
        assert scope is not None
        assert scope.type == "function"
        assert scope.name == "inner_function"
        assert scope.start_line == 3
        assert scope.end_line == 4

    def test_lambda_not_a_scope(self) -> None:
        tree = _parse(LAMBDA_IN_FUNCTION)
        # Line 2 has a lambda — scope should be the enclosing function
        scope = find_enclosing_scope(tree, 2, Language.PYTHON)
        assert scope is not None
        assert scope.type == "function"
        assert scope.name == "process"

    def test_no_enclosing_scope_returns_none(self) -> None:
        tree = _parse(MODULE_LEVEL_ONLY)
        scope = find_enclosing_scope(tree, 1, Language.PYTHON)
        assert scope is None

    def test_scope_at_start_boundary(self) -> None:
        tree = _parse(SIMPLE_FUNCTION)
        # Line 3 is the `def foo(...)` line itself
        scope = find_enclosing_scope(tree, 3, Language.PYTHON)
        assert scope is not None
        assert scope.name == "foo"
        assert scope.start_line == 3

    def test_scope_at_end_boundary(self) -> None:
        tree = _parse(SIMPLE_FUNCTION)
        # Line 4 is the last line of foo
        scope = find_enclosing_scope(tree, 4, Language.PYTHON)
        assert scope is not None
        assert scope.name == "foo"
        assert scope.end_line == 4

    def test_decorated_function_includes_decorator(self) -> None:
        tree = _parse(DECORATED_SINGLE)
        scope = find_enclosing_scope(tree, 3, Language.PYTHON)
        assert scope is not None
        assert scope.type == "function"
        assert scope.name == "decorated_func"
        assert scope.start_line == 1  # Includes @my_decorator
        assert scope.end_line == 3

    def test_multiple_decorators_included(self) -> None:
        tree = _parse(DECORATED_MULTIPLE)
        scope = find_enclosing_scope(tree, 5, Language.PYTHON)
        assert scope is not None
        assert scope.name == "my_function"
        assert scope.start_line == 1  # All 3 decorators included
        assert scope.end_line == 5

    def test_class_with_decorator(self) -> None:
        tree = _parse(DECORATED_CLASS)
        scope = find_enclosing_scope(tree, 3, Language.PYTHON)
        assert scope is not None
        assert scope.type == "class"
        assert scope.name == "Config"
        assert scope.start_line == 1  # Includes @dataclass
        assert scope.end_line == 4

    def test_scope_truncation_over_limit(self) -> None:
        body_lines = [f"    line_{i} = {i}" for i in range(300)]
        source = "def large_function():\n" + "\n".join(body_lines) + "\n    pass\n"
        source_lines = source.splitlines()
        scope = Scope(type="function", name="large_function", start_line=1, end_line=len(source_lines))
        result = extract_scope_context(scope, source_lines, limit=200)
        result_lines = result.split("\n")
        assert result_lines[-1] == f"... [truncated {len(source_lines) - 200} lines]"
        # First 200 lines are preserved (plus the truncation marker line)
        assert len(result_lines) == 201

    def test_scope_truncation_preserves_signature(self) -> None:
        body_lines = [f"    line_{i} = {i}" for i in range(100)]
        source = MULTILINE_SIGNATURE.rstrip("\n") + "\n" + "\n".join(body_lines) + "\n"
        source_lines = source.splitlines()
        scope = Scope(type="function", name="complex_function", start_line=1, end_line=len(source_lines))
        result = extract_scope_context(scope, source_lines, limit=50)
        # The 6-line signature must be included in the first 50 lines
        assert "def complex_function(" in result
        assert ") -> dict:" in result

    def test_scope_under_limit_returns_full(self) -> None:
        source_lines = SIMPLE_FUNCTION.splitlines()
        scope = Scope(type="function", name="foo", start_line=3, end_line=4)
        result = extract_scope_context(scope, source_lines, limit=200)
        assert "... [truncated" not in result
        assert "def foo(a: int, b: int) -> int:" in result
        assert "return a + b" in result

    def test_scope_extraction_empty_function(self) -> None:
        source_lines = EMPTY_FUNCTION.splitlines()
        scope = Scope(type="function", name="empty", start_line=1, end_line=2)
        result = extract_scope_context(scope, source_lines, limit=200)
        assert "def empty():" in result
        assert "pass" in result

    def test_comprehension_not_a_scope(self) -> None:
        tree = _parse(COMPREHENSION_IN_FUNCTION)
        # Line 2 has a list comprehension — scope should be the function
        scope = find_enclosing_scope(tree, 2, Language.PYTHON)
        assert scope is not None
        assert scope.type == "function"
        assert scope.name == "process"

    def test_static_method_scope(self) -> None:
        tree = _parse(STATIC_CLASS_PROPERTY)
        # Line 4 is `pass` inside static_method
        scope = find_enclosing_scope(tree, 4, Language.PYTHON)
        assert scope is not None
        assert scope.type == "function"
        assert scope.name == "static_method"
        assert scope.start_line == 2  # Includes @staticmethod

    def test_class_method_scope(self) -> None:
        tree = _parse(STATIC_CLASS_PROPERTY)
        # Line 8 is `pass` inside class_method
        scope = find_enclosing_scope(tree, 8, Language.PYTHON)
        assert scope is not None
        assert scope.type == "function"
        assert scope.name == "class_method"
        assert scope.start_line == 6  # Includes @classmethod

    def test_property_scope(self) -> None:
        tree = _parse(STATIC_CLASS_PROPERTY)
        # Line 12 is `return self._value` inside my_property
        scope = find_enclosing_scope(tree, 12, Language.PYTHON)
        assert scope is not None
        assert scope.type == "function"
        assert scope.name == "my_property"
        assert scope.start_line == 10  # Includes @property

    def test_new_file_exempt_from_truncation(self) -> None:
        body_lines = [f"    line_{i} = {i}" for i in range(300)]
        source = "def large_function():\n" + "\n".join(body_lines) + "\n    pass\n"
        source_lines = source.splitlines()
        scope = Scope(type="function", name="large_function", start_line=1, end_line=len(source_lines))
        result = extract_scope_context(scope, source_lines, limit=200, is_new_file=True)
        assert "... [truncated" not in result
        # All lines should be present
        assert result.count("\n") == len(source_lines) - 1


# ---------------------------------------------------------------------------
# TestFindEnclosingScopeEdgeCases
# ---------------------------------------------------------------------------


class TestFindEnclosingScopeEdgeCases:
    """Edge cases for find_enclosing_scope()."""

    def test_line_zero_returns_none(self) -> None:
        tree = _parse(SIMPLE_FUNCTION)
        assert find_enclosing_scope(tree, 0, Language.PYTHON) is None

    def test_negative_line_returns_none(self) -> None:
        tree = _parse(SIMPLE_FUNCTION)
        assert find_enclosing_scope(tree, -1, Language.PYTHON) is None

    def test_line_beyond_file_returns_none(self) -> None:
        tree = _parse(SIMPLE_FUNCTION)
        assert find_enclosing_scope(tree, 9999, Language.PYTHON) is None

    def test_unsupported_language_returns_none(self) -> None:
        tree = _parse(SIMPLE_FUNCTION)
        assert find_enclosing_scope(tree, 4, Language.JAVASCRIPT) is None

    def test_decorator_line_returns_function_scope(self) -> None:
        tree = _parse(DECORATED_SINGLE)
        # Line 1 is the @my_decorator line
        scope = find_enclosing_scope(tree, 1, Language.PYTHON)
        assert scope is not None
        assert scope.name == "decorated_func"
        assert scope.start_line == 1

    def test_another_method_in_nested_scopes(self) -> None:
        tree = _parse(NESTED_SCOPES)
        # Line 8 is `pass` in another_method
        scope = find_enclosing_scope(tree, 8, Language.PYTHON)
        assert scope is not None
        assert scope.name == "another_method"
        assert scope.start_line == 7
        assert scope.end_line == 8
