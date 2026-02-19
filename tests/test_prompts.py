"""Tests for prompt construction."""

from diffguard.llm.prompts import (
    SYSTEM_PROMPT,
    CodeContext,
    DiffLine,
    ScopeContext,
    SymbolDef,
    _estimate_tokens,
    build_user_prompt,
)

# ---------------------------------------------------------------------------
# Sample data
# ---------------------------------------------------------------------------

SAMPLE_CONTEXT = CodeContext(
    file_path="src/api/handler.py",
    diff_lines=[
        DiffLine(line_num=10, change_type="+", content="    user_input = request.get('data')"),
        DiffLine(line_num=11, change_type="+", content="    db.execute(f'SELECT * FROM users WHERE id={user_input}')"),
    ],
    expanded_region=(
        "def handle_request(request):\n"
        "    # Process the request\n"
        "    data = request.json()\n"
        "    if not data:\n"
        "        return error_response(400)\n"
        "    user_input = request.get('data')\n"
        "    db.execute(f'SELECT * FROM users WHERE id={user_input}')\n"
        "    result = process(data)\n"
        "    return success_response(result)"
    ),
    region_start_line=5,
    scopes=[
        ScopeContext(
            type="function",
            name="handle_request",
            start_line=5,
            end_line=20,
            source="def handle_request(request):\n    # ... full function body ...",
        ),
    ],
    symbols={
        "validate": SymbolDef(
            name="validate",
            code=(
                "def validate(data):\n"
                "    if not isinstance(data, dict):\n"
                "        raise ValueError('Expected dict')\n"
                "    return True"
            ),
            file="src/utils.py",
        ),
    },
)


def _context_with_no_scope() -> CodeContext:
    return CodeContext(
        file_path="src/simple.py",
        diff_lines=[DiffLine(line_num=3, change_type="+", content="x = eval(input())")],
        expanded_region="import os\n\nx = eval(input())\nprint(x)",
        region_start_line=1,
    )


def _context_with_removed_lines() -> CodeContext:
    return CodeContext(
        file_path="src/auth.py",
        diff_lines=[
            DiffLine(line_num=5, change_type="-", content="    validate(token)"),
            DiffLine(line_num=5, change_type="+", content="    pass  # TODO: validate"),
        ],
        expanded_region="def login(token):\n    pass  # TODO: validate\n    return True",
        region_start_line=4,
    )


# ---------------------------------------------------------------------------
# AC1-5: System prompt tests
# ---------------------------------------------------------------------------


class TestSystemPrompt:
    def test_contains_role_definition(self) -> None:
        assert "security analyst" in SYSTEM_PROMPT.lower()
        assert "code review" in SYSTEM_PROMPT.lower()

    def test_specifies_json_output_format(self) -> None:
        assert '"findings"' in SYSTEM_PROMPT
        assert '"what"' in SYSTEM_PROMPT
        assert '"why"' in SYSTEM_PROMPT
        assert '"how_to_fix"' in SYSTEM_PROMPT
        assert '"severity"' in SYSTEM_PROMPT
        assert '"confidence"' in SYSTEM_PROMPT
        assert '"line_range"' in SYSTEM_PROMPT
        assert "JSON" in SYSTEM_PROMPT

    def test_references_owasp_cwe(self) -> None:
        assert "OWASP" in SYSTEM_PROMPT
        assert "Top 10" in SYSTEM_PROMPT
        assert "CWE" in SYSTEM_PROMPT

    def test_defines_severity_levels(self) -> None:
        for level in ["Critical", "High", "Medium", "Low", "Info"]:
            assert level in SYSTEM_PROMPT
        assert "CVSS" in SYSTEM_PROMPT

    def test_defines_confidence_levels(self) -> None:
        prompt_lower = SYSTEM_PROMPT.lower()
        assert "confidence" in prompt_lower
        for level in ["High", "Medium", "Low"]:
            assert level in SYSTEM_PROMPT


# ---------------------------------------------------------------------------
# AC6-12: Single file prompt tests
# ---------------------------------------------------------------------------


class TestBuildUserPromptSingleFile:
    def test_single_file_contains_path_and_code(self) -> None:
        prompt = build_user_prompt(SAMPLE_CONTEXT)

        assert "src/api/handler.py" in prompt
        assert "user_input = request.get('data')" in prompt

    def test_file_path_clearly_marked(self) -> None:
        prompt = build_user_prompt(SAMPLE_CONTEXT)

        assert "## File: src/api/handler.py" in prompt

    def test_diff_lines_highlighted(self) -> None:
        prompt = build_user_prompt(SAMPLE_CONTEXT)

        assert "|+ " in prompt
        lines = prompt.splitlines()
        added = [line for line in lines if "|+" in line]
        assert len(added) == 2
        assert any("user_input = request.get('data')" in line for line in added)
        assert any("db.execute" in line for line in added)

    def test_context_lines_not_marked(self) -> None:
        prompt = build_user_prompt(SAMPLE_CONTEXT)

        lines = prompt.splitlines()
        context_lines = [line for line in lines if "| " in line and "|+" not in line]
        assert len(context_lines) > 0

    def test_scope_context_included(self) -> None:
        prompt = build_user_prompt(SAMPLE_CONTEXT)

        assert "Enclosing Scopes" in prompt
        assert "function" in prompt
        assert "`handle_request`" in prompt

    def test_scope_source_included(self) -> None:
        prompt = build_user_prompt(SAMPLE_CONTEXT)

        assert "full function body" in prompt

    def test_multiple_scopes(self) -> None:
        ctx = CodeContext(
            file_path="src/api/handler.py",
            diff_lines=[DiffLine(line_num=15, change_type="+", content="    self.data = data")],
            expanded_region="    self.data = data",
            region_start_line=15,
            scopes=[
                ScopeContext(
                    type="function", name="__init__", start_line=12, end_line=20, source="def __init__(self, data): ..."
                ),
                ScopeContext(
                    type="class", name="APIHandler", start_line=1, end_line=50, source="class APIHandler: ..."
                ),
            ],
        )
        prompt = build_user_prompt(ctx)

        assert "`__init__`" in prompt
        assert "`APIHandler`" in prompt
        assert "function" in prompt
        assert "class" in prompt

    def test_symbol_definitions_included(self) -> None:
        prompt = build_user_prompt(SAMPLE_CONTEXT)

        assert "Referenced Definitions" in prompt
        assert "`validate`" in prompt
        assert "src/utils.py" in prompt
        assert "def validate(data):" in prompt

    def test_multiple_symbols(self) -> None:
        ctx = CodeContext(
            file_path="src/app.py",
            diff_lines=[DiffLine(line_num=10, change_type="+", content="result = process(sanitize(data))")],
            expanded_region="result = process(sanitize(data))",
            region_start_line=10,
            symbols={
                "process": SymbolDef(name="process", code="def process(data): ...", file="src/core.py"),
                "sanitize": SymbolDef(name="sanitize", code="def sanitize(s): ...", file="src/utils.py"),
                "logger": SymbolDef(name="logger", code="logger = logging.getLogger(__name__)", file="src/log.py"),
            },
        )
        prompt = build_user_prompt(ctx)

        assert "`process`" in prompt
        assert "`sanitize`" in prompt
        assert "`logger`" in prompt
        assert "src/core.py" in prompt
        assert "src/utils.py" in prompt
        assert "src/log.py" in prompt


# ---------------------------------------------------------------------------
# AC13: Multiple files
# ---------------------------------------------------------------------------


class TestBuildUserPromptMultiFile:
    def test_multiple_files(self) -> None:
        contexts = [
            CodeContext(
                file_path="src/api/auth.py",
                diff_lines=[DiffLine(line_num=5, change_type="+", content="    token = request.headers['auth']")],
                expanded_region="def authenticate(request):\n    token = request.headers['auth']",
                region_start_line=4,
            ),
            CodeContext(
                file_path="src/api/users.py",
                diff_lines=[
                    DiffLine(line_num=12, change_type="+", content="    db.query(f'DELETE FROM users WHERE id={uid}')")
                ],
                expanded_region="def delete_user(uid):\n    db.query(f'DELETE FROM users WHERE id={uid}')",
                region_start_line=11,
            ),
            CodeContext(
                file_path="src/api/admin.py",
                diff_lines=[DiffLine(line_num=8, change_type="+", content="    os.system(cmd)")],
                expanded_region="def run_command(cmd):\n    os.system(cmd)",
                region_start_line=7,
            ),
        ]
        prompt = build_user_prompt(contexts)

        assert "## File: src/api/auth.py" in prompt
        assert "## File: src/api/users.py" in prompt
        assert "## File: src/api/admin.py" in prompt
        assert "---" in prompt


# ---------------------------------------------------------------------------
# AC14: Empty context
# ---------------------------------------------------------------------------


class TestBuildUserPromptEmpty:
    def test_empty_context_list(self) -> None:
        prompt = build_user_prompt([])

        assert "No code changes" in prompt

    def test_context_with_no_diff_lines(self) -> None:
        ctx = CodeContext(
            file_path="src/empty.py",
            diff_lines=[],
            expanded_region="",
            region_start_line=1,
        )
        prompt = build_user_prompt(ctx)

        assert "src/empty.py" in prompt


# ---------------------------------------------------------------------------
# AC15-18: Prompt truncation
# ---------------------------------------------------------------------------


def _make_large_context() -> CodeContext:
    """Create a context large enough to require truncation."""
    large_scope_source = "\n".join(f"    line_{i} = {i}" for i in range(500))
    large_symbols = {
        f"sym_{i}": SymbolDef(
            name=f"sym_{i}",
            code=f"def sym_{i}(x):\n    return x * {i}\n\n" * 10,
            file=f"src/mod_{i}.py",
        )
        for i in range(20)
    }
    # Build expanded region with the diff line at the correct offset
    region_lines = [f"line_{i} = {i}" for i in range(100)]
    region_lines[50] = "x = eval(input())"  # line 500 = offset 50 from start 450
    return CodeContext(
        file_path="src/large.py",
        diff_lines=[DiffLine(line_num=500, change_type="+", content="x = eval(input())")],
        expanded_region="\n".join(region_lines),
        region_start_line=450,
        scopes=[
            ScopeContext(
                type="function",
                name="big_function",
                start_line=1,
                end_line=1000,
                source=large_scope_source,
            ),
        ],
        symbols=large_symbols,
    )


class TestPromptTruncation:
    def test_no_truncation_when_under_limit(self) -> None:
        prompt_full = build_user_prompt(SAMPLE_CONTEXT)
        prompt_limited = build_user_prompt(SAMPLE_CONTEXT, max_tokens=100_000)

        assert prompt_full == prompt_limited

    def test_truncation_when_over_limit(self) -> None:
        ctx = _make_large_context()
        prompt_full = build_user_prompt(ctx)
        prompt_truncated = build_user_prompt(ctx, max_tokens=500)

        assert len(prompt_truncated) < len(prompt_full)
        assert "truncated" in prompt_truncated.lower()

    def test_preserves_diff_lines(self) -> None:
        ctx = _make_large_context()
        prompt = build_user_prompt(ctx, max_tokens=500)

        assert "x = eval(input())" in prompt

    def test_truncates_scope_first(self) -> None:
        ctx = _make_large_context()

        full_prompt = build_user_prompt(ctx)
        full_tokens = _estimate_tokens(full_prompt)

        # Set limit so scope source must be dropped but symbols can stay
        scope_source_tokens = _estimate_tokens(ctx.scopes[0].source)
        limit = full_tokens - scope_source_tokens + 100

        prompt = build_user_prompt(ctx, max_tokens=limit)

        # Scope source gone (no "line_0 = 0" from scope source)
        # but scope metadata remains
        assert "`big_function`" in prompt
        # At least some symbols should remain
        assert "Referenced Definitions" in prompt

    def test_truncates_symbols_after_scope(self) -> None:
        ctx = _make_large_context()
        prompt = build_user_prompt(ctx, max_tokens=500)

        # With very tight limit, both scope source and symbols should be gone
        assert "Referenced Definitions" not in prompt
        # But diff lines and code context remain
        assert "Code Context" in prompt
        assert "x = eval(input())" in prompt


# ---------------------------------------------------------------------------
# AC19-21: Prompt format
# ---------------------------------------------------------------------------


class TestPromptFormat:
    def test_includes_line_numbers(self) -> None:
        prompt = build_user_prompt(SAMPLE_CONTEXT)

        assert "  10 |" in prompt
        assert "  11 |" in prompt
        assert "   5 |" in prompt

    def test_special_characters_in_code_blocks(self) -> None:
        ctx = CodeContext(
            file_path="src/markdown.py",
            diff_lines=[DiffLine(line_num=2, change_type="+", content='    result = f"```{data}```"')],
            expanded_region='# Comment with ## heading\n    result = f"```{data}```"\nmore = True',
            region_start_line=1,
        )
        prompt = build_user_prompt(ctx)

        # Code is in fenced code blocks, special chars preserved
        assert "```{data}```" in prompt
        assert "## heading" in prompt  # appears inside code block, not as markdown heading

    def test_consistent_format_across_calls(self) -> None:
        ctx1 = _context_with_no_scope()
        ctx2 = CodeContext(
            file_path="src/other.py",
            diff_lines=[DiffLine(line_num=1, change_type="+", content="import os")],
            expanded_region="import os",
            region_start_line=1,
        )

        prompt1 = build_user_prompt(ctx1)
        prompt2 = build_user_prompt(ctx2)

        # Both have file header and code context sections
        assert "## File:" in prompt1
        assert "## File:" in prompt2
        assert "### Code Context" in prompt1
        assert "### Code Context" in prompt2
        # Both end with the analysis instruction
        assert prompt1.endswith("Analyze the above code changes for security vulnerabilities.")
        assert prompt2.endswith("Analyze the above code changes for security vulnerabilities.")

    def test_removed_lines_section(self) -> None:
        ctx = _context_with_removed_lines()
        prompt = build_user_prompt(ctx)

        assert "### Removed Lines" in prompt
        assert "validate(token)" in prompt

    def test_accepts_single_context(self) -> None:
        prompt = build_user_prompt(SAMPLE_CONTEXT)

        assert "## File: src/api/handler.py" in prompt

    def test_accepts_list_of_contexts(self) -> None:
        prompt = build_user_prompt([SAMPLE_CONTEXT])

        assert "## File: src/api/handler.py" in prompt
