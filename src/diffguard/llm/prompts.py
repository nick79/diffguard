"""Prompt construction for LLM security analysis."""

from dataclasses import dataclass, field
from typing import Literal

__all__ = [
    "SYSTEM_PROMPT",
    "CodeContext",
    "DiffLine",
    "ScopeContext",
    "SymbolDef",
    "build_user_prompt",
    "estimate_tokens",
]


@dataclass
class DiffLine:
    """A single changed line from a diff."""

    line_num: int
    change_type: Literal["+", "-", " "]
    content: str


@dataclass
class SymbolDef:
    """A resolved first-party symbol definition."""

    name: str
    code: str
    file: str


@dataclass
class ScopeContext:
    """An enclosing scope with its source code for prompt context."""

    type: str
    name: str
    start_line: int
    end_line: int
    source: str


@dataclass
class CodeContext:
    """Complete context for a single file to be analyzed by the LLM."""

    file_path: str
    diff_lines: list[DiffLine]
    expanded_region: str
    region_start_line: int = 1
    scopes: list[ScopeContext] = field(default_factory=list)
    symbols: dict[str, SymbolDef] = field(default_factory=dict)


SYSTEM_PROMPT = """\
You are a senior security analyst performing a focused code review for security vulnerabilities.

## Task
Analyze the provided code changes for security vulnerabilities. \
Focus on the CHANGED lines (marked with `+` for additions and `-` for removals). \
Surrounding context and referenced definitions are provided to help you understand the code's behavior.

## Output Format
Respond ONLY with a JSON object containing a "findings" array:

{
  "findings": [
    {
      "what": "Brief description of the vulnerability",
      "why": "Explanation of the security impact and risk",
      "how_to_fix": "Step-by-step remediation: what to change, a short code example showing the secure pattern",
      "severity": "Critical|High|Medium|Low|Info",
      "confidence": "High|Medium|Low",
      "cwe_id": "CWE-XXX",
      "owasp_category": "AXX:2025-Category Name",
      "line_range": {"start": 10, "end": 15},
      "file_path": "path/to/file"
    }
  ]
}

Return {"findings": []} if no security issues are found.

## Severity Classification Rules
Assign severity based on the CWE and exploit conditions. Use EXACTLY these rules:

### Critical — Direct, unauthenticated exploitation leading to full system compromise
Assign Critical ONLY when ALL of these conditions are met:
1. The vulnerability allows remote code execution, OS command injection, or full authentication bypass.
2. No user interaction or special privileges are required to exploit it.
3. The vulnerable code path is directly reachable from external input.

CWEs that are Critical (when conditions above are met):
- CWE-78 (OS Command Injection), CWE-94 (Code Injection), CWE-95 (Eval Injection)
- CWE-502 (Deserialization of Untrusted Data) — only if it leads to RCE
- CWE-287 (Improper Authentication) — only if it's a complete bypass
- CWE-306 (Missing Authentication for Critical Function)

### High — Exploitable vulnerabilities with significant but bounded impact
Assign High when the vulnerability is exploitable but requires SOME conditions:
- User interaction required (e.g., clicking a link for XSS)
- Attacker needs authenticated access
- Impact is significant but not full system compromise

CWEs that are typically High:
- CWE-89 (SQL Injection), CWE-79 (XSS), CWE-22 (Path Traversal)
- CWE-502 (Deserialization) — when impact is data tampering, not RCE
- CWE-327 (Broken Crypto), CWE-330 (Insufficient Randomness for security tokens)
- CWE-918 (SSRF), CWE-611 (XXE), CWE-776 (XML Entity Expansion)
- CWE-798 (Hardcoded Credentials), CWE-259 (Hardcoded Password)
- CWE-434 (Unrestricted File Upload)

### Medium — Conditionally exploitable or moderate impact
Assign Medium when exploitation requires specific conditions or impact is limited:
- Requires chaining with another vulnerability
- Limited to information disclosure (not credentials)
- Requires specific configuration or environment

CWEs that are typically Medium:
- CWE-352 (CSRF), CWE-200 (Information Exposure)
- CWE-532 (Log Injection / sensitive data in logs)
- CWE-614 (Missing Secure flag on cookie), CWE-1004 (Missing HttpOnly)
- CWE-311 (Missing Encryption), CWE-319 (Cleartext Transmission)
- CWE-601 (Open Redirect)

### Low — Minor issues with minimal security impact
- CWE-209 (Error Message Information Exposure)
- CWE-1236 (Improper Neutralization of Formula Elements)
- Minor configuration weaknesses

### Info — Best practice recommendations with no direct exploitability
- Code quality suggestions, defense-in-depth recommendations

### Severity override rules
- If confidence is Low, cap severity at Medium regardless of CWE.
- If the vulnerable code is behind authentication AND requires admin privileges, reduce by one level.
- Never assign Critical to a finding that requires user interaction to exploit.

## Confidence Levels
- **High**: Clear, well-established vulnerability pattern with complete context \
(e.g., unsanitized SQL concatenation, hardcoded credentials, pickle.loads on user input).
- **Medium**: Suspicious code but incomplete context \
(e.g., input validation may exist elsewhere, sanitization might happen in a calling function).
- **Low**: Possible concern based on patterns, but significant uncertainty remains.

## Classification
- Classify findings using OWASP Top 10 (2025) categories.
- Include CWE identifiers for precise classification.
- Omit cwe_id or owasp_category if you cannot determine them confidently.

## Rules
- Focus ONLY on changed lines (marked + or -). Do not report issues in unchanged context.
- Be precise about affected line numbers.
- Provide detailed remediation in how_to_fix: include what to change, a short code example \
showing the secure pattern, and a one-line explanation of why it prevents the vulnerability. \
Never return one-sentence generic advice like "sanitize input".
- Use Low confidence when context is insufficient.
- Do not fabricate findings. Return empty findings if the code is secure.
- Be consistent: the same code pattern with the same CWE must always get the same severity."""

_TRUNCATION_MARKER = "... [truncated for token limit]"
_FOOTER = "Analyze the above code changes for security vulnerabilities."


def estimate_tokens(text: str) -> int:
    """Estimate token count using a ~4 characters per token heuristic."""
    return len(text) // 4


def build_user_prompt(
    contexts: CodeContext | list[CodeContext],
    *,
    max_tokens: int | None = None,
) -> str:
    """Build the user prompt from code contexts for LLM analysis.

    Args:
        contexts: One or more file contexts to include in the prompt.
        max_tokens: Optional token budget for the user prompt. If set,
            truncates supplementary context (scopes first, then symbols)
            to fit. Diff lines and expanded regions are never truncated.

    Returns:
        Formatted prompt string ready to send to the LLM.
    """
    if isinstance(contexts, CodeContext):
        contexts = [contexts]

    if not contexts:
        return "No code changes to analyze."

    prompt = _assemble_prompt(contexts)

    if max_tokens is None or estimate_tokens(prompt) <= max_tokens:
        return prompt

    return _truncate_prompt(contexts, max_tokens)


def _assemble_prompt(contexts: list[CodeContext]) -> str:
    """Assemble the full prompt from file sections."""
    sections = [_format_file_section(ctx) for ctx in contexts]
    return "\n\n---\n\n".join(sections) + f"\n\n{_FOOTER}"


def _truncate_prompt(contexts: list[CodeContext], max_tokens: int) -> str:
    """Truncate prompt to fit within token budget.

    Truncation order:
    1. Remove scope source code (keep scope metadata)
    2. Remove symbol definitions
    3. Diff lines and expanded regions are NEVER truncated.
    """
    # Step 1: Strip scope source, keep metadata
    scopes_stripped = [
        CodeContext(
            file_path=ctx.file_path,
            diff_lines=ctx.diff_lines,
            expanded_region=ctx.expanded_region,
            region_start_line=ctx.region_start_line,
            scopes=[
                ScopeContext(type=s.type, name=s.name, start_line=s.start_line, end_line=s.end_line, source="")
                for s in ctx.scopes
            ],
            symbols=ctx.symbols,
        )
        for ctx in contexts
    ]

    sections = [_format_file_section(ctx) for ctx in scopes_stripped]
    prompt = "\n\n---\n\n".join(sections) + f"\n\n{_TRUNCATION_MARKER}\n\n{_FOOTER}"

    if estimate_tokens(prompt) <= max_tokens:
        return prompt

    # Step 2: Also remove symbols (reuse already-stripped scopes)
    fully_stripped = [
        CodeContext(
            file_path=ctx.file_path,
            diff_lines=ctx.diff_lines,
            expanded_region=ctx.expanded_region,
            region_start_line=ctx.region_start_line,
            scopes=ctx.scopes,
            symbols={},
        )
        for ctx in scopes_stripped
    ]

    sections = [_format_file_section(ctx) for ctx in fully_stripped]
    return "\n\n---\n\n".join(sections) + f"\n\n{_TRUNCATION_MARKER}\n\n{_FOOTER}"


def _format_file_section(context: CodeContext) -> str:
    """Format a single file's context as a prompt section."""
    parts: list[str] = []

    parts.append(f"## File: {context.file_path}")

    code_block = _format_code_block(context)
    if code_block:
        parts.append(f"### Code Context\n```\n{code_block}\n```")

    removed = [dl for dl in context.diff_lines if dl.change_type == "-"]
    if removed:
        removed_block = "\n".join(f"{dl.line_num:>4} |- {dl.content}" for dl in removed)
        parts.append(f"### Removed Lines\n```\n{removed_block}\n```")

    if context.scopes:
        scope_lines: list[str] = []
        for scope in context.scopes:
            header = f"- {scope.type} `{scope.name}` (lines {scope.start_line}-{scope.end_line})"
            if scope.source:
                scope_lines.append(f"{header}:\n```\n{scope.source}\n```")
            else:
                scope_lines.append(header)
        parts.append("### Enclosing Scopes\n" + "\n".join(scope_lines))

    if context.symbols:
        sym_lines: list[str] = []
        for name, sym_def in context.symbols.items():
            sym_lines.append(f"**`{name}`** (from `{sym_def.file}`):\n```\n{sym_def.code}\n```")
        parts.append("### Referenced Definitions\n" + "\n".join(sym_lines))

    return "\n\n".join(parts)


def _format_code_block(context: CodeContext) -> str:
    """Format the expanded region with line numbers and change markers."""
    added_line_nums = {dl.line_num for dl in context.diff_lines if dl.change_type == "+"}

    if not context.expanded_region:
        if not added_line_nums:
            return ""
        formatted: list[str] = []
        for dl in sorted(context.diff_lines, key=lambda d: d.line_num):
            if dl.change_type == "+":
                formatted.append(f"{dl.line_num:>4} |+ {dl.content}")
        return "\n".join(formatted)

    lines = context.expanded_region.splitlines()
    formatted = []
    for i, line in enumerate(lines):
        line_num = context.region_start_line + i
        marker = "+" if line_num in added_line_nums else " "
        formatted.append(f"{line_num:>4} |{marker} {line}")

    return "\n".join(formatted)
