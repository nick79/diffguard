"""Svelte Single File Component extraction for hybrid AST analysis."""

import re

from diffguard.ast.languages import Language

__all__ = [
    "detect_svelte_script_language",
    "extract_svelte_script",
    "extract_svelte_template",
]

_SCRIPT_OPEN = re.compile(r"<script\b([^>]*)>", re.IGNORECASE)
_SCRIPT_CLOSE = re.compile(r"</script\s*>", re.IGNORECASE)
_STYLE_OPEN = re.compile(r"<style\b[^>]*>", re.IGNORECASE)
_STYLE_CLOSE = re.compile(r"</style\s*>", re.IGNORECASE)
_LANG_ATTR = re.compile(r'lang\s*=\s*["\'](\w+)["\']', re.IGNORECASE)

# Matches an entire <script ...>...</script> or <style ...>...</style> block.
_SCRIPT_BLOCK = re.compile(r"<script\b[^>]*>.*?</script\s*>", re.IGNORECASE | re.DOTALL)
_STYLE_BLOCK = re.compile(r"<style\b[^>]*>.*?</style\s*>", re.IGNORECASE | re.DOTALL)


def extract_svelte_script(source: str) -> tuple[str, int] | None:
    """Extract the ``<script>`` block content from a Svelte component.

    Returns ``(script_content, start_line_offset)`` where *start_line_offset*
    is the 1-indexed line number of the first line of script content within the
    full file.  Returns ``None`` if no ``<script>`` block is found.
    """
    open_match = _SCRIPT_OPEN.search(source)
    if open_match is None:
        return None

    close_match = _SCRIPT_CLOSE.search(source, open_match.end())
    if close_match is None:
        return None

    inner = source[open_match.end() : close_match.start()]
    # The first line of content starts on the line after the <script> tag.
    # Count newlines *before* the end of the opening tag to find its line.
    tag_line = source[: open_match.end()].count("\n") + 1
    return inner.strip("\n"), tag_line + 1


def detect_svelte_script_language(source: str) -> Language:
    """Detect whether the ``<script>`` tag specifies TypeScript.

    Returns ``Language.TYPESCRIPT`` if ``lang="ts"`` or ``lang="typescript"``
    is present; otherwise returns ``Language.JAVASCRIPT``.
    """
    open_match = _SCRIPT_OPEN.search(source)
    if open_match is None:
        return Language.JAVASCRIPT

    attrs = open_match.group(1)
    lang_match = _LANG_ATTR.search(attrs)
    if lang_match is None:
        return Language.JAVASCRIPT

    lang_value = lang_match.group(1).lower()
    if lang_value in ("ts", "typescript"):
        return Language.TYPESCRIPT
    return Language.JAVASCRIPT


def extract_svelte_template(source: str) -> tuple[str, int] | None:
    """Extract the template content from a Svelte component.

    Svelte templates are implicit — everything outside ``<script>`` and
    ``<style>`` blocks is template content.  Returns
    ``(template_content, start_line_offset)`` where *start_line_offset* is the
    1-indexed line number of the first non-empty template line.  Returns
    ``None`` if no template content remains after stripping blocks.
    """
    # Remove all <script> and <style> blocks, preserving line numbers
    # by replacing content with empty lines.
    result = source
    for pattern in (_SCRIPT_BLOCK, _STYLE_BLOCK):
        for m in reversed(list(pattern.finditer(result))):
            # Count newlines in the matched block to preserve line numbering
            newline_count = m.group(0).count("\n")
            result = result[: m.start()] + "\n" * newline_count + result[m.end() :]

    # Check if any non-whitespace content remains
    stripped = result.strip()
    if not stripped:
        return None

    # Find the first non-empty line to determine start_line_offset
    lines = result.split("\n")
    for i, line in enumerate(lines):
        if line.strip():
            return stripped, i + 1

    return None
