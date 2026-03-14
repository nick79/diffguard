"""Vue Single File Component extraction for hybrid AST analysis."""

import re

from diffguard.ast.languages import Language

__all__ = [
    "detect_vue_script_language",
    "extract_vue_script",
    "extract_vue_template",
]

_SCRIPT_OPEN = re.compile(r"<script\b([^>]*)>", re.IGNORECASE)
_SCRIPT_CLOSE = re.compile(r"</script\s*>", re.IGNORECASE)
_TEMPLATE_OPEN = re.compile(r"<template\b([^>]*)>", re.IGNORECASE)
_TEMPLATE_CLOSE = re.compile(r"</template\s*>", re.IGNORECASE)
_LANG_ATTR = re.compile(r'lang\s*=\s*["\'](\w+)["\']', re.IGNORECASE)


def extract_vue_script(source: str) -> tuple[str, int] | None:
    """Extract the ``<script>`` block content from a Vue SFC.

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


def detect_vue_script_language(source: str) -> Language:
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


def extract_vue_template(source: str) -> tuple[str, int] | None:
    """Extract the ``<template>`` block content from a Vue SFC.

    Returns ``(template_content, start_line_offset)`` where *start_line_offset*
    is the 1-indexed line number of the first line of template content within
    the full file.  Returns ``None`` if no ``<template>`` block is found.
    """
    open_match = _TEMPLATE_OPEN.search(source)
    if open_match is None:
        return None

    close_match = _TEMPLATE_CLOSE.search(source, open_match.end())
    if close_match is None:
        return None

    inner = source[open_match.end() : close_match.start()]
    tag_line = source[: open_match.end()].count("\n") + 1
    return inner.strip("\n"), tag_line + 1
