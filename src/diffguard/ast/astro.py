"""Astro component extraction for hybrid AST analysis."""

import re

from diffguard.ast.languages import Language

__all__ = [
    "detect_astro_frontmatter_language",
    "extract_astro_frontmatter",
    "extract_astro_template",
]

_FRONTMATTER_FENCE = re.compile(r"^---\s*$", re.MULTILINE)

# Markers that indicate TypeScript in frontmatter content.
_TS_MARKERS = re.compile(
    r"import\s+type\s+\{|"
    r"///\s*<reference\s+types=|"
    r":\s*(?:string|number|boolean|Record|Array|Promise)\b|"
    r"\bas\s+const\b",
)


def extract_astro_frontmatter(source: str) -> tuple[str, int] | None:
    """Extract the frontmatter block (between ``---`` fences) from an Astro component.

    Returns ``(frontmatter_content, start_line_offset)`` where *start_line_offset*
    is the 1-indexed line number of the first line of frontmatter content within the
    full file.  Returns ``None`` if no frontmatter block is found.
    """
    open_match = _FRONTMATTER_FENCE.search(source)
    if open_match is None:
        return None

    close_match = _FRONTMATTER_FENCE.search(source, open_match.end())
    if close_match is None:
        return None

    inner = source[open_match.end() : close_match.start()]
    # The first line of content starts on the line after the opening ---.
    # Count newlines before end of opening fence to find its line number.
    tag_line = source[: open_match.end()].count("\n") + 1
    stripped = inner.strip("\n")
    if not stripped:
        return None
    return stripped, tag_line + 1


def detect_astro_frontmatter_language(source: str) -> Language:
    """Detect whether the frontmatter contains TypeScript.

    Returns ``Language.TYPESCRIPT`` if TypeScript markers are found
    (``import type``, triple-slash reference, type annotations);
    otherwise returns ``Language.JAVASCRIPT``.
    """
    result = extract_astro_frontmatter(source)
    if result is None:
        return Language.JAVASCRIPT

    content, _ = result
    if _TS_MARKERS.search(content):
        return Language.TYPESCRIPT
    return Language.JAVASCRIPT


def extract_astro_template(source: str) -> tuple[str, int] | None:
    """Extract the template content from an Astro component.

    The template is everything after the closing ``---`` fence.  Returns
    ``(template_content, start_line_offset)`` where *start_line_offset* is the
    1-indexed line number of the first line of template content.  Returns ``None``
    if no template content exists after the frontmatter.
    """
    open_match = _FRONTMATTER_FENCE.search(source)
    if open_match is None:
        # No frontmatter — entire file is template
        return _find_first_content_line(source, base_line=0)

    close_match = _FRONTMATTER_FENCE.search(source, open_match.end())
    if close_match is None:
        return None

    template = source[close_match.end() :]
    base_line = source[: close_match.end()].count("\n")
    return _find_first_content_line(template, base_line=base_line)


def _find_first_content_line(text: str, *, base_line: int) -> tuple[str, int] | None:
    """Find first non-empty line in *text*, returning ``(stripped, 1-indexed line)``."""
    stripped = text.strip()
    if not stripped:
        return None
    for i, line in enumerate(text.split("\n")):
        if line.strip():
            return stripped, base_line + i + 1
    return None
