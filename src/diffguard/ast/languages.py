"""Language detection and extension mapping for tree-sitter parsing."""

import enum
from pathlib import PurePosixPath


class Language(enum.Enum):
    """Programming languages supported by diffguard."""

    PYTHON = "python"
    JAVASCRIPT = "javascript"
    TYPESCRIPT = "typescript"
    JAVA = "java"
    RUBY = "ruby"
    GO = "go"
    PHP = "php"
    VUE = "vue"
    SVELTE = "svelte"
    HTML = "html"
    CSS = "css"
    MAKEFILE = "makefile"


_EXTENSION_MAP: dict[str, Language] = {
    ".py": Language.PYTHON,
    ".pyi": Language.PYTHON,
    ".js": Language.JAVASCRIPT,
    ".mjs": Language.JAVASCRIPT,
    ".cjs": Language.JAVASCRIPT,
    ".jsx": Language.JAVASCRIPT,
    ".ts": Language.TYPESCRIPT,
    ".mts": Language.TYPESCRIPT,
    ".cts": Language.TYPESCRIPT,
    ".tsx": Language.TYPESCRIPT,
    ".java": Language.JAVA,
    ".rb": Language.RUBY,
    ".go": Language.GO,
    ".php": Language.PHP,
    ".vue": Language.VUE,
    ".svelte": Language.SVELTE,
    ".html": Language.HTML,
    ".htm": Language.HTML,
    ".ejs": Language.HTML,
    ".hbs": Language.HTML,
    ".handlebars": Language.HTML,
    ".njk": Language.HTML,
    ".nunjucks": Language.HTML,
    ".pug": Language.HTML,
    ".erb": Language.HTML,
    ".jinja": Language.HTML,
    ".jinja2": Language.HTML,
    ".mustache": Language.HTML,
    ".css": Language.CSS,
    ".scss": Language.CSS,
    ".sass": Language.CSS,
    ".less": Language.CSS,
    ".mk": Language.MAKEFILE,
}

_COMPOUND_EXTENSION_MAP: dict[str, Language] = {
    ".blade.php": Language.HTML,
}

_FILENAME_MAP: dict[str, Language] = {
    "Makefile": Language.MAKEFILE,
    "makefile": Language.MAKEFILE,
    "GNUmakefile": Language.MAKEFILE,
}


def detect_language(file_path: str) -> Language | None:
    """Detect the programming language of a file from its extension or filename.

    Returns None for unrecognized or missing extensions/filenames.
    Handles case-insensitive extensions, hidden files, and double extensions.
    Checks compound extensions (e.g. .blade.php) before single-suffix lookup.
    Falls back to filename-based detection for extensionless files (e.g. Makefile).
    """
    path = PurePosixPath(file_path)
    name_lower = path.name.lower()

    # Check compound extensions first (e.g. .blade.php before .php)
    for compound_ext, lang in _COMPOUND_EXTENSION_MAP.items():
        if name_lower.endswith(compound_ext):
            return lang

    suffix = path.suffix.lower()
    if suffix:
        return _EXTENSION_MAP.get(suffix)
    return _FILENAME_MAP.get(path.name)
