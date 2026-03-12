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
    ".mk": Language.MAKEFILE,
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
    Falls back to filename-based detection for extensionless files (e.g. Makefile).
    """
    path = PurePosixPath(file_path)
    suffix = path.suffix.lower()
    if suffix:
        return _EXTENSION_MAP.get(suffix)
    return _FILENAME_MAP.get(path.name)
