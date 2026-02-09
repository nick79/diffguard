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
}


def detect_language(file_path: str) -> Language | None:
    """Detect the programming language of a file from its extension.

    Returns None for unrecognized or missing extensions.
    Handles case-insensitive extensions, hidden files, and double extensions.
    """
    suffix = PurePosixPath(file_path).suffix.lower()
    return _EXTENSION_MAP.get(suffix)
