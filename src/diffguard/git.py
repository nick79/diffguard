"""Git diff parsing and extraction."""

import re
import subprocess
from dataclasses import dataclass, field

from diffguard.exceptions import GitError

_SUBPROCESS_TIMEOUT = 30

HUNK_HEADER_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


@dataclass
class DiffHunk:
    """A single hunk from a unified diff."""

    old_start: int
    old_count: int
    new_start: int
    new_count: int
    lines: list[tuple[str, str]] = field(default_factory=list)


@dataclass
class DiffFile:
    """A single file's changes from a git diff."""

    old_path: str
    new_path: str
    hunks: list[DiffHunk] = field(default_factory=list)
    is_new_file: bool = False
    is_deleted: bool = False
    is_renamed: bool = False
    is_binary: bool = False
    mode_changed: bool = False

    @property
    def path(self) -> str:
        """Primary file path (new_path for most cases, old_path for deletions)."""
        if self.is_deleted:
            return self.old_path
        return self.new_path


def is_git_repo() -> bool:
    """Check if current directory is inside a git repository.

    Returns:
        True if inside a git repository, False otherwise.
    """
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--is-inside-work-tree"],
            capture_output=True,
            text=True,
            check=False,
            timeout=_SUBPROCESS_TIMEOUT,
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def get_staged_diff() -> str:
    """Get the staged diff from git.

    Returns:
        Unified diff string of staged changes. Empty string if no staged changes.

    Raises:
        GitError: If git command fails or git is not installed.
    """
    try:
        result = subprocess.run(
            ["git", "diff", "--cached"],
            capture_output=True,
            text=True,
            check=False,
            timeout=_SUBPROCESS_TIMEOUT,
        )
    except FileNotFoundError as e:
        msg = "git is not installed or not in PATH"
        raise GitError(msg) from e
    except subprocess.TimeoutExpired as e:
        msg = "git diff --cached timed out"
        raise GitError(msg) from e

    if result.returncode != 0:
        msg = f"git diff --cached failed: {result.stderr.strip()}"
        raise GitError(msg)

    return result.stdout


def _parse_diff_git_header(line: str) -> tuple[str, str]:
    """Parse 'diff --git a/... b/...' to extract old and new paths.

    Uses ' b/' as the separator between old and new paths. Falls back to
    splitting on space if the expected format is not found.
    """
    rest = line[len("diff --git ") :]

    # Handle quoted paths (git C-style quoting for special chars)
    if rest.startswith('"'):
        old_path, remainder = _parse_c_quoted(rest)
        if old_path.startswith("a/"):
            old_path = old_path[2:]
        remainder = remainder.lstrip()
        if remainder.startswith('"'):
            new_path, _ = _parse_c_quoted(remainder)
        else:
            new_path = remainder
        if new_path.startswith("b/"):
            new_path = new_path[2:]
        return old_path, new_path

    # Unquoted: split on " b/"
    if rest.startswith("a/"):
        idx = rest.find(" b/")
        if idx != -1:
            return rest[2:idx], rest[idx + 3 :]

    return rest, rest


_C_ESCAPE_MAP: dict[str, str] = {
    "\\": "\\",
    '"': '"',
    "n": "\n",
    "t": "\t",
    "r": "\r",
    "a": "\a",
    "b": "\b",
    "f": "\f",
    "v": "\v",
}


def _parse_c_quoted(s: str) -> tuple[str, str]:
    """Parse a C-style quoted string, returning (unquoted_content, remainder).

    Handles standard C escape sequences (\\n, \\t, etc.) and octal escapes
    (\\NNN) as used by git's C-style path quoting.
    """
    if not s.startswith('"'):
        idx = s.find(" ")
        if idx == -1:
            return s, ""
        return s[:idx], s[idx + 1 :]

    i = 1
    result: list[str] = []
    while i < len(s):
        if s[i] == "\\" and i + 1 < len(s):
            next_ch = s[i + 1]
            if next_ch in _C_ESCAPE_MAP:
                result.append(_C_ESCAPE_MAP[next_ch])
                i += 2
            elif next_ch.isdigit():
                # Octal escape: up to 3 digits
                octal = next_ch
                for j in range(i + 2, min(i + 4, len(s))):
                    if s[j].isdigit() and int(s[j]) < 8:
                        octal += s[j]
                    else:
                        break
                result.append(chr(int(octal, 8)))
                i += 1 + len(octal)
            else:
                result.append(next_ch)
                i += 2
        elif s[i] == '"':
            return "".join(result), s[i + 1 :]
        else:
            result.append(s[i])
            i += 1

    return "".join(result), ""


def _extract_path(raw: str, prefix: str) -> str | None:
    """Extract file path from a --- or +++ line, stripping a/ or b/ prefix.

    Returns None for /dev/null.
    """
    if raw == "/dev/null":
        return None
    if raw.startswith('"'):
        unquoted, _ = _parse_c_quoted(raw)
        if unquoted.startswith(prefix):
            return unquoted[len(prefix) :]
        return unquoted
    if raw.startswith(prefix):
        return raw[len(prefix) :]
    return raw


def _parse_hunk_header(hunk_match: re.Match[str]) -> DiffHunk:
    """Create a DiffHunk from a hunk header regex match."""
    old_start = int(hunk_match.group(1))
    old_count = int(hunk_match.group(2)) if hunk_match.group(2) else 1
    new_start = int(hunk_match.group(3))
    new_count = int(hunk_match.group(4)) if hunk_match.group(4) else 1
    return DiffHunk(old_start=old_start, old_count=old_count, new_start=new_start, new_count=new_count)


def _apply_metadata_line(line: str, diff_file: DiffFile) -> None:
    """Apply a metadata line (file flags, paths) to a DiffFile."""
    if line.startswith("new file mode"):
        diff_file.is_new_file = True
    elif line.startswith("deleted file mode"):
        diff_file.is_deleted = True
    elif line.startswith("old mode ") or line.startswith("new mode "):
        diff_file.mode_changed = True
    elif line.startswith("rename from "):
        diff_file.old_path = line[len("rename from ") :]
        diff_file.is_renamed = True
    elif line.startswith("rename to "):
        diff_file.new_path = line[len("rename to ") :]
        diff_file.is_renamed = True
    elif line.startswith("Binary files"):
        diff_file.is_binary = True
    elif line.startswith("--- "):
        path = _extract_path(line[4:], "a/")
        if path is not None:
            diff_file.old_path = path
    elif line.startswith("+++ "):
        path = _extract_path(line[4:], "b/")
        if path is not None:
            diff_file.new_path = path


def parse_diff(diff_string: str) -> list[DiffFile]:
    """Parse a unified diff string into structured DiffFile objects.

    Args:
        diff_string: Unified diff output from git diff.

    Returns:
        List of DiffFile objects representing each changed file.
    """
    if not diff_string or not diff_string.strip():
        return []

    files: list[DiffFile] = []
    current_file: DiffFile | None = None
    current_hunk: DiffHunk | None = None

    for line in diff_string.split("\n"):
        # New file diff header — highest priority
        if line.startswith("diff --git "):
            if current_file is not None:
                files.append(current_file)
            old_path, new_path = _parse_diff_git_header(line)
            current_file = DiffFile(old_path=old_path, new_path=new_path)
            current_hunk = None
            continue

        if current_file is None:
            continue

        # Inside a hunk: consume diff lines before checking metadata
        if current_hunk is not None and line and line[0] in (" ", "+", "-"):
            current_hunk.lines.append((line[0], line[1:]))
            continue

        # No-newline marker
        if line.startswith("\\"):
            continue

        # Hunk header
        hunk_match = HUNK_HEADER_RE.match(line)
        if hunk_match:
            current_hunk = _parse_hunk_header(hunk_match)
            current_file.hunks.append(current_hunk)
            continue

        # Metadata lines (file flags, paths, binary markers)
        _apply_metadata_line(line, current_file)

    if current_file is not None:
        files.append(current_file)

    return files
