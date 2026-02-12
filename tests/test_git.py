"""Tests for git diff parsing and extraction."""

from unittest.mock import MagicMock, patch

import pytest

from diffguard.exceptions import GitError
from diffguard.git import DiffFile, DiffHunk, get_staged_diff, is_git_repo, parse_diff

# === Test fixtures (inline as specified by TASKS.md) ===

SAMPLE_SINGLE_FILE_DIFF = """\
diff --git a/src/main.py b/src/main.py
index abc123..def456 100644
--- a/src/main.py
+++ b/src/main.py
@@ -10,5 +10,7 @@ def hello():
     print("hello")
+    print("world")
"""

SAMPLE_NEW_FILE_DIFF = """\
diff --git a/src/new.py b/src/new.py
new file mode 100644
index 0000000..abc123
--- /dev/null
+++ b/src/new.py
@@ -0,0 +1,5 @@
+def new_function():
+    pass
"""

SAMPLE_DELETED_FILE_DIFF = """\
diff --git a/src/old.py b/src/old.py
deleted file mode 100644
index abc123..0000000
--- a/src/old.py
+++ /dev/null
@@ -1,5 +0,0 @@
-def old_function():
-    pass
"""

SAMPLE_RENAMED_FILE_DIFF = """\
diff --git a/old_name.py b/new_name.py
similarity index 100%
rename from old_name.py
rename to new_name.py
"""

SAMPLE_BINARY_FILE_DIFF = """\
diff --git a/image.png b/image.png
new file mode 100644
Binary files /dev/null and b/image.png differ
"""

SAMPLE_MULTI_FILE_DIFF = """\
diff --git a/src/a.py b/src/a.py
index abc123..def456 100644
--- a/src/a.py
+++ b/src/a.py
@@ -1,3 +1,4 @@
 import os
+import sys

 def main():
diff --git a/src/b.py b/src/b.py
index 111111..222222 100644
--- a/src/b.py
+++ b/src/b.py
@@ -5,3 +5,4 @@ def foo():
     pass
+    return True
diff --git a/src/c.py b/src/c.py
new file mode 100644
index 0000000..333333
--- /dev/null
+++ b/src/c.py
@@ -0,0 +1,2 @@
+def bar():
+    pass
"""

SAMPLE_RENAMED_WITH_CHANGES_DIFF = """\
diff --git a/old_name.py b/new_name.py
similarity index 80%
rename from old_name.py
rename to new_name.py
--- a/old_name.py
+++ b/new_name.py
@@ -1,3 +1,4 @@
 def hello():
-    print("old")
+    print("new")
+    print("extra")
"""

SAMPLE_MULTIPLE_HUNKS_DIFF = """\
diff --git a/src/app.py b/src/app.py
index abc123..def456 100644
--- a/src/app.py
+++ b/src/app.py
@@ -5,3 +5,4 @@ def func_a():
     pass
+    return 1
@@ -20,4 +21,5 @@ def func_b():
     x = 1
+    y = 2
     return x
@@ -50,2 +52,3 @@ def func_c():
     pass
+    return None
"""

SAMPLE_MODE_CHANGE_DIFF = """\
diff --git a/script.sh b/script.sh
old mode 100644
new mode 100755
"""

SAMPLE_MIXED_BINARY_TEXT_DIFF = """\
diff --git a/src/main.py b/src/main.py
index abc123..def456 100644
--- a/src/main.py
+++ b/src/main.py
@@ -1,2 +1,3 @@
 import os
+import sys
diff --git a/logo.png b/logo.png
new file mode 100644
Binary files /dev/null and b/logo.png differ
diff --git a/README.md b/README.md
index 111111..222222 100644
--- a/README.md
+++ b/README.md
@@ -1,1 +1,2 @@
 # Project
+New line
"""

SAMPLE_SINGLE_LINE_HUNK_DIFF = """\
diff --git a/src/main.py b/src/main.py
index abc123..def456 100644
--- a/src/main.py
+++ b/src/main.py
@@ -10 +12 @@ def hello():
-    old_line
+    new_line
"""

SAMPLE_HUNK_WITH_CONTEXT_TEXT_DIFF = """\
diff --git a/src/main.py b/src/main.py
index abc123..def456 100644
--- a/src/main.py
+++ b/src/main.py
@@ -10,5 +12,7 @@ def my_function():
     print("hello")
+    print("world")
"""

SAMPLE_SPACE_IN_PATH_DIFF = """\
diff --git a/src/my file.py b/src/my file.py
index abc123..def456 100644
--- a/src/my file.py
+++ b/src/my file.py
@@ -1,2 +1,3 @@
 x = 1
+y = 2
"""

SAMPLE_UNICODE_PATH_DIFF = """\
diff --git a/src/caf\u00e9.py b/src/caf\u00e9.py
index abc123..def456 100644
--- a/src/caf\u00e9.py
+++ b/src/caf\u00e9.py
@@ -1,2 +1,3 @@
 x = 1
+y = 2
"""


# === Tests ===


class TestParseSingleFileDiff:
    """Parse single-file diff."""

    def test_single_file_returns_one_diff_file(self) -> None:
        result = parse_diff(SAMPLE_SINGLE_FILE_DIFF)
        assert len(result) == 1

    def test_single_file_has_correct_path(self) -> None:
        result = parse_diff(SAMPLE_SINGLE_FILE_DIFF)
        assert result[0].path == "src/main.py"

    def test_single_file_has_hunks(self) -> None:
        result = parse_diff(SAMPLE_SINGLE_FILE_DIFF)
        assert len(result[0].hunks) == 1


class TestParseMultiFileDiff:
    """Parse multi-file diff."""

    def test_multi_file_returns_correct_count(self) -> None:
        result = parse_diff(SAMPLE_MULTI_FILE_DIFF)
        assert len(result) == 3

    def test_multi_file_has_correct_paths(self) -> None:
        result = parse_diff(SAMPLE_MULTI_FILE_DIFF)
        paths = [f.path for f in result]
        assert paths == ["src/a.py", "src/b.py", "src/c.py"]


class TestDetectNewFile:
    """Detect new file."""

    def test_new_file_flag_is_set(self) -> None:
        result = parse_diff(SAMPLE_NEW_FILE_DIFF)
        assert len(result) == 1
        assert result[0].is_new_file is True

    def test_new_file_has_correct_path(self) -> None:
        result = parse_diff(SAMPLE_NEW_FILE_DIFF)
        assert result[0].path == "src/new.py"

    def test_new_file_has_hunks(self) -> None:
        result = parse_diff(SAMPLE_NEW_FILE_DIFF)
        assert len(result[0].hunks) == 1


class TestDetectDeletedFile:
    """Detect deleted file."""

    def test_deleted_file_flag_is_set(self) -> None:
        result = parse_diff(SAMPLE_DELETED_FILE_DIFF)
        assert len(result) == 1
        assert result[0].is_deleted is True

    def test_deleted_file_has_correct_path(self) -> None:
        result = parse_diff(SAMPLE_DELETED_FILE_DIFF)
        assert result[0].path == "src/old.py"

    def test_deleted_file_has_hunks(self) -> None:
        result = parse_diff(SAMPLE_DELETED_FILE_DIFF)
        assert len(result[0].hunks) == 1


class TestDetectRenamedFile:
    """Detect renamed file."""

    def test_renamed_file_flag_is_set(self) -> None:
        result = parse_diff(SAMPLE_RENAMED_FILE_DIFF)
        assert len(result) == 1
        assert result[0].is_renamed is True

    def test_renamed_file_has_correct_old_path(self) -> None:
        result = parse_diff(SAMPLE_RENAMED_FILE_DIFF)
        assert result[0].old_path == "old_name.py"

    def test_renamed_file_has_correct_new_path(self) -> None:
        result = parse_diff(SAMPLE_RENAMED_FILE_DIFF)
        assert result[0].new_path == "new_name.py"

    def test_renamed_file_without_changes_has_no_hunks(self) -> None:
        result = parse_diff(SAMPLE_RENAMED_FILE_DIFF)
        assert len(result[0].hunks) == 0


class TestDetectRenamedFileWithChanges:
    """Detect renamed file with changes."""

    def test_renamed_with_changes_flag_is_set(self) -> None:
        result = parse_diff(SAMPLE_RENAMED_WITH_CHANGES_DIFF)
        assert result[0].is_renamed is True

    def test_renamed_with_changes_has_hunks(self) -> None:
        result = parse_diff(SAMPLE_RENAMED_WITH_CHANGES_DIFF)
        assert len(result[0].hunks) > 0

    def test_renamed_with_changes_has_correct_paths(self) -> None:
        result = parse_diff(SAMPLE_RENAMED_WITH_CHANGES_DIFF)
        assert result[0].old_path == "old_name.py"
        assert result[0].new_path == "new_name.py"


class TestParseHunkHeaderStandard:
    """Parse hunk headers - standard format."""

    def test_standard_hunk_header_values(self) -> None:
        result = parse_diff(SAMPLE_HUNK_WITH_CONTEXT_TEXT_DIFF)
        hunk = result[0].hunks[0]
        assert hunk.old_start == 10
        assert hunk.old_count == 5
        assert hunk.new_start == 12
        assert hunk.new_count == 7


class TestParseHunkHeaderSingleLine:
    """Parse hunk headers - single line (no count)."""

    def test_single_line_hunk_header_defaults_count_to_one(self) -> None:
        result = parse_diff(SAMPLE_SINGLE_LINE_HUNK_DIFF)
        hunk = result[0].hunks[0]
        assert hunk.old_start == 10
        assert hunk.old_count == 1
        assert hunk.new_start == 12
        assert hunk.new_count == 1


class TestParseHunkHeaderWithContext:
    """Parse hunk headers - with context text."""

    def test_hunk_header_with_context_text_parses_correctly(self) -> None:
        result = parse_diff(SAMPLE_HUNK_WITH_CONTEXT_TEXT_DIFF)
        hunk = result[0].hunks[0]
        assert hunk.old_start == 10
        assert hunk.new_start == 12


class TestParseMultipleHunks:
    """Parse multiple hunks in single file."""

    def test_multiple_hunks_count(self) -> None:
        result = parse_diff(SAMPLE_MULTIPLE_HUNKS_DIFF)
        assert len(result) == 1
        assert len(result[0].hunks) == 3

    def test_multiple_hunks_have_correct_ranges(self) -> None:
        result = parse_diff(SAMPLE_MULTIPLE_HUNKS_DIFF)
        hunks = result[0].hunks
        assert hunks[0].old_start == 5
        assert hunks[1].old_start == 20
        assert hunks[2].old_start == 50


class TestBinaryFile:
    """Handle binary files - skip gracefully."""

    def test_binary_file_flag_is_set(self) -> None:
        result = parse_diff(SAMPLE_BINARY_FILE_DIFF)
        assert len(result) == 1
        assert result[0].is_binary is True

    def test_binary_file_has_empty_hunks(self) -> None:
        result = parse_diff(SAMPLE_BINARY_FILE_DIFF)
        assert len(result[0].hunks) == 0


class TestMixedBinaryTextFiles:
    """Handle mixed binary and text files."""

    def test_mixed_returns_correct_count(self) -> None:
        result = parse_diff(SAMPLE_MIXED_BINARY_TEXT_DIFF)
        assert len(result) == 3

    def test_mixed_binary_file_marked_correctly(self) -> None:
        result = parse_diff(SAMPLE_MIXED_BINARY_TEXT_DIFF)
        binary_files = [f for f in result if f.is_binary]
        text_files = [f for f in result if not f.is_binary]
        assert len(binary_files) == 1
        assert len(text_files) == 2

    def test_mixed_binary_file_has_correct_path(self) -> None:
        result = parse_diff(SAMPLE_MIXED_BINARY_TEXT_DIFF)
        binary_file = next(f for f in result if f.is_binary)
        assert binary_file.path == "logo.png"


class TestEmptyDiff:
    """Empty diff returns empty list."""

    def test_empty_string_returns_empty_list(self) -> None:
        assert parse_diff("") == []

    def test_none_like_empty_returns_empty_list(self) -> None:
        assert parse_diff("") == []


class TestWhitespaceOnlyDiff:
    """Whitespace-only diff returns empty list."""

    def test_spaces_only(self) -> None:
        assert parse_diff("   ") == []

    def test_tabs_only(self) -> None:
        assert parse_diff("\t\t") == []

    def test_newlines_only(self) -> None:
        assert parse_diff("\n\n\n") == []

    def test_mixed_whitespace(self) -> None:
        assert parse_diff("  \t\n  \n\t  ") == []


class TestModeChangeOnly:
    """File mode change only (no content)."""

    def test_mode_changed_flag_is_set(self) -> None:
        result = parse_diff(SAMPLE_MODE_CHANGE_DIFF)
        assert len(result) == 1
        assert result[0].mode_changed is True

    def test_mode_change_has_empty_hunks(self) -> None:
        result = parse_diff(SAMPLE_MODE_CHANGE_DIFF)
        assert len(result[0].hunks) == 0


class TestParseDiffLines:
    """Parse diff lines correctly."""

    def test_added_lines_have_plus_type(self) -> None:
        result = parse_diff(SAMPLE_SINGLE_FILE_DIFF)
        hunk = result[0].hunks[0]
        added = [(t, c) for t, c in hunk.lines if t == "+"]
        assert len(added) > 0

    def test_context_lines_have_space_type(self) -> None:
        result = parse_diff(SAMPLE_SINGLE_FILE_DIFF)
        hunk = result[0].hunks[0]
        context = [(t, c) for t, c in hunk.lines if t == " "]
        assert len(context) > 0

    def test_removed_lines_have_minus_type(self) -> None:
        result = parse_diff(SAMPLE_DELETED_FILE_DIFF)
        hunk = result[0].hunks[0]
        removed = [(t, c) for t, c in hunk.lines if t == "-"]
        assert len(removed) > 0

    def test_lines_preserve_order(self) -> None:
        result = parse_diff(SAMPLE_RENAMED_WITH_CHANGES_DIFF)
        hunk = result[0].hunks[0]
        types = [t for t, _ in hunk.lines]
        assert types == [" ", "-", "+", "+"]

    def test_lines_preserve_content(self) -> None:
        result = parse_diff(SAMPLE_RENAMED_WITH_CHANGES_DIFF)
        hunk = result[0].hunks[0]
        contents = [c for _, c in hunk.lines]
        assert "def hello():" in contents[0]


class TestFilePathsWithSpaces:
    """Handle file paths with spaces."""

    def test_path_with_space_parsed_correctly(self) -> None:
        result = parse_diff(SAMPLE_SPACE_IN_PATH_DIFF)
        assert len(result) == 1
        assert result[0].path == "src/my file.py"


class TestFilePathsWithSpecialChars:
    """Handle file paths with special characters."""

    def test_unicode_path_parsed_correctly(self) -> None:
        result = parse_diff(SAMPLE_UNICODE_PATH_DIFF)
        assert len(result) == 1
        assert result[0].path == "src/caf\u00e9.py"


class TestIsGitRepo:
    """is_git_repo."""

    @patch("diffguard.git.subprocess.run")
    def test_returns_true_for_valid_repo(self, mock_run: MagicMock) -> None:
        """is_git_repo returns True for valid repo."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "true\n"
        mock_run.return_value = mock_result

        assert is_git_repo() is True

    @patch("diffguard.git.subprocess.run")
    def test_returns_false_for_non_repo(self, mock_run: MagicMock) -> None:
        """is_git_repo returns False for non-repo."""
        mock_result = MagicMock()
        mock_result.returncode = 128
        mock_result.stderr = "fatal: not a git repository\n"
        mock_run.return_value = mock_result

        assert is_git_repo() is False

    @patch("diffguard.git.subprocess.run", side_effect=FileNotFoundError)
    def test_returns_false_when_git_not_installed(self, _mock_run: MagicMock) -> None:
        assert is_git_repo() is False


class TestGetStagedDiff:
    """get_staged_diff."""

    @patch("diffguard.git.subprocess.run")
    def test_returns_diff_string(self, mock_run: MagicMock) -> None:
        """get_staged_diff returns diff string."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = SAMPLE_SINGLE_FILE_DIFF
        mock_run.return_value = mock_result

        result = get_staged_diff()
        assert result == SAMPLE_SINGLE_FILE_DIFF

    @patch("diffguard.git.subprocess.run")
    def test_returns_empty_for_no_staged_changes(self, mock_run: MagicMock) -> None:
        """get_staged_diff returns empty for no staged changes."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = ""
        mock_run.return_value = mock_result

        result = get_staged_diff()
        assert result == ""

    @patch("diffguard.git.subprocess.run", side_effect=FileNotFoundError)
    def test_raises_git_error_when_git_not_installed(self, _mock_run: MagicMock) -> None:
        with pytest.raises(GitError, match="git is not installed"):
            get_staged_diff()

    @patch("diffguard.git.subprocess.run")
    def test_raises_git_error_on_failure(self, mock_run: MagicMock) -> None:
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stderr = "some error"
        mock_run.return_value = mock_result

        with pytest.raises(GitError, match="git diff --cached failed"):
            get_staged_diff()


class TestDiffFileDataclass:
    """Test DiffFile dataclass behavior."""

    def test_path_property_returns_new_path_by_default(self) -> None:
        f = DiffFile(old_path="a.py", new_path="b.py")
        assert f.path == "b.py"

    def test_path_property_returns_old_path_for_deleted(self) -> None:
        f = DiffFile(old_path="a.py", new_path="a.py", is_deleted=True)
        assert f.path == "a.py"

    def test_default_flags_are_false(self) -> None:
        f = DiffFile(old_path="a.py", new_path="a.py")
        assert f.is_new_file is False
        assert f.is_deleted is False
        assert f.is_renamed is False
        assert f.is_binary is False
        assert f.mode_changed is False

    def test_default_hunks_is_empty(self) -> None:
        f = DiffFile(old_path="a.py", new_path="a.py")
        assert f.hunks == []


class TestDiffHunkDataclass:
    """Test DiffHunk dataclass behavior."""

    def test_default_lines_is_empty(self) -> None:
        h = DiffHunk(old_start=1, old_count=1, new_start=1, new_count=1)
        assert h.lines == []

    def test_lines_are_mutable(self) -> None:
        h = DiffHunk(old_start=1, old_count=1, new_start=1, new_count=1)
        h.lines.append(("+", "new line"))
        assert len(h.lines) == 1
