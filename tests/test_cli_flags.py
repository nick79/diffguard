"""Tests for CLI flags: --verbose, --dry-run, --json, --output, and combinations."""

import json
import os
from pathlib import Path  # noqa: TC003 — used at runtime by tmp_path fixture type hints
from unittest.mock import AsyncMock, MagicMock, patch

from typer.testing import CliRunner

from diffguard.ast.languages import Language
from diffguard.cli import app
from diffguard.config import DiffguardConfig
from diffguard.context import Region
from diffguard.git import DiffFile, DiffHunk
from diffguard.llm import AnalysisResult, CodeContext, ConfidenceLevel, DiffLine, Finding, SeverityLevel
from diffguard.llm.prompts import ScopeContext
from diffguard.pipeline import FileContext, PreparedContext

runner = CliRunner()

_DIFF_TEXT = "diff --git a/test.py b/test.py\n"


def _make_diff_file(path: str = "test.py") -> DiffFile:
    return DiffFile(
        old_path=path,
        new_path=path,
        hunks=[
            DiffHunk(
                old_start=1,
                old_count=3,
                new_start=1,
                new_count=3,
                lines=[("+", "print('hello')")],
            )
        ],
    )


def _make_finding(severity: SeverityLevel = SeverityLevel.HIGH) -> Finding:
    return Finding(
        what="SQL Injection",
        why="User input in query",
        how_to_fix="Use parameterized queries",
        severity=severity,
        confidence=ConfidenceLevel.HIGH,
        cwe_id="CWE-89",
        file_path="test.py",
        line_range=(1, 3),
    )


def _make_prepared() -> PreparedContext:
    fc = FileContext(
        file_path="test.py",
        language=Language.PYTHON,
        source_lines=["print('hello')", "x = 1", "y = 2"],
        regions=[Region(start_line=1, end_line=3)],
        diff_lines=[DiffLine(line_num=1, change_type="+", content="print('hello')")],
        scopes=[ScopeContext(type="function", name="main", start_line=1, end_line=3, source="def main(): ...")],
    )
    cc = CodeContext(
        file_path="test.py",
        diff_lines=[DiffLine(line_num=1, change_type="+", content="print('hello')")],
        expanded_region="print('hello')\nx = 1\ny = 2",
        region_start_line=1,
        scopes=[ScopeContext(type="function", name="main", start_line=1, end_line=3, source="def main(): ...")],
    )
    return PreparedContext(file_contexts=[fc], code_contexts=[cc])


# ---------------------------------------------------------------------------
# Common patch targets
# ---------------------------------------------------------------------------
_GIT = "diffguard.cli.is_git_repo"
_CONFIG = "diffguard.cli.load_config"
_DIFF = "diffguard.cli.get_staged_diff"
_PARSE = "diffguard.cli.parse_diff"
_ANALYZE = "diffguard.cli.analyze_staged_changes"
_PREPARE = "diffguard.cli.prepare_file_contexts"
_ANALYZE_FILES = "diffguard.cli.analyze_files"
_CLIENT = "diffguard.cli.OpenAIClient"
_COMMIT = "diffguard.cli.get_commit_hash"
_BRANCH = "diffguard.cli.get_branch_name"
_ENV = {"OPENAI_API_KEY": "test-key"}


class TestVerboseFlag:
    @patch(_BRANCH, return_value="main")
    @patch(_COMMIT, return_value="abc123")
    @patch(_ANALYZE_FILES, new_callable=AsyncMock)
    @patch(_PREPARE)
    @patch(_CLIENT)
    @patch(_PARSE)
    @patch(_DIFF, return_value=_DIFF_TEXT)
    @patch(_CONFIG, return_value=DiffguardConfig())
    @patch(_GIT, return_value=True)
    @patch.dict(os.environ, _ENV)
    def test_shows_elapsed_time(
        self,
        _git: MagicMock,
        _cfg: MagicMock,
        _diff: MagicMock,
        mock_parse: MagicMock,
        _client: MagicMock,
        mock_prepare: MagicMock,
        mock_af: AsyncMock,
        _commit: MagicMock,
        _branch: MagicMock,
    ) -> None:
        mock_parse.return_value = [_make_diff_file()]
        mock_prepare.return_value = _make_prepared()
        mock_af.return_value = AnalysisResult()

        result = runner.invoke(app, ["--verbose"])

        assert result.exit_code == 0
        assert "completed in" in result.output.lower()

    @patch(_BRANCH, return_value="main")
    @patch(_COMMIT, return_value="abc123")
    @patch(_ANALYZE_FILES, new_callable=AsyncMock)
    @patch(_PREPARE)
    @patch(_CLIENT)
    @patch(_PARSE)
    @patch(_DIFF, return_value=_DIFF_TEXT)
    @patch(_CONFIG, return_value=DiffguardConfig())
    @patch(_GIT, return_value=True)
    @patch.dict(os.environ, _ENV)
    def test_shows_file_count(
        self,
        _git: MagicMock,
        _cfg: MagicMock,
        _diff: MagicMock,
        mock_parse: MagicMock,
        _client: MagicMock,
        mock_prepare: MagicMock,
        mock_af: AsyncMock,
        _commit: MagicMock,
        _branch: MagicMock,
    ) -> None:
        mock_parse.return_value = [_make_diff_file()]
        mock_prepare.return_value = _make_prepared()
        mock_af.return_value = AnalysisResult()

        result = runner.invoke(app, ["--verbose"])

        assert result.exit_code == 0
        assert "1 file(s)" in result.output

    @patch(_BRANCH, return_value="main")
    @patch(_COMMIT, return_value="abc123")
    @patch(_ANALYZE_FILES, new_callable=AsyncMock)
    @patch(_PREPARE)
    @patch(_CLIENT)
    @patch(_PARSE)
    @patch(_DIFF, return_value=_DIFF_TEXT)
    @patch(_CONFIG, return_value=DiffguardConfig())
    @patch(_GIT, return_value=True)
    @patch.dict(os.environ, _ENV)
    def test_shows_per_file_details(
        self,
        _git: MagicMock,
        _cfg: MagicMock,
        _diff: MagicMock,
        mock_parse: MagicMock,
        _client: MagicMock,
        mock_prepare: MagicMock,
        mock_af: AsyncMock,
        _commit: MagicMock,
        _branch: MagicMock,
    ) -> None:
        mock_parse.return_value = [_make_diff_file()]
        mock_prepare.return_value = _make_prepared()
        mock_af.return_value = AnalysisResult()

        result = runner.invoke(app, ["--verbose"])

        assert result.exit_code == 0
        assert "region lines" in result.output
        assert "scope(s)" in result.output

    @patch(_BRANCH, return_value="main")
    @patch(_COMMIT, return_value="abc123")
    @patch(_ANALYZE_FILES, new_callable=AsyncMock)
    @patch(_PREPARE)
    @patch(_CLIENT)
    @patch(_PARSE)
    @patch(_DIFF, return_value=_DIFF_TEXT)
    @patch(_CONFIG, return_value=DiffguardConfig())
    @patch(_GIT, return_value=True)
    @patch.dict(os.environ, _ENV)
    def test_shows_token_estimates(
        self,
        _git: MagicMock,
        _cfg: MagicMock,
        _diff: MagicMock,
        mock_parse: MagicMock,
        _client: MagicMock,
        mock_prepare: MagicMock,
        mock_af: AsyncMock,
        _commit: MagicMock,
        _branch: MagicMock,
    ) -> None:
        mock_parse.return_value = [_make_diff_file()]
        mock_prepare.return_value = _make_prepared()
        mock_af.return_value = AnalysisResult()

        result = runner.invoke(app, ["--verbose"])

        assert result.exit_code == 0
        assert "tokens" in result.output

    @patch(_BRANCH, return_value="main")
    @patch(_COMMIT, return_value="abc123")
    @patch(_ANALYZE_FILES, new_callable=AsyncMock)
    @patch(_PREPARE)
    @patch(_CLIENT)
    @patch(_PARSE)
    @patch(_DIFF, return_value=_DIFF_TEXT)
    @patch(_CONFIG, return_value=DiffguardConfig())
    @patch(_GIT, return_value=True)
    @patch.dict(os.environ, _ENV)
    def test_short_flag_v(
        self,
        _git: MagicMock,
        _cfg: MagicMock,
        _diff: MagicMock,
        mock_parse: MagicMock,
        _client: MagicMock,
        mock_prepare: MagicMock,
        mock_af: AsyncMock,
        _commit: MagicMock,
        _branch: MagicMock,
    ) -> None:
        mock_parse.return_value = [_make_diff_file()]
        mock_prepare.return_value = _make_prepared()
        mock_af.return_value = AnalysisResult()

        result = runner.invoke(app, ["-v"])

        assert result.exit_code == 0
        assert "completed in" in result.output.lower()


class TestDryRunEnhanced:
    @patch(_PREPARE)
    @patch(_PARSE)
    @patch(_DIFF, return_value=_DIFF_TEXT)
    @patch(_CONFIG, return_value=DiffguardConfig())
    @patch(_GIT, return_value=True)
    @patch.dict(os.environ, {}, clear=True)
    def test_lists_files_to_analyze(
        self,
        _git: MagicMock,
        _cfg: MagicMock,
        _diff: MagicMock,
        mock_parse: MagicMock,
        mock_prepare: MagicMock,
    ) -> None:
        mock_parse.return_value = [_make_diff_file()]
        mock_prepare.return_value = _make_prepared()

        result = runner.invoke(app, ["--dry-run"])

        assert result.exit_code == 0
        assert "test.py" in result.output

    @patch(_PREPARE)
    @patch(_PARSE)
    @patch(_DIFF, return_value=_DIFF_TEXT)
    @patch(_CONFIG, return_value=DiffguardConfig())
    @patch(_GIT, return_value=True)
    @patch.dict(os.environ, {}, clear=True)
    def test_shows_token_estimates(
        self,
        _git: MagicMock,
        _cfg: MagicMock,
        _diff: MagicMock,
        mock_parse: MagicMock,
        mock_prepare: MagicMock,
    ) -> None:
        mock_parse.return_value = [_make_diff_file()]
        mock_prepare.return_value = _make_prepared()

        result = runner.invoke(app, ["--dry-run"])

        assert result.exit_code == 0
        assert "tokens" in result.output

    @patch(_PREPARE)
    @patch(_PARSE)
    @patch(_DIFF, return_value=_DIFF_TEXT)
    @patch(_CONFIG, return_value=DiffguardConfig())
    @patch(_GIT, return_value=True)
    @patch.dict(os.environ, {}, clear=True)
    def test_does_not_call_llm(
        self,
        _git: MagicMock,
        _cfg: MagicMock,
        _diff: MagicMock,
        mock_parse: MagicMock,
        mock_prepare: MagicMock,
    ) -> None:
        mock_parse.return_value = [_make_diff_file()]
        mock_prepare.return_value = _make_prepared()

        with patch(_ANALYZE, new_callable=AsyncMock) as mock_analyze:
            result = runner.invoke(app, ["--dry-run"])

            assert result.exit_code == 0
            mock_analyze.assert_not_awaited()

    @patch(_PREPARE)
    @patch(_PARSE)
    @patch(_DIFF, return_value=_DIFF_TEXT)
    @patch(_CONFIG, return_value=DiffguardConfig())
    @patch(_GIT, return_value=True)
    @patch.dict(os.environ, {}, clear=True)
    def test_shows_total_tokens(
        self,
        _git: MagicMock,
        _cfg: MagicMock,
        _diff: MagicMock,
        mock_parse: MagicMock,
        mock_prepare: MagicMock,
    ) -> None:
        mock_parse.return_value = [_make_diff_file()]
        mock_prepare.return_value = _make_prepared()

        result = runner.invoke(app, ["--dry-run"])

        assert result.exit_code == 0
        assert "Total estimated tokens" in result.output

    @patch(_PREPARE)
    @patch(_PARSE)
    @patch(_DIFF, return_value=_DIFF_TEXT)
    @patch(_CONFIG, return_value=DiffguardConfig())
    @patch(_GIT, return_value=True)
    @patch.dict(os.environ, {}, clear=True)
    def test_exits_with_zero(
        self,
        _git: MagicMock,
        _cfg: MagicMock,
        _diff: MagicMock,
        mock_parse: MagicMock,
        mock_prepare: MagicMock,
    ) -> None:
        mock_parse.return_value = [_make_diff_file()]
        mock_prepare.return_value = _make_prepared()

        result = runner.invoke(app, ["--dry-run"])

        assert result.exit_code == 0


class TestJsonFlag:
    @patch(_BRANCH, return_value="main")
    @patch(_COMMIT, return_value="abc123")
    @patch(_ANALYZE, new_callable=AsyncMock)
    @patch(_CLIENT)
    @patch(_PARSE)
    @patch(_DIFF, return_value=_DIFF_TEXT)
    @patch(_CONFIG, return_value=DiffguardConfig())
    @patch(_GIT, return_value=True)
    @patch.dict(os.environ, _ENV)
    def test_outputs_valid_json(
        self,
        _git: MagicMock,
        _cfg: MagicMock,
        _diff: MagicMock,
        mock_parse: MagicMock,
        _client: MagicMock,
        mock_analyze: AsyncMock,
        _commit: MagicMock,
        _branch: MagicMock,
    ) -> None:
        mock_parse.return_value = [_make_diff_file()]
        mock_analyze.return_value = AnalysisResult(findings=[_make_finding(SeverityLevel.LOW)])

        result = runner.invoke(app, ["--json"])

        data = json.loads(result.output)
        assert "findings" in data
        assert "schema_version" in data
        assert "version" in data
        assert "timestamp" in data
        assert "metadata" in data
        assert "summary" in data
        assert len(data["findings"]) == 1
        assert data["findings"][0]["what"] == "SQL Injection"

    @patch(_BRANCH, return_value="main")
    @patch(_COMMIT, return_value="abc123")
    @patch(_ANALYZE, new_callable=AsyncMock)
    @patch(_CLIENT)
    @patch(_PARSE)
    @patch(_DIFF, return_value=_DIFF_TEXT)
    @patch(_CONFIG, return_value=DiffguardConfig())
    @patch(_GIT, return_value=True)
    @patch.dict(os.environ, _ENV)
    def test_no_extra_text(
        self,
        _git: MagicMock,
        _cfg: MagicMock,
        _diff: MagicMock,
        mock_parse: MagicMock,
        _client: MagicMock,
        mock_analyze: AsyncMock,
        _commit: MagicMock,
        _branch: MagicMock,
    ) -> None:
        mock_parse.return_value = [_make_diff_file()]
        mock_analyze.return_value = AnalysisResult()

        result = runner.invoke(app, ["--json"])

        stripped = result.output.strip()
        assert stripped.startswith("{")
        assert stripped.endswith("}")

    @patch(_BRANCH, return_value="main")
    @patch(_COMMIT, return_value="abc123")
    @patch(_ANALYZE, new_callable=AsyncMock)
    @patch(_CLIENT)
    @patch(_PARSE)
    @patch(_DIFF, return_value=_DIFF_TEXT)
    @patch(_CONFIG, return_value=DiffguardConfig())
    @patch(_GIT, return_value=True)
    @patch.dict(os.environ, _ENV)
    def test_no_findings_empty_array(
        self,
        _git: MagicMock,
        _cfg: MagicMock,
        _diff: MagicMock,
        mock_parse: MagicMock,
        _client: MagicMock,
        mock_analyze: AsyncMock,
        _commit: MagicMock,
        _branch: MagicMock,
    ) -> None:
        mock_parse.return_value = [_make_diff_file()]
        mock_analyze.return_value = AnalysisResult()

        result = runner.invoke(app, ["--json"])

        data = json.loads(result.output)
        assert data["findings"] == []
        assert data["summary"]["total"] == 0
        assert result.exit_code == 0

    @patch(_BRANCH, return_value="main")
    @patch(_COMMIT, return_value="abc123")
    @patch(_ANALYZE, new_callable=AsyncMock)
    @patch(_CLIENT)
    @patch(_PARSE)
    @patch(_DIFF, return_value=_DIFF_TEXT)
    @patch(_CONFIG, return_value=DiffguardConfig())
    @patch(_GIT, return_value=True)
    @patch.dict(os.environ, _ENV)
    def test_critical_finding_exit_code(
        self,
        _git: MagicMock,
        _cfg: MagicMock,
        _diff: MagicMock,
        mock_parse: MagicMock,
        _client: MagicMock,
        mock_analyze: AsyncMock,
        _commit: MagicMock,
        _branch: MagicMock,
    ) -> None:
        mock_parse.return_value = [_make_diff_file()]
        mock_analyze.return_value = AnalysisResult(findings=[_make_finding(SeverityLevel.CRITICAL)])

        result = runner.invoke(app, ["--json"])

        assert result.exit_code == 1
        data = json.loads(result.output)
        assert data["findings"][0]["severity"] == "Critical"


class TestOutputFlag:
    @patch(_BRANCH, return_value="main")
    @patch(_COMMIT, return_value="abc123")
    @patch(_ANALYZE, new_callable=AsyncMock)
    @patch(_CLIENT)
    @patch(_PARSE)
    @patch(_DIFF, return_value=_DIFF_TEXT)
    @patch(_CONFIG, return_value=DiffguardConfig())
    @patch(_GIT, return_value=True)
    @patch.dict(os.environ, _ENV)
    def test_creates_report_file(
        self,
        _git: MagicMock,
        _cfg: MagicMock,
        _diff: MagicMock,
        mock_parse: MagicMock,
        _client: MagicMock,
        mock_analyze: AsyncMock,
        _commit: MagicMock,
        _branch: MagicMock,
        tmp_path: Path,
    ) -> None:
        mock_parse.return_value = [_make_diff_file()]
        mock_analyze.return_value = AnalysisResult(findings=[_make_finding(SeverityLevel.LOW)])
        out_file = tmp_path / "report.json"

        result = runner.invoke(app, ["--output", str(out_file)])

        assert result.exit_code == 0
        assert out_file.exists()

    @patch(_BRANCH, return_value="main")
    @patch(_COMMIT, return_value="abc123")
    @patch(_ANALYZE, new_callable=AsyncMock)
    @patch(_CLIENT)
    @patch(_PARSE)
    @patch(_DIFF, return_value=_DIFF_TEXT)
    @patch(_CONFIG, return_value=DiffguardConfig())
    @patch(_GIT, return_value=True)
    @patch.dict(os.environ, _ENV)
    def test_valid_json_in_file(
        self,
        _git: MagicMock,
        _cfg: MagicMock,
        _diff: MagicMock,
        mock_parse: MagicMock,
        _client: MagicMock,
        mock_analyze: AsyncMock,
        _commit: MagicMock,
        _branch: MagicMock,
        tmp_path: Path,
    ) -> None:
        mock_parse.return_value = [_make_diff_file()]
        mock_analyze.return_value = AnalysisResult(findings=[_make_finding(SeverityLevel.LOW)])
        out_file = tmp_path / "report.json"

        runner.invoke(app, ["--output", str(out_file)])

        data = json.loads(out_file.read_text())
        assert "findings" in data
        assert "schema_version" in data
        assert len(data["findings"]) == 1

    @patch(_BRANCH, return_value="main")
    @patch(_COMMIT, return_value="abc123")
    @patch(_ANALYZE, new_callable=AsyncMock)
    @patch(_CLIENT)
    @patch(_PARSE)
    @patch(_DIFF, return_value=_DIFF_TEXT)
    @patch(_CONFIG, return_value=DiffguardConfig())
    @patch(_GIT, return_value=True)
    @patch.dict(os.environ, _ENV)
    def test_overwrites_existing(
        self,
        _git: MagicMock,
        _cfg: MagicMock,
        _diff: MagicMock,
        mock_parse: MagicMock,
        _client: MagicMock,
        mock_analyze: AsyncMock,
        _commit: MagicMock,
        _branch: MagicMock,
        tmp_path: Path,
    ) -> None:
        mock_parse.return_value = [_make_diff_file()]
        mock_analyze.return_value = AnalysisResult()
        out_file = tmp_path / "report.json"
        out_file.write_text("old content")

        runner.invoke(app, ["--output", str(out_file)])

        data = json.loads(out_file.read_text())
        assert data["findings"] == []

    @patch(_BRANCH, return_value="main")
    @patch(_COMMIT, return_value="abc123")
    @patch(_ANALYZE, new_callable=AsyncMock)
    @patch(_CLIENT)
    @patch(_PARSE)
    @patch(_DIFF, return_value=_DIFF_TEXT)
    @patch(_CONFIG, return_value=DiffguardConfig())
    @patch(_GIT, return_value=True)
    @patch.dict(os.environ, _ENV)
    def test_missing_directory_created(
        self,
        _git: MagicMock,
        _cfg: MagicMock,
        _diff: MagicMock,
        mock_parse: MagicMock,
        _client: MagicMock,
        mock_analyze: AsyncMock,
        _commit: MagicMock,
        _branch: MagicMock,
        tmp_path: Path,
    ) -> None:
        mock_parse.return_value = [_make_diff_file()]
        mock_analyze.return_value = AnalysisResult()
        out_file = tmp_path / "nested" / "dir" / "report.json"

        result = runner.invoke(app, ["--output", str(out_file)])

        assert result.exit_code == 0
        assert out_file.exists()

    @patch(_BRANCH, return_value="main")
    @patch(_COMMIT, return_value="abc123")
    @patch(_ANALYZE, new_callable=AsyncMock)
    @patch(_CLIENT)
    @patch(_PARSE)
    @patch(_DIFF, return_value=_DIFF_TEXT)
    @patch(_CONFIG, return_value=DiffguardConfig())
    @patch(_GIT, return_value=True)
    @patch.dict(os.environ, _ENV)
    def test_permission_denied(
        self,
        _git: MagicMock,
        _cfg: MagicMock,
        _diff: MagicMock,
        mock_parse: MagicMock,
        _client: MagicMock,
        mock_analyze: AsyncMock,
        _commit: MagicMock,
        _branch: MagicMock,
        tmp_path: Path,
    ) -> None:
        mock_parse.return_value = [_make_diff_file()]
        mock_analyze.return_value = AnalysisResult()
        readonly_dir = tmp_path / "readonly"
        readonly_dir.mkdir()
        readonly_dir.chmod(0o444)
        out_file = readonly_dir / "subdir" / "report.json"

        result = runner.invoke(app, ["--output", str(out_file)])

        readonly_dir.chmod(0o755)  # restore for cleanup
        assert result.exit_code == 2
        assert "Permission denied" in result.output

    @patch(_BRANCH, return_value="main")
    @patch(_COMMIT, return_value="abc123")
    @patch(_ANALYZE, new_callable=AsyncMock)
    @patch(_CLIENT)
    @patch(_PARSE)
    @patch(_DIFF, return_value=_DIFF_TEXT)
    @patch(_CONFIG, return_value=DiffguardConfig())
    @patch(_GIT, return_value=True)
    @patch.dict(os.environ, _ENV)
    def test_terminal_output_and_file(
        self,
        _git: MagicMock,
        _cfg: MagicMock,
        _diff: MagicMock,
        mock_parse: MagicMock,
        _client: MagicMock,
        mock_analyze: AsyncMock,
        _commit: MagicMock,
        _branch: MagicMock,
        tmp_path: Path,
    ) -> None:
        mock_parse.return_value = [_make_diff_file()]
        mock_analyze.return_value = AnalysisResult(findings=[_make_finding(SeverityLevel.LOW)])
        out_file = tmp_path / "report.json"

        result = runner.invoke(app, ["--output", str(out_file)])

        assert result.exit_code == 0
        assert "1 issue" in result.output
        assert "Report saved to" in result.output
        assert out_file.exists()


class TestCombinedFlags:
    @patch(_PREPARE)
    @patch(_PARSE)
    @patch(_DIFF, return_value=_DIFF_TEXT)
    @patch(_CONFIG, return_value=DiffguardConfig())
    @patch(_GIT, return_value=True)
    @patch.dict(os.environ, {}, clear=True)
    def test_verbose_dry_run(
        self,
        _git: MagicMock,
        _cfg: MagicMock,
        _diff: MagicMock,
        mock_parse: MagicMock,
        mock_prepare: MagicMock,
    ) -> None:
        mock_parse.return_value = [_make_diff_file()]
        mock_prepare.return_value = _make_prepared()

        result = runner.invoke(app, ["--verbose", "--dry-run"])

        assert result.exit_code == 0
        assert "region lines" in result.output
        assert "scope(s)" in result.output
        assert "tokens" in result.output

    @patch(_BRANCH, return_value="main")
    @patch(_COMMIT, return_value="abc123")
    @patch(_ANALYZE_FILES, new_callable=AsyncMock)
    @patch(_PREPARE)
    @patch(_CLIENT)
    @patch(_PARSE)
    @patch(_DIFF, return_value=_DIFF_TEXT)
    @patch(_CONFIG, return_value=DiffguardConfig())
    @patch(_GIT, return_value=True)
    @patch.dict(os.environ, _ENV)
    def test_verbose_json(
        self,
        _git: MagicMock,
        _cfg: MagicMock,
        _diff: MagicMock,
        mock_parse: MagicMock,
        _client: MagicMock,
        mock_prepare: MagicMock,
        mock_af: AsyncMock,
        _commit: MagicMock,
        _branch: MagicMock,
    ) -> None:
        mock_parse.return_value = [_make_diff_file()]
        mock_prepare.return_value = _make_prepared()
        mock_af.return_value = AnalysisResult(findings=[_make_finding(SeverityLevel.LOW)])

        result = runner.invoke(app, ["--verbose", "--json"])

        data = json.loads(result.output)
        assert "findings" in data
        assert "Analyzing" not in result.output

    @patch(_BRANCH, return_value="main")
    @patch(_COMMIT, return_value="abc123")
    @patch(_ANALYZE, new_callable=AsyncMock)
    @patch(_CLIENT)
    @patch(_PARSE)
    @patch(_DIFF, return_value=_DIFF_TEXT)
    @patch(_CONFIG, return_value=DiffguardConfig())
    @patch(_GIT, return_value=True)
    @patch.dict(os.environ, _ENV)
    def test_json_output_same_content(
        self,
        _git: MagicMock,
        _cfg: MagicMock,
        _diff: MagicMock,
        mock_parse: MagicMock,
        _client: MagicMock,
        mock_analyze: AsyncMock,
        _commit: MagicMock,
        _branch: MagicMock,
        tmp_path: Path,
    ) -> None:
        mock_parse.return_value = [_make_diff_file()]
        mock_analyze.return_value = AnalysisResult(findings=[_make_finding(SeverityLevel.LOW)])
        out_file = tmp_path / "report.json"

        result = runner.invoke(app, ["--json", "--output", str(out_file)])

        stdout_data = json.loads(result.output)
        file_data = json.loads(out_file.read_text())
        assert stdout_data == file_data

    @patch(_PREPARE)
    @patch(_PARSE)
    @patch(_DIFF, return_value=_DIFF_TEXT)
    @patch(_CONFIG, return_value=DiffguardConfig())
    @patch(_GIT, return_value=True)
    @patch.dict(os.environ, {}, clear=True)
    def test_dry_run_json(
        self,
        _git: MagicMock,
        _cfg: MagicMock,
        _diff: MagicMock,
        mock_parse: MagicMock,
        mock_prepare: MagicMock,
    ) -> None:
        mock_parse.return_value = [_make_diff_file()]
        mock_prepare.return_value = _make_prepared()

        result = runner.invoke(app, ["--dry-run", "--json"])

        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["dry_run"] is True
        assert "files" in data
        assert "total_estimated_tokens" in data

    @patch(_PREPARE)
    @patch(_PARSE)
    @patch(_DIFF, return_value=_DIFF_TEXT)
    @patch(_CONFIG, return_value=DiffguardConfig())
    @patch(_GIT, return_value=True)
    @patch.dict(os.environ, {}, clear=True)
    def test_dry_run_output(
        self,
        _git: MagicMock,
        _cfg: MagicMock,
        _diff: MagicMock,
        mock_parse: MagicMock,
        mock_prepare: MagicMock,
        tmp_path: Path,
    ) -> None:
        mock_parse.return_value = [_make_diff_file()]
        mock_prepare.return_value = _make_prepared()
        out_file = tmp_path / "dry-run.json"

        result = runner.invoke(app, ["--dry-run", "--output", str(out_file)])

        assert result.exit_code == 0
        assert out_file.exists()
        data = json.loads(out_file.read_text())
        assert data["dry_run"] is True
        assert "Report saved to" in result.output
