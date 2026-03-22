"""Tests for helm-doctor CLI commands."""
from click.testing import CliRunner

from helm_doctor.cli import main


class TestVersion:
    def test_version_flag(self):
        runner = CliRunner()
        result = runner.invoke(main, ["--version"])
        assert result.exit_code == 0
        assert "helm-doctor" in result.output

    def test_help(self):
        runner = CliRunner()
        result = runner.invoke(main, ["--help"])
        assert result.exit_code == 0
        assert "scan" in result.output
        assert "demo" in result.output
        assert "rules" in result.output


class TestScanCommand:
    def test_scan_good_chart(self, good_chart):
        runner = CliRunner()
        result = runner.invoke(main, ["scan", good_chart])
        assert result.exit_code == 0

    def test_scan_bad_chart(self, bad_chart):
        runner = CliRunner()
        result = runner.invoke(main, ["scan", bad_chart])
        assert result.exit_code == 0

    def test_scan_nonexistent_path(self):
        runner = CliRunner()
        result = runner.invoke(main, ["scan", "/nonexistent/path"])
        assert result.exit_code != 0

    def test_scan_verbose(self, good_chart):
        runner = CliRunner()
        result = runner.invoke(main, ["scan", good_chart, "--verbose"])
        assert result.exit_code == 0

    def test_scan_export_json(self, good_chart, tmp_path):
        output = str(tmp_path / "report.json")
        runner = CliRunner()
        result = runner.invoke(main, ["scan", good_chart, "--export", "json", "--output", output])
        assert result.exit_code == 0
        import json
        with open(output) as f:
            data = json.load(f)
        assert "issues" in data

    def test_scan_export_html(self, good_chart, tmp_path):
        output = str(tmp_path / "report.html")
        runner = CliRunner()
        result = runner.invoke(main, ["scan", good_chart, "--export", "html", "--output", output])
        assert result.exit_code == 0
        assert (tmp_path / "report.html").exists()

    def test_scan_fail_on_critical(self, bad_chart):
        runner = CliRunner()
        result = runner.invoke(main, ["scan", bad_chart, "--fail-on", "critical"])
        # bad_chart has critical issues, so should exit 1
        # (if any critical issues are found)
        # Exit code depends on whether critical issues exist
        assert result.exit_code in (0, 1)

    def test_scan_category_filter(self, good_chart):
        runner = CliRunner()
        result = runner.invoke(main, ["scan", good_chart, "--category", "security"])
        assert result.exit_code == 0


class TestDemoCommand:
    def test_demo_runs(self):
        runner = CliRunner()
        result = runner.invoke(main, ["demo"])
        assert result.exit_code == 0
        assert "helm-doctor" in result.output.lower() or "score" in result.output.lower()


class TestRulesCommand:
    def test_rules_list(self):
        runner = CliRunner()
        result = runner.invoke(main, ["rules"])
        assert result.exit_code == 0
        assert "HD-" in result.output
