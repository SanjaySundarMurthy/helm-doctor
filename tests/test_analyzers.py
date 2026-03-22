"""Tests for helm-doctor analyzers."""
import os

from helm_doctor.analyzers.chart_analyzer import analyze_chart_yaml, get_chart_metadata
from helm_doctor.analyzers.dependency_analyzer import analyze_dependencies
from helm_doctor.analyzers.security_analyzer import analyze_security
from helm_doctor.analyzers.structure_analyzer import analyze_structure
from helm_doctor.analyzers.template_analyzer import analyze_templates
from helm_doctor.analyzers.values_analyzer import analyze_values_yaml
from helm_doctor.models import Severity


class TestChartAnalyzer:
    def test_valid_chart(self, good_chart):
        issues = analyze_chart_yaml(good_chart)
        crits = [i for i in issues if i.severity == Severity.CRITICAL]
        assert len(crits) == 0, f"Good chart should have no critical issues: {[i.message for i in crits]}"

    def test_missing_chart_yaml(self, tmp_path):
        issues = analyze_chart_yaml(str(tmp_path))
        assert any(i.rule_id == "HD-C001" for i in issues)

    def test_invalid_yaml(self, tmp_chart):
        chart = tmp_chart(chart_yaml="{{invalid: yaml: [")
        issues = analyze_chart_yaml(chart)
        assert any(i.rule_id == "HD-C002" for i in issues)

    def test_missing_required_fields(self, tmp_chart):
        chart = tmp_chart(chart_yaml="apiVersion: v2\n")
        issues = analyze_chart_yaml(chart)
        rule_ids = [i.rule_id for i in issues]
        assert "HD-C004" in rule_ids  # missing name/version

    def test_bad_chart_name(self, tmp_chart):
        chart = tmp_chart(chart_yaml="apiVersion: v2\nname: BAD_CHART\nversion: 1.0.0\n")
        issues = analyze_chart_yaml(chart)
        msgs = " ".join(i.message for i in issues)
        assert "name" in msgs.lower() or "naming" in msgs.lower() or any(
            "name" in i.message.lower() for i in issues
        )

    def test_non_semver_version(self, tmp_chart):
        chart = tmp_chart(chart_yaml="apiVersion: v2\nname: test\nversion: not-semver\n")
        issues = analyze_chart_yaml(chart)
        assert any("version" in i.message.lower() or "semver" in i.message.lower() for i in issues)

    def test_get_chart_metadata_valid(self, good_chart):
        meta = get_chart_metadata(good_chart)
        assert meta["name"] == "test-chart"
        assert meta["version"] == "1.0.0"

    def test_get_chart_metadata_missing(self, tmp_path):
        meta = get_chart_metadata(str(tmp_path))
        assert meta["name"] == "unknown"


class TestStructureAnalyzer:
    def test_valid_structure(self, good_chart):
        issues = analyze_structure(good_chart)
        crits = [i for i in issues if i.severity == Severity.CRITICAL]
        assert len(crits) == 0

    def test_missing_chart_yaml(self, tmp_path):
        issues = analyze_structure(str(tmp_path))
        assert any(i.rule_id == "HD-X001" for i in issues)

    def test_missing_recommended_files(self, good_chart):
        issues = analyze_structure(good_chart)
        # Should flag missing .helmignore, README, etc.
        rule_ids = [i.rule_id for i in issues]
        assert "HD-X002" in rule_ids


class TestSecurityAnalyzer:
    def test_clean_chart(self, good_chart):
        issues = analyze_security(good_chart)
        crits = [i for i in issues if i.severity == Severity.CRITICAL]
        assert len(crits) == 0

    def test_privileged_container(self, bad_chart):
        issues = analyze_security(bad_chart)
        msgs = " ".join(i.message.lower() for i in issues)
        assert "privileged" in msgs or any(
            "privileged" in i.message.lower() for i in issues
        )

    def test_host_path(self, bad_chart):
        issues = analyze_security(bad_chart)
        msgs = " ".join(i.message.lower() for i in issues)
        assert "hostpath" in msgs or "host" in msgs

    def test_run_as_root(self, bad_chart):
        issues = analyze_security(bad_chart)
        msgs = " ".join(i.message.lower() for i in issues)
        assert "root" in msgs or "runasuser" in msgs or "user: 0" in msgs


class TestValuesAnalyzer:
    def test_valid_values(self, good_chart):
        issues = analyze_values_yaml(good_chart)
        crits = [i for i in issues if i.severity == Severity.CRITICAL]
        assert len(crits) == 0

    def test_latest_tag(self, bad_chart):
        issues = analyze_values_yaml(bad_chart)
        assert any("latest" in i.message.lower() for i in issues)

    def test_hardcoded_secret(self, bad_chart):
        issues = analyze_values_yaml(bad_chart)
        assert any(
            "password" in i.message.lower() or "secret" in i.message.lower()
            for i in issues
        )

    def test_empty_resources(self, bad_chart):
        issues = analyze_values_yaml(bad_chart)
        assert any("resource" in i.message.lower() for i in issues)

    def test_missing_values_yaml(self, tmp_path):
        os.makedirs(tmp_path / "templates", exist_ok=True)
        (tmp_path / "Chart.yaml").write_text("apiVersion: v2\nname: t\nversion: 1.0.0\n")
        issues = analyze_values_yaml(str(tmp_path))
        assert len(issues) > 0  # Should detect missing values.yaml


class TestTemplateAnalyzer:
    def test_no_templates_dir(self, tmp_path):
        (tmp_path / "Chart.yaml").write_text("apiVersion: v2\nname: t\nversion: 1.0.0\n")
        issues = analyze_templates(str(tmp_path))
        assert any(i.rule_id == "HD-T001" for i in issues)

    def test_empty_templates_dir(self, tmp_path):
        (tmp_path / "Chart.yaml").write_text("apiVersion: v2\nname: t\nversion: 1.0.0\n")
        (tmp_path / "templates").mkdir()
        issues = analyze_templates(str(tmp_path))
        assert any(i.rule_id == "HD-T002" for i in issues)

    def test_missing_helpers(self, tmp_chart):
        chart = tmp_chart(templates={"deployment.yaml": "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: test\n"})
        issues = analyze_templates(chart)
        assert any(i.rule_id == "HD-T003" for i in issues)

    def test_hardcoded_namespace(self, bad_chart):
        issues = analyze_templates(bad_chart)
        assert any(i.rule_id == "HD-T006" for i in issues)

    def test_good_chart_no_critical(self, good_chart):
        issues = analyze_templates(good_chart)
        crits = [i for i in issues if i.severity == Severity.CRITICAL]
        assert len(crits) == 0


class TestDependencyAnalyzer:
    def test_no_dependencies(self, good_chart):
        issues = analyze_dependencies(good_chart)
        assert len(issues) == 0

    def test_missing_chart_yaml(self, tmp_path):
        issues = analyze_dependencies(str(tmp_path))
        assert len(issues) == 0

    def test_dependencies_without_lock(self, tmp_chart):
        chart = tmp_chart(
            chart_yaml=(
                "apiVersion: v2\nname: test\nversion: 1.0.0\n"
                "dependencies:\n"
                "  - name: redis\n"
                "    version: ~17.0.0\n"
                "    repository: https://charts.bitnami.com/bitnami\n"
            ),
        )
        issues = analyze_dependencies(chart)
        rule_ids = [i.rule_id for i in issues]
        assert "HD-D003" in rule_ids  # missing Chart.lock

    def test_dependency_missing_version(self, tmp_chart):
        chart = tmp_chart(
            chart_yaml=(
                "apiVersion: v2\nname: test\nversion: 1.0.0\n"
                "dependencies:\n"
                "  - name: redis\n"
                "    repository: https://charts.bitnami.com/bitnami\n"
            ),
        )
        issues = analyze_dependencies(chart)
        assert any(i.rule_id == "HD-D006" for i in issues)

    def test_dependency_missing_repo(self, tmp_chart):
        chart = tmp_chart(
            chart_yaml=(
                "apiVersion: v2\nname: test\nversion: 1.0.0\n"
                "dependencies:\n"
                "  - name: redis\n"
                "    version: ~17.0.0\n"
            ),
        )
        issues = analyze_dependencies(chart)
        assert any(i.rule_id == "HD-D008" for i in issues)
