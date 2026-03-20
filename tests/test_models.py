"""Tests for helm-doctor models."""
from helm_doctor.models import AnalysisReport, Issue, Severity, Category, SEVERITY_SCORES


class TestSeverity:
    def test_all_values(self):
        assert Severity.CRITICAL.value == "critical"
        assert Severity.HIGH.value == "high"
        assert Severity.MEDIUM.value == "medium"
        assert Severity.LOW.value == "low"
        assert Severity.INFO.value == "info"

    def test_severity_scores(self):
        assert SEVERITY_SCORES[Severity.CRITICAL] > SEVERITY_SCORES[Severity.HIGH]
        assert SEVERITY_SCORES[Severity.HIGH] > SEVERITY_SCORES[Severity.MEDIUM]
        assert SEVERITY_SCORES[Severity.INFO] == 0


class TestIssue:
    def test_create_issue(self):
        issue = Issue(
            rule_id="HD-C001",
            severity=Severity.CRITICAL,
            category=Category.CHART_STRUCTURE,
            message="Test issue",
            file_path="Chart.yaml",
        )
        assert issue.rule_id == "HD-C001"
        assert issue.severity == Severity.CRITICAL
        assert issue.suggestion is None
        assert issue.doc_url is None

    def test_issue_with_optional_fields(self):
        issue = Issue(
            rule_id="HD-C001",
            severity=Severity.LOW,
            category=Category.METADATA,
            message="Test",
            file_path="Chart.yaml",
            line=10,
            suggestion="Fix it",
            doc_url="https://example.com",
        )
        assert issue.line == 10
        assert issue.suggestion == "Fix it"


class TestAnalysisReport:
    def test_empty_report(self):
        report = AnalysisReport(chart_path="/tmp/test")
        assert report.critical_count == 0
        assert report.high_count == 0
        assert report.score == 100.0
        assert report.grade == "A+"

    def test_severity_counts(self):
        report = AnalysisReport(chart_path="/tmp/test")
        report.issues = [
            Issue("HD-C001", Severity.CRITICAL, Category.CHART_STRUCTURE, "crit", "f"),
            Issue("HD-C002", Severity.CRITICAL, Category.CHART_STRUCTURE, "crit2", "f"),
            Issue("HD-C003", Severity.HIGH, Category.METADATA, "high", "f"),
            Issue("HD-C004", Severity.MEDIUM, Category.VALUES, "med", "f"),
            Issue("HD-C005", Severity.LOW, Category.TEMPLATES, "low", "f"),
            Issue("HD-C006", Severity.INFO, Category.SECURITY, "info", "f"),
        ]
        assert report.critical_count == 2
        assert report.high_count == 1
        assert report.medium_count == 1
        assert report.low_count == 1
        assert report.info_count == 1

    def test_calculate_score_no_issues(self):
        report = AnalysisReport(chart_path="/tmp/test", total_rules=10)
        report.calculate_score()
        assert report.score == 100.0
        assert report.grade == "A+"

    def test_calculate_score_many_issues(self):
        report = AnalysisReport(chart_path="/tmp/test", total_rules=5)
        report.issues = [
            Issue("HD-C001", Severity.CRITICAL, Category.CHART_STRUCTURE, "crit", "f"),
            Issue("HD-C002", Severity.CRITICAL, Category.CHART_STRUCTURE, "crit2", "f"),
            Issue("HD-C003", Severity.HIGH, Category.METADATA, "high", "f"),
            Issue("HD-C004", Severity.HIGH, Category.METADATA, "high2", "f"),
        ]
        report.calculate_score()
        assert report.score < 50
        assert report.grade in ("D-", "D", "D+", "F")

    def test_calculate_score_zero_rules(self):
        report = AnalysisReport(chart_path="/tmp/test", total_rules=0)
        report.calculate_score()
        assert report.score == 0.0
        assert report.grade == "F"
