"""Core data models for helm-doctor."""
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Severity(Enum):
    """Issue severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Category(Enum):
    """Issue categories."""
    CHART_STRUCTURE = "Chart Structure"
    METADATA = "Metadata"
    VALUES = "Values"
    TEMPLATES = "Templates"
    SECURITY = "Security"
    BEST_PRACTICES = "Best Practices"
    DEPENDENCIES = "Dependencies"
    RESOURCE_MANAGEMENT = "Resource Management"
    NETWORKING = "Networking"
    RELIABILITY = "Reliability"
    DOCUMENTATION = "Documentation"


SEVERITY_SCORES = {
    Severity.CRITICAL: 15,
    Severity.HIGH: 10,
    Severity.MEDIUM: 5,
    Severity.LOW: 2,
    Severity.INFO: 0,
}

SEVERITY_COLORS = {
    Severity.CRITICAL: "bright_red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}

SEVERITY_ICONS = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH: "🟠",
    Severity.MEDIUM: "🟡",
    Severity.LOW: "🔵",
    Severity.INFO: "⚪",
}

CATEGORY_ICONS = {
    Category.CHART_STRUCTURE: "📦",
    Category.METADATA: "🏷️",
    Category.VALUES: "⚙️",
    Category.TEMPLATES: "📄",
    Category.SECURITY: "🔒",
    Category.BEST_PRACTICES: "✅",
    Category.DEPENDENCIES: "🔗",
    Category.RESOURCE_MANAGEMENT: "📊",
    Category.NETWORKING: "🌐",
    Category.RELIABILITY: "🛡️",
    Category.DOCUMENTATION: "📚",
}


@dataclass
class Issue:
    """Represents a single lint/validation issue."""
    rule_id: str
    severity: Severity
    category: Category
    message: str
    file_path: str
    line: Optional[int] = None
    suggestion: Optional[str] = None
    doc_url: Optional[str] = None


@dataclass
class RuleResult:
    """Result from running a single rule check."""
    rule_id: str
    rule_name: str
    passed: bool
    issues: list = field(default_factory=list)


@dataclass
class AnalysisReport:
    """Full analysis report from all analyzers."""
    chart_path: str
    chart_name: str = "unknown"
    chart_version: str = "0.0.0"
    app_version: str = ""
    chart_type: str = "application"
    total_rules: int = 0
    passed_rules: int = 0
    failed_rules: int = 0
    issues: list = field(default_factory=list)
    score: float = 100.0
    grade: str = "A+"
    summary: dict = field(default_factory=dict)

    @property
    def critical_count(self):
        return sum(1 for i in self.issues if i.severity == Severity.CRITICAL)

    @property
    def high_count(self):
        return sum(1 for i in self.issues if i.severity == Severity.HIGH)

    @property
    def medium_count(self):
        return sum(1 for i in self.issues if i.severity == Severity.MEDIUM)

    @property
    def low_count(self):
        return sum(1 for i in self.issues if i.severity == Severity.LOW)

    @property
    def info_count(self):
        return sum(1 for i in self.issues if i.severity == Severity.INFO)

    def calculate_score(self):
        """Calculate health score based on issues found."""
        if self.total_rules == 0:
            self.score = 0.0
            self.grade = "F"
            return

        total_deductions = sum(SEVERITY_SCORES[i.severity] for i in self.issues)
        max_possible = self.total_rules * 5  # avg weight
        self.score = max(0, round(100 - (total_deductions / max(max_possible, 1)) * 100, 1))

        if self.score >= 95:
            self.grade = "A+"
        elif self.score >= 90:
            self.grade = "A"
        elif self.score >= 85:
            self.grade = "A-"
        elif self.score >= 80:
            self.grade = "B+"
        elif self.score >= 75:
            self.grade = "B"
        elif self.score >= 70:
            self.grade = "B-"
        elif self.score >= 65:
            self.grade = "C+"
        elif self.score >= 60:
            self.grade = "C"
        elif self.score >= 55:
            self.grade = "C-"
        elif self.score >= 50:
            self.grade = "D+"
        elif self.score >= 45:
            self.grade = "D"
        elif self.score >= 40:
            self.grade = "D-"
        else:
            self.grade = "F"
