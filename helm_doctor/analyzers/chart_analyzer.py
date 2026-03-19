"""Chart.yaml analyzer — validates chart metadata, versioning, and structure."""
import os
import re
from typing import Optional

import yaml

from helm_doctor.models import (
    AnalysisReport, Category, Issue, RuleResult, Severity,
)

# Valid Helm API versions
VALID_API_VERSIONS = ["v1", "v2"]

# Valid chart types
VALID_CHART_TYPES = ["application", "library"]

# SemVer regex (strict)
SEMVER_RE = re.compile(
    r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
    r"(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)"
    r"(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?"
    r"(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$"
)

# Required Chart.yaml fields for v2
REQUIRED_FIELDS_V2 = ["apiVersion", "name", "version"]

# Recommended Chart.yaml fields
RECOMMENDED_FIELDS = [
    "description", "type", "appVersion", "maintainers",
    "home", "sources", "keywords", "icon",
]

# Chart name regex (lowercase, digits, dashes)
CHART_NAME_RE = re.compile(r"^[a-z][a-z0-9\-]*$")


def analyze_chart_yaml(chart_path: str) -> list:
    """Run all Chart.yaml rules and return issues."""
    chart_yaml_path = os.path.join(chart_path, "Chart.yaml")
    issues = []

    # Rule HD-C001: Chart.yaml must exist
    if not os.path.isfile(chart_yaml_path):
        issues.append(Issue(
            rule_id="HD-C001",
            severity=Severity.CRITICAL,
            category=Category.CHART_STRUCTURE,
            message="Chart.yaml file is missing",
            file_path="Chart.yaml",
            suggestion="Create a Chart.yaml file with at least apiVersion, name, and version fields",
            doc_url="https://helm.sh/docs/topics/charts/#the-chartyaml-file",
        ))
        return issues

    try:
        with open(chart_yaml_path, "r", encoding="utf-8") as f:
            chart = yaml.safe_load(f)
    except yaml.YAMLError as e:
        issues.append(Issue(
            rule_id="HD-C002",
            severity=Severity.CRITICAL,
            category=Category.CHART_STRUCTURE,
            message=f"Chart.yaml has invalid YAML syntax: {e}",
            file_path="Chart.yaml",
            suggestion="Fix the YAML syntax errors in Chart.yaml",
        ))
        return issues

    if not isinstance(chart, dict):
        issues.append(Issue(
            rule_id="HD-C003",
            severity=Severity.CRITICAL,
            category=Category.CHART_STRUCTURE,
            message="Chart.yaml does not contain a valid YAML mapping",
            file_path="Chart.yaml",
            suggestion="Ensure Chart.yaml contains key-value pairs, not a list or scalar",
        ))
        return issues

    # Rule HD-C004: Required fields
    for field_name in REQUIRED_FIELDS_V2:
        if field_name not in chart or chart[field_name] is None:
            issues.append(Issue(
                rule_id="HD-C004",
                severity=Severity.CRITICAL,
                category=Category.METADATA,
                message=f"Required field '{field_name}' is missing from Chart.yaml",
                file_path="Chart.yaml",
                suggestion=f"Add '{field_name}' to Chart.yaml",
                doc_url="https://helm.sh/docs/topics/charts/#the-chartyaml-file",
            ))

    # Rule HD-C005: apiVersion must be valid
    api_version = chart.get("apiVersion", "")
    if api_version and api_version not in VALID_API_VERSIONS:
        issues.append(Issue(
            rule_id="HD-C005",
            severity=Severity.HIGH,
            category=Category.METADATA,
            message=f"Invalid apiVersion '{api_version}'. Must be 'v1' or 'v2'",
            file_path="Chart.yaml",
            suggestion="Set apiVersion to 'v2' for Helm 3 charts",
            doc_url="https://helm.sh/docs/topics/charts/#the-apiversion-field",
        ))

    # Rule HD-C006: apiVersion should be v2
    if api_version == "v1":
        issues.append(Issue(
            rule_id="HD-C006",
            severity=Severity.MEDIUM,
            category=Category.METADATA,
            message="Chart uses apiVersion 'v1' (Helm 2 format). Consider upgrading to 'v2'",
            file_path="Chart.yaml",
            suggestion="Update apiVersion to 'v2' for Helm 3 features like library charts and dependencies",
            doc_url="https://helm.sh/docs/topics/charts/#the-apiversion-field",
        ))

    # Rule HD-C007: Chart name must follow conventions
    chart_name = str(chart.get("name", ""))
    if chart_name and not CHART_NAME_RE.match(chart_name):
        issues.append(Issue(
            rule_id="HD-C007",
            severity=Severity.MEDIUM,
            category=Category.METADATA,
            message=f"Chart name '{chart_name}' should use lowercase letters, digits, and dashes only",
            file_path="Chart.yaml",
            suggestion="Rename chart to use only lowercase letters, digits, and dashes (e.g., 'my-chart')",
            doc_url="https://helm.sh/docs/chart_best_practices/conventions/#chart-names",
        ))

    # Rule HD-C008: Chart name length
    if len(chart_name) > 53:
        issues.append(Issue(
            rule_id="HD-C008",
            severity=Severity.HIGH,
            category=Category.METADATA,
            message=f"Chart name '{chart_name}' exceeds 53 characters (DNS subdomain limit)",
            file_path="Chart.yaml",
            suggestion="Shorten chart name to 53 characters or fewer",
        ))

    # Rule HD-C009: Version must be valid SemVer
    version = str(chart.get("version", ""))
    if version and not SEMVER_RE.match(version):
        issues.append(Issue(
            rule_id="HD-C009",
            severity=Severity.HIGH,
            category=Category.METADATA,
            message=f"Chart version '{version}' is not valid SemVer",
            file_path="Chart.yaml",
            suggestion="Use valid semantic versioning (e.g., '1.0.0', '0.2.1-beta.1')",
            doc_url="https://semver.org/",
        ))

    # Rule HD-C010: Version should not be 0.0.0
    if version == "0.0.0":
        issues.append(Issue(
            rule_id="HD-C010",
            severity=Severity.LOW,
            category=Category.METADATA,
            message="Chart version is '0.0.0' — likely a placeholder",
            file_path="Chart.yaml",
            suggestion="Set a meaningful version (e.g., '0.1.0' for initial development)",
        ))

    # Rule HD-C011: appVersion should be set
    if "appVersion" not in chart or not chart["appVersion"]:
        issues.append(Issue(
            rule_id="HD-C011",
            severity=Severity.LOW,
            category=Category.METADATA,
            message="appVersion is not set in Chart.yaml",
            file_path="Chart.yaml",
            suggestion="Set appVersion to the version of the application being deployed",
            doc_url="https://helm.sh/docs/topics/charts/#the-appversion-field",
        ))

    # Rule HD-C012: description should be set
    if not chart.get("description"):
        issues.append(Issue(
            rule_id="HD-C012",
            severity=Severity.LOW,
            category=Category.DOCUMENTATION,
            message="Chart description is missing",
            file_path="Chart.yaml",
            suggestion="Add a meaningful description to Chart.yaml",
        ))

    # Rule HD-C013: type should be set (v2)
    if api_version == "v2" and "type" not in chart:
        issues.append(Issue(
            rule_id="HD-C013",
            severity=Severity.LOW,
            category=Category.METADATA,
            message="Chart type is not explicitly set (defaults to 'application')",
            file_path="Chart.yaml",
            suggestion="Explicitly set 'type: application' or 'type: library'",
        ))

    # Rule HD-C014: type must be valid
    chart_type = chart.get("type", "")
    if chart_type and chart_type not in VALID_CHART_TYPES:
        issues.append(Issue(
            rule_id="HD-C014",
            severity=Severity.HIGH,
            category=Category.METADATA,
            message=f"Invalid chart type '{chart_type}'. Must be 'application' or 'library'",
            file_path="Chart.yaml",
            suggestion="Set type to 'application' or 'library'",
        ))

    # Rule HD-C015: maintainers should be set
    maintainers = chart.get("maintainers")
    if not maintainers:
        issues.append(Issue(
            rule_id="HD-C015",
            severity=Severity.LOW,
            category=Category.DOCUMENTATION,
            message="No maintainers listed in Chart.yaml",
            file_path="Chart.yaml",
            suggestion="Add maintainers with name and email for chart ownership",
            doc_url="https://helm.sh/docs/topics/charts/#the-chartyaml-file",
        ))
    elif isinstance(maintainers, list):
        for i, m in enumerate(maintainers):
            if isinstance(m, dict):
                if not m.get("name"):
                    issues.append(Issue(
                        rule_id="HD-C016",
                        severity=Severity.LOW,
                        category=Category.DOCUMENTATION,
                        message=f"Maintainer #{i+1} is missing a name",
                        file_path="Chart.yaml",
                        suggestion="Add a name for each maintainer entry",
                    ))
                if not m.get("email"):
                    issues.append(Issue(
                        rule_id="HD-C017",
                        severity=Severity.INFO,
                        category=Category.DOCUMENTATION,
                        message=f"Maintainer '{m.get('name', f'#{i+1}')}' has no email",
                        file_path="Chart.yaml",
                        suggestion="Add an email for each maintainer entry",
                    ))

    # Rule HD-C018: home URL should be set
    if not chart.get("home"):
        issues.append(Issue(
            rule_id="HD-C018",
            severity=Severity.INFO,
            category=Category.DOCUMENTATION,
            message="Chart home URL is not set",
            file_path="Chart.yaml",
            suggestion="Add a home URL pointing to the project's homepage or repository",
        ))

    # Rule HD-C019: sources should be set
    if not chart.get("sources"):
        issues.append(Issue(
            rule_id="HD-C019",
            severity=Severity.INFO,
            category=Category.DOCUMENTATION,
            message="No source URLs listed in Chart.yaml",
            file_path="Chart.yaml",
            suggestion="Add source URLs (e.g., GitHub repository) for transparency",
        ))

    # Rule HD-C020: icon should be set
    if not chart.get("icon"):
        issues.append(Issue(
            rule_id="HD-C020",
            severity=Severity.INFO,
            category=Category.DOCUMENTATION,
            message="Chart icon URL is not set",
            file_path="Chart.yaml",
            suggestion="Add an icon URL for chart gallery/UI display",
        ))

    # Rule HD-C021: keywords should be set
    if not chart.get("keywords"):
        issues.append(Issue(
            rule_id="HD-C021",
            severity=Severity.INFO,
            category=Category.DOCUMENTATION,
            message="No keywords defined in Chart.yaml",
            file_path="Chart.yaml",
            suggestion="Add keywords for chart discoverability in Helm repositories",
        ))

    # Rule HD-C022: deprecated should not be true without notice
    if chart.get("deprecated", False):
        issues.append(Issue(
            rule_id="HD-C022",
            severity=Severity.MEDIUM,
            category=Category.METADATA,
            message="Chart is marked as deprecated",
            file_path="Chart.yaml",
            suggestion="If the chart is deprecated, ensure migration docs exist. Otherwise, remove 'deprecated: true'",
        ))

    # Rule HD-C023: kubeVersion should be set
    if not chart.get("kubeVersion"):
        issues.append(Issue(
            rule_id="HD-C023",
            severity=Severity.MEDIUM,
            category=Category.METADATA,
            message="kubeVersion constraint is not set",
            file_path="Chart.yaml",
            suggestion="Set kubeVersion (e.g., '>= 1.23.0-0') to enforce Kubernetes compatibility",
            doc_url="https://helm.sh/docs/topics/charts/#the-kubeversion-field",
        ))

    return issues


def get_chart_metadata(chart_path: str) -> dict:
    """Extract chart metadata for the report."""
    chart_yaml_path = os.path.join(chart_path, "Chart.yaml")
    defaults = {
        "name": "unknown",
        "version": "0.0.0",
        "appVersion": "",
        "type": "application",
        "description": "",
    }

    if not os.path.isfile(chart_yaml_path):
        return defaults

    try:
        with open(chart_yaml_path, "r", encoding="utf-8") as f:
            chart = yaml.safe_load(f) or {}
        if isinstance(chart, dict):
            for k in defaults:
                defaults[k] = str(chart.get(k, defaults[k]))
        return defaults
    except Exception:
        return defaults
