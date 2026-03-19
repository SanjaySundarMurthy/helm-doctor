"""Dependency analyzer — validates Helm chart dependencies."""
import os
import re

import yaml

from helm_doctor.models import Category, Issue, Severity

SEMVER_RE = re.compile(
    r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
    r"(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)"
    r"(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?"
    r"(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$"
)

SEMVER_RANGE_RE = re.compile(r"[\^~>=<|x\*]")


def analyze_dependencies(chart_path: str) -> list:
    """Run all dependency rules and return issues."""
    chart_yaml_path = os.path.join(chart_path, "Chart.yaml")
    issues = []

    if not os.path.isfile(chart_yaml_path):
        return issues

    try:
        with open(chart_yaml_path, "r", encoding="utf-8") as f:
            chart = yaml.safe_load(f) or {}
    except Exception:
        return issues

    if not isinstance(chart, dict):
        return issues

    api_version = chart.get("apiVersion", "v2")
    deps = chart.get("dependencies", [])

    # Rule HD-D001: v2 charts should use dependencies in Chart.yaml
    requirements_path = os.path.join(chart_path, "requirements.yaml")
    if os.path.isfile(requirements_path):
        if api_version == "v2":
            issues.append(Issue(
                rule_id="HD-D001",
                severity=Severity.MEDIUM,
                category=Category.DEPENDENCIES,
                message="requirements.yaml found — Helm v2 style. Use Chart.yaml 'dependencies' field for v2",
                file_path="requirements.yaml",
                suggestion="Move dependencies from requirements.yaml to the 'dependencies' section of Chart.yaml",
                doc_url="https://helm.sh/docs/topics/charts/#chart-dependencies",
            ))
        else:
            # Load from requirements.yaml for v1
            try:
                with open(requirements_path, "r", encoding="utf-8") as f:
                    req = yaml.safe_load(f) or {}
                deps = req.get("dependencies", [])
            except Exception:
                pass

    if not deps:
        return issues

    if not isinstance(deps, list):
        issues.append(Issue(
            rule_id="HD-D002",
            severity=Severity.HIGH,
            category=Category.DEPENDENCIES,
            message="Dependencies must be a list/array",
            file_path="Chart.yaml",
            suggestion="Ensure 'dependencies' is a YAML list of dependency objects",
        ))
        return issues

    charts_dir = os.path.join(chart_path, "charts")
    lock_file = os.path.join(chart_path, "Chart.lock")

    # Rule HD-D003: Chart.lock should exist if dependencies are defined
    if not os.path.isfile(lock_file):
        issues.append(Issue(
            rule_id="HD-D003",
            severity=Severity.MEDIUM,
            category=Category.DEPENDENCIES,
            message="Chart.lock is missing — dependencies are not locked",
            file_path="Chart.lock",
            suggestion="Run 'helm dependency update' to generate Chart.lock for reproducible builds",
            doc_url="https://helm.sh/docs/helm/helm_dependency_update/",
        ))

    # Rule HD-D004: charts/ directory should exist if dependencies are defined
    if not os.path.isdir(charts_dir):
        issues.append(Issue(
            rule_id="HD-D004",
            severity=Severity.MEDIUM,
            category=Category.DEPENDENCIES,
            message="charts/ directory is missing — dependencies are not downloaded",
            file_path="charts/",
            suggestion="Run 'helm dependency build' to download chart dependencies",
        ))

    seen_names = set()
    for i, dep in enumerate(deps):
        if not isinstance(dep, dict):
            continue

        dep_name = dep.get("name", f"dependency-{i}")

        # Rule HD-D005: dependency name is required
        if not dep.get("name"):
            issues.append(Issue(
                rule_id="HD-D005",
                severity=Severity.HIGH,
                category=Category.DEPENDENCIES,
                message=f"Dependency #{i+1} is missing a name",
                file_path="Chart.yaml",
                suggestion="Add 'name' field to the dependency entry",
            ))

        # Rule HD-D006: dependency version is required
        version = dep.get("version", "")
        if not version:
            issues.append(Issue(
                rule_id="HD-D006",
                severity=Severity.HIGH,
                category=Category.DEPENDENCIES,
                message=f"Dependency '{dep_name}' has no version constraint",
                file_path="Chart.yaml",
                suggestion=f"Add a version constraint for '{dep_name}' (e.g., '~1.0.0' or '^2.0.0')",
            ))
        elif not SEMVER_RE.match(version) and not SEMVER_RANGE_RE.search(version):
            issues.append(Issue(
                rule_id="HD-D007",
                severity=Severity.MEDIUM,
                category=Category.DEPENDENCIES,
                message=f"Dependency '{dep_name}' has unusual version constraint: '{version}'",
                file_path="Chart.yaml",
                suggestion="Use SemVer ranges (e.g., '~1.0.0', '^2.0.0', '>=1.0.0 <2.0.0')",
            ))

        # Rule HD-D008: dependency repository is required
        repo = dep.get("repository", "")
        if not repo:
            issues.append(Issue(
                rule_id="HD-D008",
                severity=Severity.HIGH,
                category=Category.DEPENDENCIES,
                message=f"Dependency '{dep_name}' has no repository URL",
                file_path="Chart.yaml",
                suggestion=f"Add 'repository' URL for '{dep_name}' (e.g., 'https://charts.bitnami.com/bitnami')",
            ))
        elif repo.startswith("file://"):
            issues.append(Issue(
                rule_id="HD-D009",
                severity=Severity.INFO,
                category=Category.DEPENDENCIES,
                message=f"Dependency '{dep_name}' uses a local file:// repository",
                file_path="Chart.yaml",
                suggestion="Ensure the local chart path exists and is valid for CI/CD builds",
            ))

        # Rule HD-D010: duplicate dependency names
        if dep_name in seen_names:
            issues.append(Issue(
                rule_id="HD-D010",
                severity=Severity.HIGH,
                category=Category.DEPENDENCIES,
                message=f"Duplicate dependency name: '{dep_name}'",
                file_path="Chart.yaml",
                suggestion=f"Use 'alias' field to differentiate multiple instances of '{dep_name}'",
            ))
        seen_names.add(dep_name)

        # Rule HD-D011: alias recommended for common charts
        if dep_name in ("postgresql", "redis", "mysql", "mongodb", "elasticsearch", "rabbitmq", "kafka"):
            if not dep.get("alias"):
                issues.append(Issue(
                    rule_id="HD-D011",
                    severity=Severity.INFO,
                    category=Category.DEPENDENCIES,
                    message=f"Consider adding an alias for common dependency '{dep_name}'",
                    file_path="Chart.yaml",
                    suggestion=f"Add 'alias: myApp{dep_name.capitalize()}' for clarity when multiple charts use '{dep_name}'",
                ))

        # Rule HD-D012: condition should be set for optional deps
        if not dep.get("condition") and not dep.get("tags"):
            issues.append(Issue(
                rule_id="HD-D012",
                severity=Severity.LOW,
                category=Category.DEPENDENCIES,
                message=f"Dependency '{dep_name}' has no 'condition' or 'tags' for toggling",
                file_path="Chart.yaml",
                suggestion=f"Add 'condition: {dep_name}.enabled' so users can disable it via values.yaml",
                doc_url="https://helm.sh/docs/topics/charts/#tags-and-condition-fields-in-dependencies",
            ))

    return issues
