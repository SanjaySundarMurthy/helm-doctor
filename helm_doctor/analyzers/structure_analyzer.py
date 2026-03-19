"""Structure analyzer — validates overall chart directory structure."""
import os

from helm_doctor.models import Category, Issue, Severity

# Expected files/directories in a well-structured Helm chart
EXPECTED_FILES = {
    "Chart.yaml": (True, Severity.CRITICAL, "Required Helm chart metadata file"),
    "values.yaml": (True, Severity.MEDIUM, "Default values file"),
    "templates/": (True, Severity.HIGH, "Template directory for Kubernetes manifests"),
    ".helmignore": (False, Severity.LOW, "Helm ignore file (like .gitignore)"),
    "README.md": (False, Severity.LOW, "Chart documentation"),
    "LICENSE": (False, Severity.INFO, "License file"),
    "values.schema.json": (False, Severity.INFO, "JSON schema for values validation"),
}

# Files that should NOT be in the chart
FORBIDDEN_FILES = [
    ".env",
    "*.pem",
    "*.key",
    "*.p12",
    "*.pfx",
    "*.jks",
    "id_rsa",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
]

# Maximum chart size (unpackaged) in MB
MAX_CHART_SIZE_MB = 50


def analyze_structure(chart_path: str) -> list:
    """Run all structure rules and return issues."""
    issues = []

    # Rule HD-X001: Verify it's a Helm chart
    if not os.path.isfile(os.path.join(chart_path, "Chart.yaml")):
        issues.append(Issue(
            rule_id="HD-X001",
            severity=Severity.CRITICAL,
            category=Category.CHART_STRUCTURE,
            message="Not a valid Helm chart — Chart.yaml is missing",
            file_path=".",
            suggestion="Ensure you're pointing to a valid Helm chart directory",
        ))
        return issues

    # Check expected files
    for name, (required, severity, desc) in EXPECTED_FILES.items():
        target = os.path.join(chart_path, name)
        exists = os.path.exists(target)
        if not exists and not required:
            issues.append(Issue(
                rule_id="HD-X002",
                severity=severity,
                category=Category.CHART_STRUCTURE,
                message=f"Recommended file/directory missing: {name}",
                file_path=name,
                suggestion=f"Add {name} — {desc}",
            ))

    # Rule HD-X003: .helmignore should exist
    helmignore_path = os.path.join(chart_path, ".helmignore")
    if not os.path.isfile(helmignore_path):
        issues.append(Issue(
            rule_id="HD-X003",
            severity=Severity.LOW,
            category=Category.CHART_STRUCTURE,
            message=".helmignore file is missing",
            file_path=".helmignore",
            suggestion="Add .helmignore to exclude unnecessary files from the chart package (tests, docs, CI configs)",
            doc_url="https://helm.sh/docs/chart_template_guide/helm_ignore_file/",
        ))

    # Rule HD-X004: values.schema.json for validation
    schema_path = os.path.join(chart_path, "values.schema.json")
    if not os.path.isfile(schema_path):
        issues.append(Issue(
            rule_id="HD-X004",
            severity=Severity.INFO,
            category=Category.VALUES,
            message="values.schema.json is not present — no automatic values validation",
            file_path="values.schema.json",
            suggestion="Add values.schema.json to validate user-supplied values during helm install/upgrade",
            doc_url="https://helm.sh/docs/topics/charts/#schema-files",
        ))

    # Rule HD-X005: Check for forbidden/sensitive files
    for root, _, files in os.walk(chart_path):
        for f in files:
            rel = os.path.relpath(os.path.join(root, f), chart_path)
            for pattern in FORBIDDEN_FILES:
                if pattern.startswith("*"):
                    if f.endswith(pattern[1:]):
                        issues.append(Issue(
                            rule_id="HD-X005",
                            severity=Severity.CRITICAL,
                            category=Category.SECURITY,
                            message=f"Sensitive file found in chart: {rel}",
                            file_path=rel,
                            suggestion=f"Remove '{rel}' from the chart and add the pattern to .helmignore",
                        ))
                elif f == pattern:
                    issues.append(Issue(
                        rule_id="HD-X005",
                        severity=Severity.CRITICAL,
                        category=Category.SECURITY,
                        message=f"Sensitive file found in chart: {rel}",
                        file_path=rel,
                        suggestion=f"Remove '{rel}' from the chart and add it to .helmignore",
                    ))

    # Rule HD-X006: Check total chart size
    total_size = 0
    for root, _, files in os.walk(chart_path):
        for f in files:
            try:
                total_size += os.path.getsize(os.path.join(root, f))
            except OSError:
                pass

    size_mb = total_size / (1024 * 1024)
    if size_mb > MAX_CHART_SIZE_MB:
        issues.append(Issue(
            rule_id="HD-X006",
            severity=Severity.HIGH,
            category=Category.CHART_STRUCTURE,
            message=f"Chart size ({size_mb:.1f} MB) exceeds {MAX_CHART_SIZE_MB} MB — too large",
            file_path=".",
            suggestion="Use .helmignore to exclude large files. Check for accidentally included binaries or data",
        ))
    elif size_mb > 10:
        issues.append(Issue(
            rule_id="HD-X006",
            severity=Severity.MEDIUM,
            category=Category.CHART_STRUCTURE,
            message=f"Chart size ({size_mb:.1f} MB) is large — consider reducing",
            file_path=".",
            suggestion="Review chart contents for unnecessary files. Use .helmignore liberally",
        ))

    # Rule HD-X007: Check for crds/ directory usage
    crds_dir = os.path.join(chart_path, "crds")
    templates_dir = os.path.join(chart_path, "templates")

    if os.path.isdir(templates_dir):
        for root, _, files in os.walk(templates_dir):
            for f in files:
                if f.endswith((".yaml", ".yml")):
                    try:
                        full_path = os.path.join(root, f)
                        with open(full_path, "r", encoding="utf-8") as fh:
                            content = fh.read()
                        if "kind: CustomResourceDefinition" in content:
                            issues.append(Issue(
                                rule_id="HD-X007",
                                severity=Severity.MEDIUM,
                                category=Category.BEST_PRACTICES,
                                message=f"CRD found in templates/ ({f}) — should be in crds/ directory",
                                file_path=os.path.relpath(full_path, chart_path),
                                suggestion="Move CRDs to the crds/ directory for proper lifecycle management",
                                doc_url="https://helm.sh/docs/chart_best_practices/custom_resource_definitions/",
                            ))
                    except Exception:
                        pass

    return issues
