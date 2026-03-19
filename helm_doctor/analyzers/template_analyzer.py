"""Template analyzer — validates Helm templates for best practices and common errors."""
import os
import re

from helm_doctor.models import Category, Issue, Severity

# Template function patterns
DEPRECATED_FUNCTIONS = {
    ".Capabilities.KubeVersion.GitVersion": "Use .Capabilities.KubeVersion.Version instead",
    "template": "Use 'include' instead of 'template' for composability (include allows piping)",
}

# Dangerous template patterns
DANGEROUS_PATTERNS = [
    (re.compile(r"\{\{-?\s*\.Values\.\w+\s*-?\}\}(?!\s*\|)"), "HD-T010",
     "Unquoted .Values reference — use 'quote' or 'toYaml' pipe to prevent injection",
     Severity.MEDIUM),
]

# Required template best practices
REQUIRED_LABELS_PATTERNS = [
    "app.kubernetes.io/name",
    "app.kubernetes.io/instance",
    "app.kubernetes.io/version",
    "app.kubernetes.io/managed-by",
]

# Namespace hardcoding pattern
HARDCODED_NAMESPACE_RE = re.compile(r"namespace:\s+[a-z][a-z0-9\-]+\s*$", re.MULTILINE)

# Image tag pattern
IMAGE_LATEST_RE = re.compile(r"image:\s*[\"']?[\w\-\.\/]+:latest[\"']?\s*$", re.MULTILINE)

# Resource kind pattern
RESOURCE_KIND_RE = re.compile(r"^kind:\s*(\w+)", re.MULTILINE)

# Template define pattern
TEMPLATE_DEFINE_RE = re.compile(r'\{\{-?\s*define\s+"([^"]+)"')

# Template usage pattern (include/template)
TEMPLATE_USAGE_RE = re.compile(r'\{\{-?\s*(?:include|template)\s+"([^"]+)"')

# .Release.Namespace usage
RELEASE_NS_RE = re.compile(r"\.Release\.Namespace")

# Helm hook pattern
HELM_HOOK_RE = re.compile(r'"helm\.sh/hook"')

# Resource limits in template
RESOURCES_SECTION_RE = re.compile(r"resources:", re.MULTILINE)

# toYaml with nindent/indent pattern
TOYAML_RE = re.compile(r"toYaml\s+\.\w+.*\|\s*(?:nindent|indent)")

# Common Helm template files
EXPECTED_HELPERS = ["_helpers.tpl"]


def analyze_templates(chart_path: str) -> list:
    """Run all template rules and return issues."""
    templates_dir = os.path.join(chart_path, "templates")
    issues = []

    # Rule HD-T001: templates directory should exist
    if not os.path.isdir(templates_dir):
        issues.append(Issue(
            rule_id="HD-T001",
            severity=Severity.HIGH,
            category=Category.CHART_STRUCTURE,
            message="templates/ directory is missing",
            file_path="templates/",
            suggestion="Create a templates/ directory with your Kubernetes manifests",
            doc_url="https://helm.sh/docs/chart_template_guide/getting_started/",
        ))
        return issues

    # Collect template files
    template_files = []
    for root, _, files in os.walk(templates_dir):
        for f in files:
            if f.endswith((".yaml", ".yml", ".tpl")):
                full_path = os.path.join(root, f)
                rel_path = os.path.relpath(full_path, chart_path)
                template_files.append((full_path, rel_path, f))

    # Rule HD-T002: templates directory should not be empty
    if not template_files:
        issues.append(Issue(
            rule_id="HD-T002",
            severity=Severity.HIGH,
            category=Category.CHART_STRUCTURE,
            message="templates/ directory contains no YAML or TPL files",
            file_path="templates/",
            suggestion="Add Kubernetes resource templates (.yaml) and helper templates (.tpl)",
        ))
        return issues

    # Rule HD-T003: _helpers.tpl should exist
    has_helpers = any(f == "_helpers.tpl" for _, _, f in template_files)
    if not has_helpers:
        issues.append(Issue(
            rule_id="HD-T003",
            severity=Severity.MEDIUM,
            category=Category.TEMPLATES,
            message="_helpers.tpl is missing — no reusable template definitions found",
            file_path="templates/",
            suggestion="Create templates/_helpers.tpl with common labels, names, and selector helpers",
            doc_url="https://helm.sh/docs/chart_template_guide/named_templates/",
        ))

    # Rule HD-T004: NOTES.txt should exist
    notes_path = os.path.join(templates_dir, "NOTES.txt")
    if not os.path.isfile(notes_path):
        issues.append(Issue(
            rule_id="HD-T004",
            severity=Severity.LOW,
            category=Category.DOCUMENTATION,
            message="templates/NOTES.txt is missing — no post-install notes for users",
            file_path="templates/NOTES.txt",
            suggestion="Create NOTES.txt with helpful post-install instructions (connection info, next steps)",
            doc_url="https://helm.sh/docs/chart_template_guide/notes_files/",
        ))

    # Rule HD-T005: tests directory
    tests_dir = os.path.join(templates_dir, "tests")
    if not os.path.isdir(tests_dir):
        issues.append(Issue(
            rule_id="HD-T005",
            severity=Severity.LOW,
            category=Category.BEST_PRACTICES,
            message="No test templates found (templates/tests/)",
            file_path="templates/tests/",
            suggestion="Add Helm chart tests (e.g., connection test pod) in templates/tests/",
            doc_url="https://helm.sh/docs/topics/chart_tests/",
        ))

    # Track defined/used templates for orphan detection
    defined_templates = set()
    used_templates = set()
    resource_types = []

    # Analyze each template file
    for full_path, rel_path, filename in template_files:
        try:
            with open(full_path, "r", encoding="utf-8") as f:
                content = f.read()
        except Exception:
            continue

        lines = content.split("\n")

        # Collect defined templates
        for m in TEMPLATE_DEFINE_RE.finditer(content):
            defined_templates.add(m.group(1))

        # Collect used templates
        for m in TEMPLATE_USAGE_RE.finditer(content):
            used_templates.add(m.group(1))

        # Collect resource types
        for m in RESOURCE_KIND_RE.finditer(content):
            resource_types.append(m.group(1))

        # Skip .tpl files for manifest-specific checks
        if filename.endswith(".tpl"):
            continue

        # Rule HD-T006: Hardcoded namespaces
        for match in HARDCODED_NAMESPACE_RE.finditer(content):
            ns_value = match.group(0).split(":")[1].strip()
            if not ns_value.startswith("{{"):
                line_num = content[:match.start()].count("\n") + 1
                issues.append(Issue(
                    rule_id="HD-T006",
                    severity=Severity.HIGH,
                    category=Category.TEMPLATES,
                    message=f"Hardcoded namespace '{ns_value}' — use .Release.Namespace instead",
                    file_path=rel_path,
                    line=line_num,
                    suggestion="Replace hardcoded namespace with {{ .Release.Namespace }}",
                    doc_url="https://helm.sh/docs/chart_best_practices/templates/#namespace",
                ))

        # Rule HD-T007: image:latest in templates
        for match in IMAGE_LATEST_RE.finditer(content):
            line_num = content[:match.start()].count("\n") + 1
            issues.append(Issue(
                rule_id="HD-T007",
                severity=Severity.HIGH,
                category=Category.BEST_PRACTICES,
                message="Hardcoded image tag 'latest' found in template",
                file_path=rel_path,
                line=line_num,
                suggestion="Use .Values.image.tag or .Chart.AppVersion for image tags",
            ))

        # Rule HD-T008: Deprecated template functions
        for deprecated, suggestion in DEPRECATED_FUNCTIONS.items():
            if deprecated in content:
                idx = content.index(deprecated)
                line_num = content[:idx].count("\n") + 1
                issues.append(Issue(
                    rule_id="HD-T008",
                    severity=Severity.MEDIUM,
                    category=Category.TEMPLATES,
                    message=f"Deprecated function/field: '{deprecated}'",
                    file_path=rel_path,
                    line=line_num,
                    suggestion=suggestion,
                ))

        # Rule HD-T009: Check for recommended labels
        if RESOURCE_KIND_RE.search(content):
            for label in REQUIRED_LABELS_PATTERNS:
                if label not in content:
                    issues.append(Issue(
                        rule_id="HD-T009",
                        severity=Severity.LOW,
                        category=Category.BEST_PRACTICES,
                        message=f"Recommended label '{label}' not found in {filename}",
                        file_path=rel_path,
                        suggestion=f"Add '{label}' label using include helper from _helpers.tpl",
                        doc_url="https://helm.sh/docs/chart_best_practices/labels/",
                    ))
                    break  # Only report once per file

        # Rule HD-T011: Check for 'helm.sh/resource-policy' on PVCs
        if "kind: PersistentVolumeClaim" in content:
            if "helm.sh/resource-policy" not in content:
                issues.append(Issue(
                    rule_id="HD-T011",
                    severity=Severity.MEDIUM,
                    category=Category.RELIABILITY,
                    message="PVC without 'helm.sh/resource-policy: keep' annotation",
                    file_path=rel_path,
                    suggestion="Add 'helm.sh/resource-policy: keep' annotation to prevent PVC deletion on helm uninstall",
                ))

        # Rule HD-T012: Check for proper hook-delete-policy
        if HELM_HOOK_RE.search(content):
            if "hook-delete-policy" not in content:
                issues.append(Issue(
                    rule_id="HD-T012",
                    severity=Severity.MEDIUM,
                    category=Category.BEST_PRACTICES,
                    message="Helm hook without hook-delete-policy annotation",
                    file_path=rel_path,
                    suggestion="Add 'helm.sh/hook-delete-policy' to clean up hook resources automatically",
                ))

        # Rule HD-T013: Check for container resource references
        if "kind: Deployment" in content or "kind: StatefulSet" in content or "kind: DaemonSet" in content:
            if not RESOURCES_SECTION_RE.search(content):
                issues.append(Issue(
                    rule_id="HD-T013",
                    severity=Severity.HIGH,
                    category=Category.RESOURCE_MANAGEMENT,
                    message=f"Workload in {filename} has no resources section",
                    file_path=rel_path,
                    suggestion="Add resources section with toYaml pipe: {{ toYaml .Values.resources | nindent 12 }}",
                ))

        # Rule HD-T014: Check for service account reference
        if "kind: Deployment" in content or "kind: StatefulSet" in content:
            if "serviceAccountName" not in content:
                issues.append(Issue(
                    rule_id="HD-T014",
                    severity=Severity.LOW,
                    category=Category.SECURITY,
                    message=f"Workload in {filename} doesn't reference a ServiceAccount",
                    file_path=rel_path,
                    suggestion="Add serviceAccountName to the pod spec for RBAC best practices",
                ))

        # Rule HD-T015: Empty template check
        stripped = content.strip()
        if not stripped or all(l.strip().startswith("#") or l.strip().startswith("{{-") for l in lines if l.strip()):
            if not filename.startswith("_") and not filename == "NOTES.txt":
                issues.append(Issue(
                    rule_id="HD-T015",
                    severity=Severity.LOW,
                    category=Category.TEMPLATES,
                    message=f"Template {filename} appears to be empty or only contains comments/conditionals",
                    file_path=rel_path,
                    suggestion="Remove empty templates or add Kubernetes resources",
                ))

        # Rule HD-T016: Check for {{- with nindent consistency
        if "toYaml" in content and "nindent" not in content and "indent" not in content:
            issues.append(Issue(
                rule_id="HD-T016",
                severity=Severity.MEDIUM,
                category=Category.TEMPLATES,
                message=f"toYaml used without nindent/indent in {filename} — may cause indentation issues",
                file_path=rel_path,
                suggestion="Use '| nindent N' after toYaml to ensure proper YAML indentation",
            ))

    # Rule HD-T017: Orphaned template definitions
    orphaned = defined_templates - used_templates
    for tmpl in orphaned:
        issues.append(Issue(
            rule_id="HD-T017",
            severity=Severity.LOW,
            category=Category.TEMPLATES,
            message=f"Template '{tmpl}' is defined but never used",
            file_path="templates/_helpers.tpl",
            suggestion=f"Remove unused template '{tmpl}' or use it in a manifest",
        ))

    return issues


def count_template_rules() -> int:
    """Return the number of template rules."""
    return 17
