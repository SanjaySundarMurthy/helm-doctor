"""Security analyzer — deep security scanning for Helm charts."""
import os
import re

import yaml

from helm_doctor.models import Category, Issue, Severity


# Dangerous Kubernetes resource types
SENSITIVE_RESOURCES = {
    "ClusterRole": "cluster-wide RBAC role",
    "ClusterRoleBinding": "cluster-wide RBAC binding",
    "PodSecurityPolicy": "pod security policy (deprecated in K8s 1.25+)",
}

# Dangerous RBAC verbs
DANGEROUS_VERBS = {"*", "create", "delete", "patch", "update"}
DANGEROUS_RESOURCES_RBAC = {"secrets", "configmaps", "*"}

# Security-sensitive annotations/labels
SECURITY_ANNOTATIONS = {
    "seccomp.security.alpha.kubernetes.io/defaultProfileName": "Seccomp profile",
    "container.apparmor.security.beta.kubernetes.io": "AppArmor profile",
}

# Capabilities patterns
DANGEROUS_CAPABILITIES = {
    "SYS_ADMIN", "NET_ADMIN", "ALL", "SYS_PTRACE",
    "NET_RAW", "SYS_MODULE", "SYS_RAWIO",
}

# hostPath pattern
HOST_PATH_RE = re.compile(r"hostPath:", re.MULTILINE)

# hostNetwork/hostPID/hostIPC patterns
HOST_NAMESPACE_RE = re.compile(r"(hostNetwork|hostPID|hostIPC):\s*true", re.MULTILINE)

# Privileged container pattern
PRIVILEGED_RE = re.compile(r"privileged:\s*true", re.MULTILINE)

# Run as root pattern
RUN_AS_ROOT_RE = re.compile(r"runAsUser:\s*0", re.MULTILINE)

# automountServiceAccountToken
AUTOMOUNT_RE = re.compile(r"automountServiceAccountToken:\s*true", re.MULTILINE)


def analyze_security(chart_path: str) -> list:
    """Run all security rules and return issues."""
    templates_dir = os.path.join(chart_path, "templates")
    issues = []

    if not os.path.isdir(templates_dir):
        return issues

    # Also check values.yaml for security config
    _check_values_security(chart_path, issues)

    # Scan all template files
    for root, _, files in os.walk(templates_dir):
        for f in files:
            if not f.endswith((".yaml", ".yml")):
                continue

            full_path = os.path.join(root, f)
            rel_path = os.path.relpath(full_path, chart_path)

            try:
                with open(full_path, "r", encoding="utf-8") as fh:
                    content = fh.read()
            except Exception:
                continue

            _check_privileged_containers(content, rel_path, issues)
            _check_host_namespaces(content, rel_path, issues)
            _check_host_path_volumes(content, rel_path, issues)
            _check_run_as_root(content, rel_path, issues)
            _check_dangerous_capabilities(content, rel_path, issues)
            _check_rbac_rules(content, rel_path, issues)
            _check_sensitive_resources(content, rel_path, issues)
            _check_automount_token(content, rel_path, issues)
            _check_network_policies(content, rel_path, issues)

    # Check for NetworkPolicy existence
    _check_network_policy_exists(templates_dir, chart_path, issues)

    # Check for PodDisruptionBudget
    _check_pdb_exists(templates_dir, chart_path, issues)

    return issues


def _check_values_security(chart_path: str, issues: list):
    """Check security settings in values.yaml."""
    values_path = os.path.join(chart_path, "values.yaml")
    if not os.path.isfile(values_path):
        return

    try:
        with open(values_path, "r", encoding="utf-8") as f:
            values = yaml.safe_load(f) or {}
    except Exception:
        return

    if not isinstance(values, dict):
        return

    # Rule HD-S001: Check for default passwords
    _scan_for_default_passwords(values, "", issues)


def _scan_for_default_passwords(data: dict, prefix: str, issues: list):
    """Recursively scan for default/weak passwords in values."""
    weak_passwords = {"admin", "password", "123456", "root", "default", "changeme", "test"}

    for key, val in data.items():
        full_key = f"{prefix}.{key}" if prefix else key
        if isinstance(val, str) and val.lower() in weak_passwords:
            if any(kw in key.lower() for kw in ("password", "secret", "token", "key")):
                issues.append(Issue(
                    rule_id="HD-S001",
                    severity=Severity.CRITICAL,
                    category=Category.SECURITY,
                    message=f"Weak/default credential detected at '{full_key}'",
                    file_path="values.yaml",
                    suggestion="Never use default passwords. Use Kubernetes Secrets with external secret management",
                ))
        if isinstance(val, dict) and prefix.count(".") < 4:
            _scan_for_default_passwords(val, full_key, issues)


def _check_privileged_containers(content: str, rel_path: str, issues: list):
    """Rule HD-S002: Check for privileged containers."""
    for match in PRIVILEGED_RE.finditer(content):
        # Ensure it's not inside a comment or conditional that disables it
        context_start = max(0, match.start() - 200)
        context = content[context_start:match.start()]
        if "{{- if" in context and "false" in context:
            continue

        line_num = content[:match.start()].count("\n") + 1
        issues.append(Issue(
            rule_id="HD-S002",
            severity=Severity.CRITICAL,
            category=Category.SECURITY,
            message="Privileged container detected — full host access granted",
            file_path=rel_path,
            line=line_num,
            suggestion="Remove 'privileged: true'. Use specific Linux capabilities instead",
            doc_url="https://kubernetes.io/docs/concepts/security/pod-security-standards/",
        ))


def _check_host_namespaces(content: str, rel_path: str, issues: list):
    """Rule HD-S003: Check for host namespace sharing."""
    for match in HOST_NAMESPACE_RE.finditer(content):
        ns_type = match.group(1)
        line_num = content[:match.start()].count("\n") + 1
        issues.append(Issue(
            rule_id="HD-S003",
            severity=Severity.HIGH,
            category=Category.SECURITY,
            message=f"{ns_type}: true — pod shares host {ns_type.replace('host', '')} namespace",
            file_path=rel_path,
            line=line_num,
            suggestion=f"Remove '{ns_type}: true' unless absolutely required (e.g., monitoring agents)",
        ))


def _check_host_path_volumes(content: str, rel_path: str, issues: list):
    """Rule HD-S004: Check for hostPath volumes."""
    for match in HOST_PATH_RE.finditer(content):
        line_num = content[:match.start()].count("\n") + 1
        issues.append(Issue(
            rule_id="HD-S004",
            severity=Severity.HIGH,
            category=Category.SECURITY,
            message="hostPath volume mount detected — allows access to host filesystem",
            file_path=rel_path,
            line=line_num,
            suggestion="Use PersistentVolumeClaims or emptyDir instead of hostPath volumes",
            doc_url="https://kubernetes.io/docs/concepts/storage/volumes/#hostpath",
        ))


def _check_run_as_root(content: str, rel_path: str, issues: list):
    """Rule HD-S005: Check for running as root (UID 0)."""
    for match in RUN_AS_ROOT_RE.finditer(content):
        line_num = content[:match.start()].count("\n") + 1
        issues.append(Issue(
            rule_id="HD-S005",
            severity=Severity.HIGH,
            category=Category.SECURITY,
            message="Container configured to run as root (runAsUser: 0)",
            file_path=rel_path,
            line=line_num,
            suggestion="Set runAsUser to a non-root UID (e.g., 1000) and runAsNonRoot: true",
            doc_url="https://kubernetes.io/docs/tasks/configure-pod-container/security-context/",
        ))


def _check_dangerous_capabilities(content: str, rel_path: str, issues: list):
    """Rule HD-S006: Check for dangerous Linux capabilities."""
    cap_pattern = re.compile(r"capabilities:\s*\n\s*add:\s*\n((?:\s*-\s*\w+\n)+)", re.MULTILINE)
    for match in cap_pattern.finditer(content):
        caps_block = match.group(1)
        caps = re.findall(r"-\s*(\w+)", caps_block)
        for cap in caps:
            if cap.upper() in DANGEROUS_CAPABILITIES:
                line_num = content[:match.start()].count("\n") + 1
                sev = Severity.CRITICAL if cap.upper() in ("SYS_ADMIN", "ALL") else Severity.HIGH
                issues.append(Issue(
                    rule_id="HD-S006",
                    severity=sev,
                    category=Category.SECURITY,
                    message=f"Dangerous capability '{cap}' added to container",
                    file_path=rel_path,
                    line=line_num,
                    suggestion=f"Remove '{cap}' capability. Use the minimum required capabilities only",
                ))


def _check_rbac_rules(content: str, rel_path: str, issues: list):
    """Rule HD-S007: Check for overly permissive RBAC rules."""
    if "kind: ClusterRole" not in content and "kind: Role" not in content:
        return

    # Check for wildcard permissions
    rules_pattern = re.compile(
        r"rules:\s*\n((?:\s*-.*\n)*)",
        re.MULTILINE,
    )
    for match in rules_pattern.finditer(content):
        rules_block = match.group(1)
        if '"*"' in rules_block or "'*'" in rules_block or "- '*'" in rules_block:
            line_num = content[:match.start()].count("\n") + 1
            issues.append(Issue(
                rule_id="HD-S007",
                severity=Severity.CRITICAL,
                category=Category.SECURITY,
                message="Wildcard (*) RBAC permissions detected — grants access to all resources/verbs",
                file_path=rel_path,
                line=line_num,
                suggestion="Follow principle of least privilege. Specify exact resources and verbs needed",
                doc_url="https://kubernetes.io/docs/reference/access-authn-authz/rbac/",
            ))


def _check_sensitive_resources(content: str, rel_path: str, issues: list):
    """Rule HD-S008: Check for sensitive resource types."""
    for resource, desc in SENSITIVE_RESOURCES.items():
        pattern = re.compile(rf"kind:\s*{resource}", re.MULTILINE)
        if pattern.search(content):
            issues.append(Issue(
                rule_id="HD-S008",
                severity=Severity.MEDIUM,
                category=Category.SECURITY,
                message=f"Contains {desc} ({resource}) — review permissions carefully",
                file_path=rel_path,
                suggestion=f"Ensure {resource} follows least-privilege principle and is documented",
            ))


def _check_automount_token(content: str, rel_path: str, issues: list):
    """Rule HD-S009: Check automountServiceAccountToken."""
    for match in AUTOMOUNT_RE.finditer(content):
        line_num = content[:match.start()].count("\n") + 1
        issues.append(Issue(
            rule_id="HD-S009",
            severity=Severity.MEDIUM,
            category=Category.SECURITY,
            message="automountServiceAccountToken is explicitly set to true",
            file_path=rel_path,
            line=line_num,
            suggestion="Set automountServiceAccountToken: false unless the pod needs Kubernetes API access",
        ))


def _check_network_policies(content: str, rel_path: str, issues: list):
    """Rule HD-S010: Validate NetworkPolicy configuration."""
    if "kind: NetworkPolicy" not in content:
        return

    # Check for empty ingress/egress (allows all)
    if "ingress: []" in content or "egress: []" in content:
        issues.append(Issue(
            rule_id="HD-S010",
            severity=Severity.MEDIUM,
            category=Category.SECURITY,
            message="NetworkPolicy with empty ingress/egress rules — this denies all traffic",
            file_path=rel_path,
            suggestion="Define specific ingress/egress rules or remove the empty array to use default behavior",
        ))


def _check_network_policy_exists(templates_dir: str, chart_path: str, issues: list):
    """Rule HD-S011: Check if NetworkPolicy is defined."""
    has_netpol = False
    for root, _, files in os.walk(templates_dir):
        for f in files:
            if not f.endswith((".yaml", ".yml")):
                continue
            try:
                full_path = os.path.join(root, f)
                with open(full_path, "r", encoding="utf-8") as fh:
                    if "kind: NetworkPolicy" in fh.read():
                        has_netpol = True
                        break
            except Exception:
                continue
        if has_netpol:
            break

    if not has_netpol:
        issues.append(Issue(
            rule_id="HD-S011",
            severity=Severity.MEDIUM,
            category=Category.SECURITY,
            message="No NetworkPolicy template found — pods are not network-isolated",
            file_path="templates/",
            suggestion="Add a NetworkPolicy template to restrict pod-to-pod and external traffic",
            doc_url="https://kubernetes.io/docs/concepts/services-networking/network-policies/",
        ))


def _check_pdb_exists(templates_dir: str, chart_path: str, issues: list):
    """Rule HD-S012: Check if PodDisruptionBudget is defined."""
    has_pdb = False
    for root, _, files in os.walk(templates_dir):
        for f in files:
            if not f.endswith((".yaml", ".yml")):
                continue
            try:
                full_path = os.path.join(root, f)
                with open(full_path, "r", encoding="utf-8") as fh:
                    if "kind: PodDisruptionBudget" in fh.read():
                        has_pdb = True
                        break
            except Exception:
                continue
        if has_pdb:
            break

    if not has_pdb:
        issues.append(Issue(
            rule_id="HD-S012",
            severity=Severity.LOW,
            category=Category.RELIABILITY,
            message="No PodDisruptionBudget template found",
            file_path="templates/",
            suggestion="Add a PodDisruptionBudget to ensure minimum availability during node drains and upgrades",
            doc_url="https://kubernetes.io/docs/tasks/run-application/configure-pdb/",
        ))
