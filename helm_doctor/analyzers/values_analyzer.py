"""Values.yaml analyzer — validates values structure, naming, and best practices."""
import os
import re

import yaml

from helm_doctor.models import Category, Issue, Severity

# Reserved top-level keys in Helm
HELM_RESERVED_KEYS = {
    "replicaCount", "image", "imagePullSecrets", "nameOverride",
    "fullnameOverride", "serviceAccount", "podAnnotations",
    "podSecurityContext", "securityContext", "service", "ingress",
    "resources", "autoscaling", "nodeSelector", "tolerations",
    "affinity",
}

# Common value patterns that indicate hardcoded secrets
SECRET_PATTERNS = [
    (re.compile(r"password", re.IGNORECASE), "password"),
    (re.compile(r"secret", re.IGNORECASE), "secret"),
    (re.compile(r"api[_-]?key", re.IGNORECASE), "API key"),
    (re.compile(r"token", re.IGNORECASE), "token"),
    (re.compile(r"private[_-]?key", re.IGNORECASE), "private key"),
    (re.compile(r"access[_-]?key", re.IGNORECASE), "access key"),
    (re.compile(r"secret[_-]?key", re.IGNORECASE), "secret key"),
    (re.compile(r"connection[_-]?string", re.IGNORECASE), "connection string"),
]

# camelCase check
CAMEL_CASE_RE = re.compile(r"^[a-z][a-zA-Z0-9]*$")


def analyze_values_yaml(chart_path: str) -> list:
    """Run all values.yaml rules and return issues."""
    values_path = os.path.join(chart_path, "values.yaml")
    issues = []

    # Rule HD-V001: values.yaml should exist
    if not os.path.isfile(values_path):
        issues.append(Issue(
            rule_id="HD-V001",
            severity=Severity.MEDIUM,
            category=Category.VALUES,
            message="values.yaml file is missing",
            file_path="values.yaml",
            suggestion="Create a values.yaml file with sensible defaults for all configurable values",
            doc_url="https://helm.sh/docs/chart_best_practices/values/",
        ))
        return issues

    try:
        with open(values_path, "r", encoding="utf-8") as f:
            raw_content = f.read()
        values = yaml.safe_load(raw_content)
    except yaml.YAMLError as e:
        issues.append(Issue(
            rule_id="HD-V002",
            severity=Severity.CRITICAL,
            category=Category.VALUES,
            message=f"values.yaml has invalid YAML syntax: {e}",
            file_path="values.yaml",
            suggestion="Fix the YAML syntax errors in values.yaml",
        ))
        return issues

    if values is None:
        issues.append(Issue(
            rule_id="HD-V003",
            severity=Severity.LOW,
            category=Category.VALUES,
            message="values.yaml is empty",
            file_path="values.yaml",
            suggestion="Add default configuration values even if the chart works without them",
        ))
        return issues

    if not isinstance(values, dict):
        issues.append(Issue(
            rule_id="HD-V004",
            severity=Severity.HIGH,
            category=Category.VALUES,
            message="values.yaml root must be a YAML mapping (key-value pairs)",
            file_path="values.yaml",
            suggestion="Ensure values.yaml contains a YAML dictionary, not a list or scalar",
        ))
        return issues

    # Analyze the values structure
    _check_naming_conventions(values, "", issues)
    _check_image_config(values, issues)
    _check_resources(values, issues)
    _check_service_config(values, issues)
    _check_ingress_config(values, issues)
    _check_security_context(values, issues)
    _check_probes(values, issues)
    _check_autoscaling(values, issues)
    _check_service_account(values, issues)
    _check_hardcoded_secrets(values, "", issues)
    _check_replica_count(values, issues)
    _check_node_scheduling(values, issues)

    # Rule HD-V030: Check for comments/documentation
    lines = raw_content.split("\n")
    comment_count = sum(1 for line in lines if line.strip().startswith("#"))
    total_lines = len([line for line in lines if line.strip()])
    if total_lines > 10 and comment_count < 3:
        issues.append(Issue(
            rule_id="HD-V030",
            severity=Severity.LOW,
            category=Category.DOCUMENTATION,
            message="values.yaml has very few comments — consider documenting configurable values",
            file_path="values.yaml",
            suggestion="Add comments above each section explaining what the values configure",
            doc_url="https://helm.sh/docs/chart_best_practices/values/#document-valuesyaml",
        ))

    return issues


def _check_naming_conventions(values: dict, prefix: str, issues: list):
    """HD-V005: Check that keys use camelCase."""
    for key in values:
        full_key = f"{prefix}.{key}" if prefix else key
        if not CAMEL_CASE_RE.match(str(key)):
            # Skip known patterns like 'pod-annotations' which some charts use
            if "_" in str(key):
                issues.append(Issue(
                    rule_id="HD-V005",
                    severity=Severity.LOW,
                    category=Category.VALUES,
                    message=f"Value key '{full_key}' uses snake_case. Helm convention is camelCase",
                    file_path="values.yaml",
                    suggestion=f"Rename '{key}' to camelCase (e.g., '{_to_camel_case(key)}')",
                    doc_url="https://helm.sh/docs/chart_best_practices/values/#naming-conventions",
                ))

        # Recurse into nested dicts (limit depth)
        if isinstance(values[key], dict) and prefix.count(".") < 4:
            _check_naming_conventions(values[key], full_key, issues)


def _check_image_config(values: dict, issues: list):
    """Check image configuration best practices."""
    image = values.get("image", {})
    if not isinstance(image, dict):
        return

    # Rule HD-V006: image.repository should be set
    if not image.get("repository"):
        issues.append(Issue(
            rule_id="HD-V006",
            severity=Severity.HIGH,
            category=Category.VALUES,
            message="image.repository is not set in values.yaml",
            file_path="values.yaml",
            suggestion="Set image.repository to the default container image (e.g., 'nginx')",
        ))

    # Rule HD-V007: image.tag should not be 'latest'
    tag = str(image.get("tag", ""))
    if tag.lower() == "latest":
        issues.append(Issue(
            rule_id="HD-V007",
            severity=Severity.HIGH,
            category=Category.BEST_PRACTICES,
            message="image.tag is set to 'latest' — this is non-deterministic and can cause deployment issues",
            file_path="values.yaml",
            suggestion="Use a specific version tag (e.g., '1.25.3') or use .Chart.AppVersion",
            doc_url="https://helm.sh/docs/chart_best_practices/pods/#images",
        ))

    # Rule HD-V008: image.pullPolicy should be set
    pull_policy = image.get("pullPolicy", "")
    if not pull_policy:
        issues.append(Issue(
            rule_id="HD-V008",
            severity=Severity.LOW,
            category=Category.VALUES,
            message="image.pullPolicy is not set (defaults to 'IfNotPresent')",
            file_path="values.yaml",
            suggestion="Explicitly set image.pullPolicy to 'IfNotPresent', 'Always', or 'Never'",
        ))
    elif pull_policy not in ("IfNotPresent", "Always", "Never"):
        issues.append(Issue(
            rule_id="HD-V009",
            severity=Severity.HIGH,
            category=Category.VALUES,
            message=f"Invalid image.pullPolicy '{pull_policy}'",
            file_path="values.yaml",
            suggestion="Set pullPolicy to 'IfNotPresent', 'Always', or 'Never'",
        ))


def _check_resources(values: dict, issues: list):
    """Check resource limit/request configuration."""
    resources = values.get("resources", {})

    # Rule HD-V010: resources should be defined
    if not resources or not isinstance(resources, dict):
        issues.append(Issue(
            rule_id="HD-V010",
            severity=Severity.HIGH,
            category=Category.RESOURCE_MANAGEMENT,
            message="No resource limits/requests defined in values.yaml",
            file_path="values.yaml",
            suggestion="Define resources.requests and resources.limits for CPU and memory",
            doc_url="https://helm.sh/docs/chart_best_practices/pods/#resources",
        ))
        return

    # Rule HD-V011: requests should be set
    if not resources.get("requests"):
        issues.append(Issue(
            rule_id="HD-V011",
            severity=Severity.HIGH,
            category=Category.RESOURCE_MANAGEMENT,
            message="Resource requests are not defined",
            file_path="values.yaml",
            suggestion="Add resources.requests.cpu and resources.requests.memory",
        ))
    else:
        req = resources["requests"]
        if isinstance(req, dict):
            if not req.get("cpu"):
                issues.append(Issue(
                    rule_id="HD-V012",
                    severity=Severity.MEDIUM,
                    category=Category.RESOURCE_MANAGEMENT,
                    message="resources.requests.cpu is not set",
                    file_path="values.yaml",
                    suggestion="Set a CPU request (e.g., '100m')",
                ))
            if not req.get("memory"):
                issues.append(Issue(
                    rule_id="HD-V013",
                    severity=Severity.MEDIUM,
                    category=Category.RESOURCE_MANAGEMENT,
                    message="resources.requests.memory is not set",
                    file_path="values.yaml",
                    suggestion="Set a memory request (e.g., '128Mi')",
                ))

    # Rule HD-V014: limits should be set
    if not resources.get("limits"):
        issues.append(Issue(
            rule_id="HD-V014",
            severity=Severity.MEDIUM,
            category=Category.RESOURCE_MANAGEMENT,
            message="Resource limits are not defined",
            file_path="values.yaml",
            suggestion="Add resources.limits.cpu and resources.limits.memory to prevent resource exhaustion",
        ))
    else:
        lim = resources["limits"]
        if isinstance(lim, dict):
            if not lim.get("memory"):
                issues.append(Issue(
                    rule_id="HD-V015",
                    severity=Severity.MEDIUM,
                    category=Category.RESOURCE_MANAGEMENT,
                    message="resources.limits.memory is not set",
                    file_path="values.yaml",
                    suggestion="Set a memory limit (e.g., '256Mi') to prevent OOM kills",
                ))


def _check_service_config(values: dict, issues: list):
    """Check service configuration."""
    service = values.get("service", {})
    if not isinstance(service, dict):
        return

    # Rule HD-V016: service.type should be set
    svc_type = service.get("type", "")
    if not svc_type:
        issues.append(Issue(
            rule_id="HD-V016",
            severity=Severity.LOW,
            category=Category.NETWORKING,
            message="service.type is not explicitly set",
            file_path="values.yaml",
            suggestion="Set service.type explicitly (ClusterIP, NodePort, LoadBalancer)",
        ))

    # Rule HD-V017: LoadBalancer warning
    if svc_type == "LoadBalancer":
        issues.append(Issue(
            rule_id="HD-V017",
            severity=Severity.INFO,
            category=Category.NETWORKING,
            message="service.type is 'LoadBalancer' — this will provision a cloud load balancer",
            file_path="values.yaml",
            suggestion="Consider using ClusterIP with an Ingress for cost efficiency",
        ))


def _check_ingress_config(values: dict, issues: list):
    """Check ingress configuration."""
    ingress = values.get("ingress", {})
    if not isinstance(ingress, dict):
        return

    enabled = ingress.get("enabled", False)
    if not enabled:
        return

    # Rule HD-V018: ingress className should be set
    if not ingress.get("className") and not ingress.get("ingressClassName"):
        issues.append(Issue(
            rule_id="HD-V018",
            severity=Severity.MEDIUM,
            category=Category.NETWORKING,
            message="Ingress is enabled but className is not set",
            file_path="values.yaml",
            suggestion="Set ingress.className (e.g., 'nginx') for explicit ingress controller selection",
        ))

    # Rule HD-V019: TLS should be configured
    if not ingress.get("tls"):
        issues.append(Issue(
            rule_id="HD-V019",
            severity=Severity.HIGH,
            category=Category.SECURITY,
            message="Ingress is enabled without TLS configuration",
            file_path="values.yaml",
            suggestion="Configure ingress.tls for HTTPS. Use cert-manager for automatic certificate management",
        ))


def _check_security_context(values: dict, issues: list):
    """Check security context configuration."""
    # Rule HD-V020: podSecurityContext should be set
    if not values.get("podSecurityContext"):
        issues.append(Issue(
            rule_id="HD-V020",
            severity=Severity.MEDIUM,
            category=Category.SECURITY,
            message="podSecurityContext is not configured",
            file_path="values.yaml",
            suggestion="Set podSecurityContext.runAsNonRoot: true and fsGroup for secure pod defaults",
        ))
    else:
        psc = values["podSecurityContext"]
        if isinstance(psc, dict):
            if not psc.get("runAsNonRoot"):
                issues.append(Issue(
                    rule_id="HD-V021",
                    severity=Severity.HIGH,
                    category=Category.SECURITY,
                    message="podSecurityContext.runAsNonRoot is not set to true",
                    file_path="values.yaml",
                    suggestion="Set runAsNonRoot: true to prevent containers from running as root",
                ))

    # Rule HD-V022: securityContext should be set
    if not values.get("securityContext"):
        issues.append(Issue(
            rule_id="HD-V022",
            severity=Severity.MEDIUM,
            category=Category.SECURITY,
            message="Container securityContext is not configured",
            file_path="values.yaml",
            suggestion="Set securityContext with readOnlyRootFilesystem, allowPrivilegeEscalation: false",
        ))
    else:
        sc = values["securityContext"]
        if isinstance(sc, dict):
            if sc.get("privileged"):
                issues.append(Issue(
                    rule_id="HD-V023",
                    severity=Severity.CRITICAL,
                    category=Category.SECURITY,
                    message="Container is configured as privileged — this is a severe security risk",
                    file_path="values.yaml",
                    suggestion="Remove 'privileged: true' unless absolutely required. Use specific capabilities instead",
                ))
            if sc.get("allowPrivilegeEscalation") is not False:
                issues.append(Issue(
                    rule_id="HD-V024",
                    severity=Severity.MEDIUM,
                    category=Category.SECURITY,
                    message="allowPrivilegeEscalation is not explicitly set to false",
                    file_path="values.yaml",
                    suggestion="Set allowPrivilegeEscalation: false to prevent privilege escalation attacks",
                ))
            if not sc.get("readOnlyRootFilesystem"):
                issues.append(Issue(
                    rule_id="HD-V025",
                    severity=Severity.MEDIUM,
                    category=Category.SECURITY,
                    message="readOnlyRootFilesystem is not set to true",
                    file_path="values.yaml",
                    suggestion="Set readOnlyRootFilesystem: true to prevent filesystem writes. Use emptyDir for writable paths",
                ))


def _check_probes(values: dict, issues: list):
    """Check health probe configuration."""
    # Rule HD-V026: liveness/readiness probes should be configurable
    has_liveness = "livenessProbe" in values
    has_readiness = "readinessProbe" in values

    if not has_liveness and not has_readiness:
        issues.append(Issue(
            rule_id="HD-V026",
            severity=Severity.MEDIUM,
            category=Category.RELIABILITY,
            message="No health probe configuration in values.yaml (livenessProbe/readinessProbe)",
            file_path="values.yaml",
            suggestion="Add livenessProbe and readinessProbe configuration for pod health management",
            doc_url="https://helm.sh/docs/chart_best_practices/pods/#health-checks",
        ))
    else:
        if not has_liveness:
            issues.append(Issue(
                rule_id="HD-V027",
                severity=Severity.MEDIUM,
                category=Category.RELIABILITY,
                message="livenessProbe configuration is missing from values.yaml",
                file_path="values.yaml",
                suggestion="Add livenessProbe for automatic pod restart on failure",
            ))
        if not has_readiness:
            issues.append(Issue(
                rule_id="HD-V028",
                severity=Severity.MEDIUM,
                category=Category.RELIABILITY,
                message="readinessProbe configuration is missing from values.yaml",
                file_path="values.yaml",
                suggestion="Add readinessProbe to prevent traffic to unready pods",
            ))


def _check_autoscaling(values: dict, issues: list):
    """Check autoscaling configuration."""
    autoscaling = values.get("autoscaling", {})
    if not isinstance(autoscaling, dict):
        return

    if autoscaling.get("enabled"):
        if not autoscaling.get("minReplicas"):
            issues.append(Issue(
                rule_id="HD-V029",
                severity=Severity.MEDIUM,
                category=Category.RELIABILITY,
                message="Autoscaling is enabled but minReplicas is not set",
                file_path="values.yaml",
                suggestion="Set autoscaling.minReplicas (e.g., 2) for minimum availability",
            ))


def _check_service_account(values: dict, issues: list):
    """Check service account configuration."""
    sa = values.get("serviceAccount", {})
    if not isinstance(sa, dict):
        return

    # Rule HD-V031: automountServiceAccountToken
    if sa.get("create", True) and sa.get("automountServiceAccountToken") is not False:
        issues.append(Issue(
            rule_id="HD-V031",
            severity=Severity.LOW,
            category=Category.SECURITY,
            message="serviceAccount.automountServiceAccountToken is not explicitly set to false",
            file_path="values.yaml",
            suggestion="Set automountServiceAccountToken: false unless your app needs Kubernetes API access",
        ))


def _check_hardcoded_secrets(values: dict, prefix: str, issues: list):
    """Check for hardcoded secrets in values."""
    for key, val in values.items():
        full_key = f"{prefix}.{key}" if prefix else key

        for pattern, name in SECRET_PATTERNS:
            if pattern.search(str(key)):
                if isinstance(val, str) and val and val not in ("", '""', "''", "changeme", "CHANGEME"):
                    # Check if value looks like a real secret (not a placeholder)
                    if len(val) > 5 and not val.startswith("{{"):
                        issues.append(Issue(
                            rule_id="HD-V032",
                            severity=Severity.CRITICAL,
                            category=Category.SECURITY,
                            message=f"Possible hardcoded {name} in '{full_key}'",
                            file_path="values.yaml",
                            suggestion=f"Use Kubernetes Secrets or external secret management (e.g., Vault, External Secrets Operator) instead of hardcoding '{full_key}'",
                        ))
                break

        if isinstance(val, dict) and prefix.count(".") < 4:
            _check_hardcoded_secrets(val, full_key, issues)


def _check_replica_count(values: dict, issues: list):
    """Check replica count configuration."""
    replica_count = values.get("replicaCount")
    if replica_count is not None:
        if isinstance(replica_count, (int, float)) and replica_count == 1:
            issues.append(Issue(
                rule_id="HD-V033",
                severity=Severity.INFO,
                category=Category.RELIABILITY,
                message="replicaCount is set to 1 — no high availability",
                file_path="values.yaml",
                suggestion="Consider setting replicaCount >= 2 for production workloads, or enable autoscaling",
            ))


def _check_node_scheduling(values: dict, issues: list):
    """Check node scheduling configuration."""
    if not values.get("nodeSelector") and not values.get("affinity") and not values.get("topologySpreadConstraints"):
        issues.append(Issue(
            rule_id="HD-V034",
            severity=Severity.INFO,
            category=Category.RELIABILITY,
            message="No node scheduling constraints defined (nodeSelector, affinity, topologySpreadConstraints)",
            file_path="values.yaml",
            suggestion="Consider adding scheduling constraints for production workloads to ensure proper pod placement",
        ))


def _to_camel_case(name: str) -> str:
    """Convert snake_case to camelCase."""
    parts = name.split("_")
    return parts[0] + "".join(p.capitalize() for p in parts[1:])
