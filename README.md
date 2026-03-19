# 🏥 helm-doctor

**The Ultimate Helm Chart Linter, Validator & Security Scanner**

[![Python](https://img.shields.io/badge/Python-3.9+-3776AB?logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Helm](https://img.shields.io/badge/Helm-3.x-0F1689?logo=helm&logoColor=white)](https://helm.sh)
[![Rules](https://img.shields.io/badge/Rules-75%2B-blue)](docs/rules.md)
[![Categories](https://img.shields.io/badge/Categories-11-purple)](docs/categories.md)

> Stop deploying broken Helm charts. `helm-doctor` catches **75+ issues** across **11 categories** — from hardcoded secrets to missing health probes — before they hit your cluster.

```
  _   _      _             ____             _
 | | | | ___| |_ __ ___   |  _ \  ___   ___| |_ ___  _ __
 | |_| |/ _ \ | '_ ` _ \  | | | |/ _ \ / __| __/ _ \| '__|
 |  _  |  __/ | | | | | | | |_| | (_) | (__| || (_) | |
 |_| |_|\___|_|_| |_| |_| |____/ \___/ \___|\__\___/|_|
```

## 🚀 Features

| Feature | Description |
|---------|-------------|
| 📦 **Chart Structure Validation** | Validates Chart.yaml, values.yaml, templates/, and directory structure |
| 🔒 **Deep Security Scanning** | Detects privileged containers, hostPath mounts, RBAC wildcards, hardcoded secrets |
| ⚙️ **Values Best Practices** | Checks image config, resource limits, security contexts, probe configuration |
| 📄 **Template Linting** | Finds hardcoded namespaces, deprecated functions, orphaned templates |
| 🔗 **Dependency Analysis** | Validates chart dependencies, version constraints, lock files |
| 📊 **Health Scoring** | A+ to F grading with detailed score breakdown |
| 🎨 **Beautiful Terminal Output** | Rich, colorful reports with severity icons and progress bars |
| 📤 **Multiple Export Formats** | JSON for CI/CD integration, HTML for interactive dashboards |
| 🎪 **Demo Mode** | Try it instantly with a built-in sample chart |
| 🚦 **CI/CD Integration** | `--fail-on` flag for pipeline gates |

## 📦 Installation

```bash
pip install helm-doctor
```

**From source:**
```bash
git clone https://github.com/ssan/helm-doctor.git
cd helm-doctor
pip install -e .
```

## ⚡ Quick Start

```bash
# Scan a Helm chart
helm-doctor scan ./my-chart

# Try the demo (no chart needed!)
helm-doctor demo

# Verbose mode with suggestions
helm-doctor scan ./my-chart --verbose

# Export as JSON for CI/CD
helm-doctor scan ./my-chart --export json

# Export interactive HTML dashboard
helm-doctor scan ./my-chart --export html

# Scan only security rules
helm-doctor scan ./my-chart --category security

# Fail in CI if critical issues found
helm-doctor scan ./my-chart --fail-on critical

# List all 75+ rules
helm-doctor rules
```

## 🏥 Demo Mode

Don't have a Helm chart handy? No problem!

```bash
helm-doctor demo
```

This creates a sample chart with intentional issues and runs the full analysis — perfect for seeing what helm-doctor can do.

## 📋 Rule Categories (75+ Rules)

| Category | Icon | Rules | What It Checks |
|----------|------|-------|----------------|
| Chart Structure | 📦 | 10 | Chart.yaml existence, YAML validity, required files |
| Metadata | 🏷️ | 12 | apiVersion, name conventions, SemVer, kubeVersion |
| Values | ⚙️ | 11 | Image config, naming conventions, empty values |
| Templates | 📄 | 8 | Hardcoded namespaces, deprecated functions, orphans |
| Security | 🔒 | 18 | Privileged containers, RBAC, secrets, TLS, hostPath |
| Best Practices | ✅ | 6 | Labels, image tags, hooks, CRD placement |
| Dependencies | 🔗 | 6 | Version constraints, lock files, conditions |
| Resource Mgmt | 📊 | 5 | CPU/memory limits, requests, workload resources |
| Networking | 🌐 | 3 | Service type, ingress config, NetworkPolicy |
| Reliability | 🛡️ | 7 | Health probes, PDB, replicas, scheduling |
| Documentation | 📚 | 6 | README, NOTES.txt, comments, maintainers |

## 🔒 Security Rules Highlights

helm-doctor performs **deep security scanning** that catches issues other linters miss:

- **HD-S001** — Weak/default credentials in values (password, admin, changeme)
- **HD-S002** — Privileged containers (`privileged: true`)
- **HD-S003** — Host namespace sharing (hostNetwork, hostPID, hostIPC)
- **HD-S004** — hostPath volume mounts (host filesystem access)
- **HD-S005** — Running as root (UID 0)
- **HD-S006** — Dangerous Linux capabilities (SYS_ADMIN, NET_ADMIN, ALL)
- **HD-S007** — Wildcard RBAC permissions (`*` on resources/verbs)
- **HD-V019** — Ingress without TLS
- **HD-V023** — Privileged security context in values
- **HD-V032** — Hardcoded secrets/passwords/API keys
- **HD-X005** — Sensitive files (.pem, .key, .env) in chart

## 🚦 CI/CD Integration

### GitHub Actions

```yaml
- name: Lint Helm Chart
  run: |
    pip install helm-doctor
    helm-doctor scan ./charts/my-app --fail-on high --export json -o report.json

- name: Upload Report
  uses: actions/upload-artifact@v4
  with:
    name: helm-doctor-report
    path: report.json
```

### Azure DevOps

```yaml
- script: |
    pip install helm-doctor
    helm-doctor scan ./charts/my-app --fail-on critical
  displayName: 'Helm Chart Security Scan'
```

### GitLab CI

```yaml
helm-lint:
  script:
    - pip install helm-doctor
    - helm-doctor scan ./charts/my-app --fail-on high --export json -o report.json
  artifacts:
    paths:
      - report.json
```

## 📊 Grading System

| Grade | Score | Status |
|-------|-------|--------|
| A+ | 95-100 | Excellent — production ready |
| A | 90-94 | Great — minor improvements possible |
| A- | 85-89 | Good — few recommendations |
| B+ | 80-84 | Above average |
| B | 75-79 | Average — several issues |
| B- | 70-74 | Below average |
| C+ | 65-69 | Needs improvement |
| C | 60-64 | Significant issues |
| C- | 55-59 | Many issues |
| D | 40-54 | Poor — major rework needed |
| F | <40 | Failing — critical issues present |

## 🛠️ CLI Reference

```
Usage: helm-doctor [OPTIONS] COMMAND [ARGS]...

Commands:
  scan   Scan a Helm chart for issues
  demo   Run on a demo chart with intentional issues
  rules  List all available lint rules

Scan Options:
  -v, --verbose          Show detailed suggestions
  -e, --export [json|html]  Export report format
  -o, --output PATH      Output file path
  -c, --category TEXT    Run specific analyzers (chart/values/templates/security/dependencies/structure)
  -s, --min-severity     Minimum severity to report
  -f, --fail-on          Exit non-zero if issues at this severity found
```

## 🤝 Contributing

Contributions welcome! Please open an issue or PR.

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

**Made with ❤️ for the Helm community by [Sai Sandeep](https://github.com/ssan)**
