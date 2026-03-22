# 🏥 helm-doctor

[![CI](https://github.com/SanjaySundarMurthy/helm-doctor/actions/workflows/ci.yml/badge.svg)](https://github.com/SanjaySundarMurthy/helm-doctor/actions/workflows/ci.yml)
[![Python](https://img.shields.io/pypi/pyversions/helm-doctor)](https://pypi.org/project/helm-doctor/)
[![PyPI](https://img.shields.io/pypi/v/helm-doctor)](https://pypi.org/project/helm-doctor/)

**The Ultimate Helm Chart Linter, Validator & Security Scanner**

[![Python](https://img.shields.io/badge/Python-3.9+-3776AB?logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Helm](https://img.shields.io/badge/Helm-3.x-0F1689?logo=helm&logoColor=white)](https://helm.sh)
[![Rules](https://img.shields.io/badge/Rules-105%2B-blue)](#-rule-categories-105-rules)
[![Categories](https://img.shields.io/badge/Categories-11-purple)](#-rule-categories-105-rules)
[![Tests](https://img.shields.io/badge/Tests-51-brightgreen)](#-running-tests)

> Stop deploying broken Helm charts. `helm-doctor` catches **105+ issues** across **11 categories** — from hardcoded secrets to missing health probes — before they hit your cluster.

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
git clone https://github.com/SanjaySundarMurthy/helm-doctor.git
cd helm-doctor
pip install -e ".[dev]"
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

# Filter by minimum severity
helm-doctor scan ./my-chart --min-severity medium

# List all 105+ rules
helm-doctor rules
```

## 🏥 Demo Mode

Don't have a Helm chart handy? No problem!

```bash
helm-doctor demo
```

This creates a sample chart with intentional issues and runs the full analysis — perfect for seeing what helm-doctor can do.

## 📋 Rule Categories (105+ Rules)

| Category | Icon | Rules | What It Checks |
|----------|------|-------|----------------|
| Chart Structure | 📦 | 9 | Chart.yaml existence, YAML validity, required files |
| Metadata | 🏷️ | 12 | apiVersion, name conventions, SemVer, kubeVersion |
| Values | ⚙️ | 9 | Image config, naming conventions, empty values |
| Templates | 📄 | 7 | Hardcoded namespaces, deprecated functions, orphans |
| Security | 🔒 | 22 | Privileged containers, RBAC, secrets, TLS, hostPath |
| Best Practices | ✅ | 6 | Labels, image tags, hooks, CRD placement |
| Dependencies | 🔗 | 12 | Version constraints, lock files, conditions, aliases |
| Resource Mgmt | 📊 | 7 | CPU/memory limits, requests, workload resources |
| Networking | 🌐 | 3 | Service type, ingress config, NetworkPolicy |
| Reliability | 🛡️ | 8 | Health probes, PDB, replicas, scheduling |
| Documentation | 📚 | 10 | README, NOTES.txt, comments, maintainers |

## 🔒 Security Rules Highlights

helm-doctor performs **deep security scanning** that catches issues other linters miss:

- **HD-S001** — Weak/default credentials in values (password, admin, changeme)
- **HD-S002** — Privileged containers (`privileged: true`)
- **HD-S003** — Host namespace sharing (hostNetwork, hostPID, hostIPC)
- **HD-S004** — hostPath volume mounts (host filesystem access)
- **HD-S005** — Running as root (UID 0)
- **HD-S006** — Dangerous Linux capabilities (SYS_ADMIN, NET_ADMIN, ALL)
- **HD-S007** — Wildcard RBAC permissions (`*` on resources/verbs)
- **HD-S008** — Sensitive resource types (ClusterRole, PodSecurityPolicy)
- **HD-S009** — automountServiceAccountToken enabled
- **HD-S010** — NetworkPolicy misconfiguration
- **HD-S011** — Missing NetworkPolicy (no pod isolation)
- **HD-S012** — Missing PodDisruptionBudget
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
| A+ | 95–100 | Excellent — production ready |
| A | 90–94 | Great — minor improvements possible |
| A- | 85–89 | Good — few recommendations |
| B+ | 80–84 | Above average |
| B | 75–79 | Average — several issues |
| B- | 70–74 | Below average |
| C+ | 65–69 | Needs improvement |
| C | 60–64 | Significant issues |
| C- | 55–59 | Many issues |
| D+ | 50–54 | Poor — major rework needed |
| D | 45–49 | Very poor |
| D- | 40–44 | Failing threshold |
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
  -s, --min-severity     Minimum severity to report (critical/high/medium/low/info)
  -f, --fail-on          Exit non-zero if issues at this severity found
```

## 📁 Project Structure

```
helm-doctor/
├── helm_doctor/
│   ├── __init__.py              # Package init & version
│   ├── cli.py                   # Click CLI (scan, demo, rules commands)
│   ├── demo.py                  # Demo chart generator
│   ├── models.py                # Issue, Severity, Category, AnalysisReport
│   ├── analyzers/
│   │   ├── chart_analyzer.py    # Chart.yaml validation (23 rules)
│   │   ├── values_analyzer.py   # values.yaml analysis (34 rules)
│   │   ├── template_analyzer.py # Template linting (17 rules)
│   │   ├── security_analyzer.py # Security scanning (12 rules)
│   │   ├── dependency_analyzer.py # Dependency checks (12 rules)
│   │   └── structure_analyzer.py  # Structure validation (7 rules)
│   └── reporters/
│       ├── terminal_reporter.py # Rich terminal output
│       └── export_reporter.py   # JSON & HTML export
├── tests/
│   ├── conftest.py              # Shared test fixtures
│   ├── test_analyzers.py        # Analyzer unit tests
│   ├── test_cli.py              # CLI integration tests
│   └── test_models.py           # Model unit tests
├── .github/workflows/ci.yml     # CI/CD pipeline
├── Dockerfile                   # Multi-stage container build
├── pyproject.toml               # Project config & dependencies
├── LICENSE                      # MIT License
└── README.md
```

## 🧪 Running Tests

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run all 51+ tests
pytest -v

# Run with coverage
pytest -v --tb=short
```

## 🐳 Docker

Run without installing Python:

```bash
# Build the image
docker build -t helm-doctor .

# Run
docker run --rm helm-doctor --help

# Scan a local chart
docker run --rm -v ${PWD}:/workspace helm-doctor scan /workspace/my-chart

# Demo mode
docker run --rm helm-doctor demo
```

Or pull from the container registry:

```bash
docker pull ghcr.io/SanjaySundarMurthy/helm-doctor:latest
docker run --rm ghcr.io/SanjaySundarMurthy/helm-doctor:latest --help
```

## 🤝 Contributing

Contributions welcome! Please open an issue or PR.

```bash
# Development setup
git clone https://github.com/SanjaySundarMurthy/helm-doctor.git
cd helm-doctor
pip install -e ".[dev]"

# Run tests
pytest -v

# Lint
ruff check .
```

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

## 🔗 Links

- **PyPI**: [https://pypi.org/project/helm-doctor/](https://pypi.org/project/helm-doctor/)
- **GitHub**: [https://github.com/SanjaySundarMurthy/helm-doctor](https://github.com/SanjaySundarMurthy/helm-doctor)
- **Issues**: [https://github.com/SanjaySundarMurthy/helm-doctor/issues](https://github.com/SanjaySundarMurthy/helm-doctor/issues)

---

**Made with ❤️ for the Helm community by [SanjaySundarMurthy](https://github.com/SanjaySundarMurthy)**
