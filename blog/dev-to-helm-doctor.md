---
title: "I Built helm-doctor Because Your Helm Charts Need a Check-Up 🏥"
published: true
description: "Your Helm charts are silently suffering. Privileged containers, hardcoded secrets, missing probes — helm-doctor catches 105+ issues before they become 3am incidents. Here's the full story."
tags: kubernetes, helm, devops, opensource
cover_image: ""
canonical_url:
series: "DevOps CLI Tools That Actually Help"
---

# I Built helm-doctor Because Your Helm Charts Need a Check-Up 🏥

*"It works on my cluster" — Famous last words before a production outage.*

Let me paint you a picture. It's 2:47 AM. Your phone is screaming. The on-call alert says pods are crashing in production. You SSH in, run `kubectl get pods`, and see the beautiful sea of `CrashLoopBackOff`. After 45 minutes of debugging, you discover the root cause:

**Someone set `image.tag: latest` in the Helm values, and the newest image broke everything.**

Or maybe it's this one:

**A junior engineer deployed a chart with `privileged: true` in the security context, and now your entire cluster is compromised.**

Or my personal favorite:

**The database password is `admin123`, hardcoded directly in `values.yaml`, and it's been committed to Git for 6 months.**

Sound familiar? Yeah, me too. That's why I built **helm-doctor**.

---

## 🤔 What Even IS helm-doctor?

**helm-doctor** is an open-source CLI tool that scans your Helm charts for issues BEFORE they become incidents. Think of it as a doctor's check-up, but for your Kubernetes deployments.

```bash
pip install helm-doctor
helm-doctor scan ./my-chart
```

That's it. Two commands. It analyzes your entire chart and spits out a health report with:

- **105+ lint rules** across **11 categories**
- **A+ to F grading** (yes, your chart gets a report card)
- **Security scanning** that catches what humans miss
- **Beautiful terminal output** (because we're developers, and we deserve pretty things)

---

## 🎪 The Demo That Sells Itself

Don't have a Helm chart handy? No problem:

```bash
helm-doctor demo
```

This creates a sample chart with **intentional** issues (the kind you've definitely shipped to production, don't lie) and runs the full analysis. Here's what the output looks like:

```
╭──────────────── 📦 Chart Information ────────────────╮
│                                                       │
│    Chart:  my-webapp                                  │
│  Version:  1.2.0                                      │
│     Type:  application                                │
│                                                       │
╰───────────────────────────────────────────────────────╯

╭──────────────── 🏥 Health Report ────────────────────╮
│                                                       │
│   Health Score: 43.7 / 100    Grade:  D-              │
│   [█████████████████░░░░░░░░░░░░░░░░░░░░░]            │
│                                                       │
╰───────────────────────────────────────────────────────╯

Issues by Severity:
  🔴 CRITICAL   3   █████
  🟠 HIGH       8   ███████████████
  🟡 MEDIUM    12   ███████████████████████
  🔵 LOW       13   █████████████████████████
  ⚪ INFO      10   ███████████████████
```

**D-minus.** That chart is failing harder than my first attempt at writing YAML.

---

## 🔒 The Security Scanner That Doesn't Sleep

This is where helm-doctor really flexes. Let me walk you through the security checks that have personally saved my clusters:

### The "Oh No" Detections

**1. Privileged Containers (HD-S002)**

```yaml
# This is basically handing your cluster keys to the container
securityContext:
  privileged: true  # 🔴 helm-doctor: CRITICAL - Full host access granted
```

helm-doctor catches this and screams at you (politely, in red). Because a privileged container can:
- Access all host devices
- Modify the host filesystem  
- Escape the container entirely
- Basically do whatever it wants

It's like giving your intern root access to production. Don't.

**2. Wildcard RBAC (HD-S007)**

```yaml
# The "I don't know what permissions I need so I'll take ALL of them" approach
rules:
  - apiGroups: ["*"]
    resources: ["*"]
    verbs: ["*"]  # 🔴 helm-doctor: CRITICAL - Wildcard permissions detected
```

This is the Kubernetes equivalent of `chmod 777`. helm-doctor flags it immediately and reminds you that the principle of least privilege exists for a reason.

**3. Hardcoded Secrets (HD-V032)**

```yaml
database:
  password: sup3r_s3cret_passw0rd  # 🔴 helm-doctor: CRITICAL - Possible hardcoded password
  apiKey: sk-1234567890abcdef       # 🔴 helm-doctor: CRITICAL - Possible hardcoded API key
```

I once found a production chart with the database password set to `password123`. In a publicly accessible Git repository. The secret scanner catches **8 pattern types**: passwords, API keys, tokens, private keys, access keys, secret keys, connection strings, and more.

**4. Host Path Volumes (HD-S004)**

```yaml
volumes:
  - name: host-data
    hostPath:
      path: /var/data  # 🟠 helm-doctor: HIGH - hostPath allows access to host filesystem
```

Unless you're running a monitoring agent or a CSI driver, you almost never need `hostPath`. helm-doctor flags it and suggests using PersistentVolumeClaims instead.

**5. Running as Root (HD-S005)**

```yaml
securityContext:
  runAsUser: 0  # 🟠 helm-doctor: HIGH - Container configured to run as root
```

93% of container images can run as non-root with zero code changes. helm-doctor makes sure you're not in the 7% that actually needs it... or the 86% that thinks it does but doesn't.

---

## 📋 The Full Rule Breakdown (105 Rules!)

Here's everything helm-doctor checks, organized by what keeps you up at night:

### 📦 Chart Structure (10 rules)
- Chart.yaml must exist and be valid YAML
- Required fields: apiVersion, name, version
- Recommended files: .helmignore, README.md, values.schema.json
- Chart size shouldn't be enormous (no accidental binary blobs)
- Sensitive files (.pem, .key, .env) must not be in the chart

### 🏷️ Metadata (12 rules)  
- apiVersion should be `v2` (it's 2026, we use Helm 3)
- Chart name must follow DNS conventions (lowercase, dashes, ≤53 chars)
- Version must be valid SemVer (not `1.0` or `latest`)
- kubeVersion constraint should be set
- Type must be `application` or `library`

### 🔒 Security (18 rules)
- No privileged containers
- No host namespace sharing (hostNetwork, hostPID, hostIPC)
- No hostPath volume mounts
- No running as root
- No dangerous capabilities (SYS_ADMIN, NET_ADMIN, ALL)
- No wildcard RBAC
- No hardcoded secrets
- Ingress must have TLS
- SecurityContext properly configured
- NetworkPolicy should exist

### ⚙️ Values (11 rules)
- Image repository and tag configuration
- Pull policy must be valid
- Resource limits and requests defined
- Health probes configurable
- Naming conventions (camelCase)

### 📄 Templates (8 rules)
- No hardcoded namespaces (use `.Release.Namespace`)
- No deprecated functions
- `_helpers.tpl` should exist
- NOTES.txt for post-install instructions
- Proper `toYaml | nindent` usage
- No orphaned template definitions

### 📊 Resource Management (5 rules)
- CPU and memory requests must be set
- Memory limits are mandatory
- Workload templates must reference resources section

### 🛡️ Reliability (7 rules)
- Liveness and readiness probes
- PodDisruptionBudget
- Replica count HA warning
- Node scheduling constraints
- Autoscaling min replicas

### 🔗 Dependencies (6 rules)
- Chart.lock for reproducible builds
- Version constraints on all dependencies
- Repository URLs required
- Condition/tags for toggling

### Plus more in Networking, Best Practices, and Documentation...

---

## 🚦 CI/CD Integration: The Real Power

helm-doctor becomes truly powerful when you put it in your pipeline. One flag changes everything:

```bash
helm-doctor scan ./my-chart --fail-on critical
```

This returns exit code 1 if ANY critical issues exist. Your pipeline fails. The bad chart never reaches production. Here's how to set it up:

### GitHub Actions

```yaml
jobs:
  helm-lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Install helm-doctor
        run: pip install helm-doctor
      
      - name: Scan Helm Chart
        run: helm-doctor scan ./charts/my-app --fail-on high --export json -o report.json
      
      - name: Upload Report
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: helm-doctor-report
          path: report.json
```

### Azure DevOps

```yaml
steps:
- script: |
    pip install helm-doctor
    helm-doctor scan ./charts/my-app --fail-on critical
  displayName: 'Helm Chart Security Scan'
```

Now every PR that touches a Helm chart gets automatically validated. No more "I forgot to add resource limits" sneaking into production.

---

## 📊 The HTML Dashboard

For those who prefer pretty pictures over terminal output:

```bash
helm-doctor scan ./my-chart --export html -o report.html
```

This generates an **interactive HTML dashboard** with:
- Health score gauge with color coding
- Filterable issues table (click to filter by severity)
- Category breakdown
- Dark theme (because we're engineers, not farmers)

Perfect for sharing with your manager who doesn't understand terminal output but definitely understands red numbers.

---

## 🧠 The Design Decisions

A few things I'm particularly proud of:

### 1. Every Rule Has a Reference

Every single rule links to the official Helm or Kubernetes documentation. When helm-doctor tells you something is wrong, it also tells you **why** and **where to learn more**.

### 2. Precision Over Volume

I didn't just dump 200 generic YAML lint rules. Every rule is specifically relevant to Helm charts. `HD-T006` (hardcoded namespace) only triggers in template files, not in values.yaml where you MIGHT legitimately hardcode a namespace.

### 3. Severity Is Meaningful

- **CRITICAL** = Your cluster will be compromised or chart will fail
- **HIGH** = Production issues likely
- **MEDIUM** = Best practice violation
- **LOW** = Nice to have
- **INFO** = Contextual awareness

### 4. Demo Mode Exists

Most linting tools require you to have a project to scan. helm-doctor includes `helm-doctor demo` because the best way to show a tool's value is to **let people see it work immediately**.

---

## 🆚 How Does It Compare?

| Feature | helm-doctor | helm lint | chart-testing | Polaris |
|---------|:-----------:|:---------:|:-------------:|:-------:|
| Rules | 105+ | ~10 | ~15 | ~30 |
| Security scanning | ✅ Deep | ❌ | ❌ | ✅ Basic |
| Values analysis | ✅ | ❌ | ❌ | ❌ |
| Dependency analysis | ✅ | ❌ | ❌ | ❌ |
| Template linting | ✅ | ✅ Basic | ✅ Basic | ❌ |
| HTML reports | ✅ | ❌ | ❌ | ✅ |
| JSON export (CI/CD) | ✅ | ❌ | ❌ | ✅ |
| Health scoring | ✅ A-F | ❌ | ❌ | ❌ |
| Demo mode | ✅ | ❌ | ❌ | ❌ |
| Zero config | ✅ | ✅ | ❌ | ❌ |

*`helm lint` is built into Helm but only catches YAML syntax and basic template errors. `chart-testing` focuses on install/upgrade testing. Polaris is great for runtime but doesn't analyze chart structure.*

---

## 🔧 Getting Started (30 Seconds)

```bash
# Install
pip install helm-doctor

# Try the demo
helm-doctor demo

# Scan your chart
helm-doctor scan ./path-to-your-chart

# Verbose mode (shows suggestions)
helm-doctor scan ./my-chart -v

# Security-only scan
helm-doctor scan ./my-chart -c security

# CI/CD mode
helm-doctor scan ./my-chart --fail-on high --export json
```

---

## 🎯 What's Next?

I'm planning to add:

- **Auto-fix mode** — automatically fix common issues
- **Custom rules** — define your own organizational policies
- **Helm plugin** — run as `helm doctor scan` instead of `helm-doctor scan`
- **Pre-commit hook** — catch issues before they're even committed
- **VS Code extension** — inline warnings while you edit charts

---

## 💡 The Takeaway

Every Helm chart deployment is a trust exercise. You're trusting that:
- The image tag actually exists
- The resource limits won't starve or OOM your pods
- The security context won't compromise your cluster
- The ingress has TLS configured
- Nobody hardcoded `password123` in the values

**helm-doctor automates that trust.** It's 105 rules that represent hundreds of collective debugging hours, production incidents, and "oh god why" moments — distilled into a single command.

Your Helm charts deserve a check-up. Give them one.

```bash
pip install helm-doctor
helm-doctor demo
```

---

*If this helped you, star the repo on [GitHub](https://github.com/ssan/helm-doctor) and drop a comment below about the worst Helm misconfiguration you've ever seen in production. I'll go first: a chart with `replicaCount: 0` that somehow made it through three review stages.* 🙃

---

**helm-doctor** is open-source (MIT) and built with Python. PRs welcome!

{% embed https://github.com/ssan/helm-doctor %}
