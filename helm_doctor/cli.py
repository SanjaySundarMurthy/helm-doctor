"""helm-doctor CLI — The ultimate Helm chart linter, validator & security scanner."""
import os
import shutil
import sys

import click
from rich.console import Console

# Fix Windows Unicode output
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")

from helm_doctor import __version__
from helm_doctor.analyzers.chart_analyzer import analyze_chart_yaml, get_chart_metadata
from helm_doctor.analyzers.dependency_analyzer import analyze_dependencies
from helm_doctor.analyzers.security_analyzer import analyze_security
from helm_doctor.analyzers.structure_analyzer import analyze_structure
from helm_doctor.analyzers.template_analyzer import analyze_templates
from helm_doctor.analyzers.values_analyzer import analyze_values_yaml
from helm_doctor.models import AnalysisReport, Severity
from helm_doctor.reporters.export_reporter import export_html, export_json
from helm_doctor.reporters.terminal_reporter import print_report

console = Console()

ANALYZER_NAMES = {
    "chart": ("Chart.yaml", analyze_chart_yaml),
    "values": ("values.yaml", analyze_values_yaml),
    "templates": ("Templates", analyze_templates),
    "security": ("Security", analyze_security),
    "dependencies": ("Dependencies", analyze_dependencies),
    "structure": ("Structure", analyze_structure),
}


@click.group(invoke_without_command=True)
@click.version_option(version=__version__, prog_name="helm-doctor")
@click.pass_context
def main(ctx):
    """🏥 helm-doctor — The ultimate Helm chart linter, validator & security scanner.

    Analyze Helm charts for best practices, security issues, and common mistakes.
    105+ rules across 11 categories.

    \b
    Examples:
      helm-doctor scan ./my-chart
      helm-doctor scan ./my-chart --verbose --export json
      helm-doctor scan ./my-chart --category security
      helm-doctor demo
      helm-doctor rules
    """
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


@main.command()
@click.argument("chart_path", type=click.Path(exists=True))
@click.option("--verbose", "-v", is_flag=True, help="Show detailed suggestions for each issue")
@click.option("--export", "-e", "export_format", type=click.Choice(["json", "html"]), help="Export report to file")
@click.option("--output", "-o", "output_path", type=click.Path(), help="Output file path for export")
@click.option("--category", "-c", multiple=True, type=click.Choice(list(ANALYZER_NAMES.keys())),
              help="Run only specific analyzers")
@click.option("--min-severity", "-s", type=click.Choice(["critical", "high", "medium", "low", "info"]),
              default="info", help="Minimum severity to report")
@click.option("--fail-on", "-f", type=click.Choice(["critical", "high", "medium", "low", "info"]),
              help="Exit with non-zero code if issues at this severity or above are found")
def scan(chart_path, verbose, export_format, output_path, category, min_severity, fail_on):
    """Scan a Helm chart for issues.

    CHART_PATH is the path to the Helm chart directory.
    """
    chart_path = os.path.abspath(chart_path)

    if not os.path.isdir(chart_path):
        console.print(f"[red]Error: '{chart_path}' is not a directory[/red]")
        sys.exit(1)

    report = _run_analysis(chart_path, category)

    # Filter by severity
    sev_order = list(Severity)
    min_sev_idx = sev_order.index(Severity(min_severity))
    report.issues = [i for i in report.issues if sev_order.index(i.severity) <= min_sev_idx]

    # Recalculate after filtering
    report.calculate_score()
    _count_rules(report)

    print_report(report, console, verbose)

    # Export
    if export_format:
        out_path = output_path or f"helm-doctor-report.{export_format}"
        if export_format == "json":
            export_json(report, out_path)
        elif export_format == "html":
            export_html(report, out_path)
        console.print(f"[green]📄 Report exported to {out_path}[/green]")

    # Fail-on check for CI/CD
    if fail_on:
        fail_sev_idx = sev_order.index(Severity(fail_on))
        failing_issues = [i for i in report.issues if sev_order.index(i.severity) <= fail_sev_idx]
        if failing_issues:
            sys.exit(1)


@main.command()
@click.option("--verbose", "-v", is_flag=True, help="Show detailed suggestions")
@click.option("--export", "-e", "export_format", type=click.Choice(["json", "html"]), help="Export report")
@click.option("--output", "-o", "output_path", type=click.Path(), help="Output path")
def demo(verbose, export_format, output_path):
    """Run helm-doctor on a demo chart with intentional issues.

    Perfect for trying out helm-doctor without a real chart.
    """
    from helm_doctor.demo import create_demo_chart

    console.print("[cyan]🎪 Creating demo chart with intentional issues...[/cyan]\n")
    demo_path = create_demo_chart()

    try:
        report = _run_analysis(demo_path, ())
        report.calculate_score()
        _count_rules(report)

        print_report(report, console, verbose)

        if export_format:
            out_path = output_path or f"helm-doctor-demo-report.{export_format}"
            if export_format == "json":
                export_json(report, out_path)
            elif export_format == "html":
                export_html(report, out_path)
            console.print(f"[green]📄 Report exported to {out_path}[/green]")
    finally:
        # Cleanup demo chart
        shutil.rmtree(os.path.dirname(demo_path), ignore_errors=True)


@main.command()
def rules():
    """List all available lint rules."""
    from rich.table import Table

    table = Table(title="📋 helm-doctor Rules", show_lines=False, padding=(0, 1))
    table.add_column("Rule ID", style="bold cyan", width=10)
    table.add_column("Category", width=22)
    table.add_column("Severity", width=10)
    table.add_column("Description")

    rules_list = _get_all_rules()
    for rule in rules_list:
        sev_colors = {
            "critical": "bright_red", "high": "red",
            "medium": "yellow", "low": "cyan", "info": "dim",
        }
        color = sev_colors.get(rule["severity"], "white")
        table.add_row(
            rule["id"],
            rule["category"],
            f"[{color}]{rule['severity'].upper()}[/{color}]",
            rule["description"],
        )

    console.print(table)
    console.print(f"\n[dim]  Total: {len(rules_list)} rules across 11 categories[/dim]\n")


def _run_analysis(chart_path: str, categories: tuple) -> AnalysisReport:
    """Run all analyzers and build the report."""
    metadata = get_chart_metadata(chart_path)

    report = AnalysisReport(
        chart_path=chart_path,
        chart_name=metadata["name"],
        chart_version=metadata["version"],
        app_version=metadata["appVersion"],
        chart_type=metadata["type"],
    )

    # If specific categories chosen, run only those; otherwise run all
    analyzers_to_run = {}
    if categories:
        for cat in categories:
            if cat in ANALYZER_NAMES:
                analyzers_to_run[cat] = ANALYZER_NAMES[cat]
    else:
        analyzers_to_run = ANALYZER_NAMES

    all_issues = []
    for name, (display, analyzer_fn) in analyzers_to_run.items():
        with console.status(f"[cyan]Analyzing {display}...[/cyan]"):
            issues = analyzer_fn(chart_path)
            all_issues.extend(issues)

    report.issues = all_issues
    report.calculate_score()
    _count_rules(report)

    return report


def _count_rules(report: AnalysisReport):
    """Count total/passed/failed rules from issues."""
    # Total rules available
    report.total_rules = len(_get_all_rules())
    failed_rules = len(set(i.rule_id for i in report.issues))
    report.failed_rules = failed_rules
    report.passed_rules = report.total_rules - failed_rules


def _get_all_rules() -> list:
    """Return master list of all rules for the 'rules' command."""
    return [
        {"id": "HD-C001", "category": "Chart Structure", "severity": "critical", "description": "Chart.yaml must exist"},
        {"id": "HD-C002", "category": "Chart Structure", "severity": "critical", "description": "Chart.yaml must have valid YAML syntax"},
        {"id": "HD-C003", "category": "Chart Structure", "severity": "critical", "description": "Chart.yaml must be a YAML mapping"},
        {"id": "HD-C004", "category": "Metadata", "severity": "critical", "description": "Required fields (apiVersion, name, version) must be present"},
        {"id": "HD-C005", "category": "Metadata", "severity": "high", "description": "apiVersion must be 'v1' or 'v2'"},
        {"id": "HD-C006", "category": "Metadata", "severity": "medium", "description": "apiVersion should be 'v2' for Helm 3"},
        {"id": "HD-C007", "category": "Metadata", "severity": "medium", "description": "Chart name must follow naming conventions"},
        {"id": "HD-C008", "category": "Metadata", "severity": "high", "description": "Chart name must not exceed 53 characters"},
        {"id": "HD-C009", "category": "Metadata", "severity": "high", "description": "Version must be valid SemVer"},
        {"id": "HD-C010", "category": "Metadata", "severity": "low", "description": "Version should not be 0.0.0"},
        {"id": "HD-C011", "category": "Metadata", "severity": "low", "description": "appVersion should be set"},
        {"id": "HD-C012", "category": "Documentation", "severity": "low", "description": "Chart description should be set"},
        {"id": "HD-C013", "category": "Metadata", "severity": "low", "description": "Chart type should be explicitly set for v2"},
        {"id": "HD-C014", "category": "Metadata", "severity": "high", "description": "Chart type must be 'application' or 'library'"},
        {"id": "HD-C015", "category": "Documentation", "severity": "low", "description": "Maintainers should be listed"},
        {"id": "HD-C016", "category": "Documentation", "severity": "low", "description": "Each maintainer should have a name"},
        {"id": "HD-C017", "category": "Documentation", "severity": "info", "description": "Maintainer email is recommended"},
        {"id": "HD-C018", "category": "Documentation", "severity": "info", "description": "Home URL should be set"},
        {"id": "HD-C019", "category": "Documentation", "severity": "info", "description": "Source URLs should be listed"},
        {"id": "HD-C020", "category": "Documentation", "severity": "info", "description": "Icon URL should be set"},
        {"id": "HD-C021", "category": "Documentation", "severity": "info", "description": "Keywords should be defined"},
        {"id": "HD-C022", "category": "Metadata", "severity": "medium", "description": "Deprecated charts should have migration docs"},
        {"id": "HD-C023", "category": "Metadata", "severity": "medium", "description": "kubeVersion constraint should be set"},
        {"id": "HD-V001", "category": "Values", "severity": "medium", "description": "values.yaml should exist"},
        {"id": "HD-V002", "category": "Values", "severity": "critical", "description": "values.yaml must have valid YAML syntax"},
        {"id": "HD-V003", "category": "Values", "severity": "low", "description": "values.yaml should not be empty"},
        {"id": "HD-V004", "category": "Values", "severity": "high", "description": "values.yaml root must be a mapping"},
        {"id": "HD-V005", "category": "Values", "severity": "low", "description": "Value keys should use camelCase"},
        {"id": "HD-V006", "category": "Values", "severity": "high", "description": "image.repository should be set"},
        {"id": "HD-V007", "category": "Best Practices", "severity": "high", "description": "image.tag should not be 'latest'"},
        {"id": "HD-V008", "category": "Values", "severity": "low", "description": "image.pullPolicy should be set"},
        {"id": "HD-V009", "category": "Values", "severity": "high", "description": "image.pullPolicy must be valid"},
        {"id": "HD-V010", "category": "Resource Management", "severity": "high", "description": "Resource limits/requests should be defined"},
        {"id": "HD-V011", "category": "Resource Management", "severity": "high", "description": "Resource requests should be set"},
        {"id": "HD-V012", "category": "Resource Management", "severity": "medium", "description": "CPU request should be set"},
        {"id": "HD-V013", "category": "Resource Management", "severity": "medium", "description": "Memory request should be set"},
        {"id": "HD-V014", "category": "Resource Management", "severity": "medium", "description": "Resource limits should be set"},
        {"id": "HD-V015", "category": "Resource Management", "severity": "medium", "description": "Memory limit should be set"},
        {"id": "HD-V016", "category": "Networking", "severity": "low", "description": "Service type should be explicitly set"},
        {"id": "HD-V017", "category": "Networking", "severity": "info", "description": "LoadBalancer type provisioning warning"},
        {"id": "HD-V018", "category": "Networking", "severity": "medium", "description": "Ingress className should be set"},
        {"id": "HD-V019", "category": "Security", "severity": "high", "description": "Ingress should have TLS configured"},
        {"id": "HD-V020", "category": "Security", "severity": "medium", "description": "podSecurityContext should be configured"},
        {"id": "HD-V021", "category": "Security", "severity": "high", "description": "runAsNonRoot should be true"},
        {"id": "HD-V022", "category": "Security", "severity": "medium", "description": "Container securityContext should be configured"},
        {"id": "HD-V023", "category": "Security", "severity": "critical", "description": "Privileged containers are a security risk"},
        {"id": "HD-V024", "category": "Security", "severity": "medium", "description": "allowPrivilegeEscalation should be false"},
        {"id": "HD-V025", "category": "Security", "severity": "medium", "description": "readOnlyRootFilesystem should be true"},
        {"id": "HD-V026", "category": "Reliability", "severity": "medium", "description": "Health probes should be configurable"},
        {"id": "HD-V027", "category": "Reliability", "severity": "medium", "description": "Liveness probe should be configured"},
        {"id": "HD-V028", "category": "Reliability", "severity": "medium", "description": "Readiness probe should be configured"},
        {"id": "HD-V029", "category": "Reliability", "severity": "medium", "description": "Autoscaling minReplicas should be set"},
        {"id": "HD-V030", "category": "Documentation", "severity": "low", "description": "values.yaml should have documentation comments"},
        {"id": "HD-V031", "category": "Security", "severity": "low", "description": "automountServiceAccountToken should be false"},
        {"id": "HD-V032", "category": "Security", "severity": "critical", "description": "No hardcoded secrets in values"},
        {"id": "HD-V033", "category": "Reliability", "severity": "info", "description": "Single replica warning for HA"},
        {"id": "HD-V034", "category": "Reliability", "severity": "info", "description": "Node scheduling constraints recommended"},
        {"id": "HD-T001", "category": "Chart Structure", "severity": "high", "description": "templates/ directory must exist"},
        {"id": "HD-T002", "category": "Chart Structure", "severity": "high", "description": "templates/ must contain YAML/TPL files"},
        {"id": "HD-T003", "category": "Templates", "severity": "medium", "description": "_helpers.tpl should exist"},
        {"id": "HD-T004", "category": "Documentation", "severity": "low", "description": "NOTES.txt should exist"},
        {"id": "HD-T005", "category": "Best Practices", "severity": "low", "description": "Chart tests should exist"},
        {"id": "HD-T006", "category": "Templates", "severity": "high", "description": "No hardcoded namespaces in templates"},
        {"id": "HD-T007", "category": "Best Practices", "severity": "high", "description": "No hardcoded 'latest' image tags"},
        {"id": "HD-T008", "category": "Templates", "severity": "medium", "description": "No deprecated functions/fields"},
        {"id": "HD-T009", "category": "Best Practices", "severity": "low", "description": "Recommended Kubernetes labels present"},
        {"id": "HD-T010", "category": "Templates", "severity": "medium", "description": "Values should be quoted/piped properly"},
        {"id": "HD-T011", "category": "Reliability", "severity": "medium", "description": "PVCs should have resource-policy annotation"},
        {"id": "HD-T012", "category": "Best Practices", "severity": "medium", "description": "Hooks should have delete-policy"},
        {"id": "HD-T013", "category": "Resource Management", "severity": "high", "description": "Workloads must have resources section"},
        {"id": "HD-T014", "category": "Security", "severity": "low", "description": "Workloads should reference a ServiceAccount"},
        {"id": "HD-T015", "category": "Templates", "severity": "low", "description": "No empty template files"},
        {"id": "HD-T016", "category": "Templates", "severity": "medium", "description": "toYaml should use nindent/indent"},
        {"id": "HD-T017", "category": "Templates", "severity": "low", "description": "No orphaned template definitions"},
        {"id": "HD-S001", "category": "Security", "severity": "critical", "description": "No weak/default credentials"},
        {"id": "HD-S002", "category": "Security", "severity": "critical", "description": "No privileged containers"},
        {"id": "HD-S003", "category": "Security", "severity": "high", "description": "No host namespace sharing"},
        {"id": "HD-S004", "category": "Security", "severity": "high", "description": "No hostPath volume mounts"},
        {"id": "HD-S005", "category": "Security", "severity": "high", "description": "No running as root (UID 0)"},
        {"id": "HD-S006", "category": "Security", "severity": "critical", "description": "No dangerous Linux capabilities"},
        {"id": "HD-S007", "category": "Security", "severity": "critical", "description": "No wildcard RBAC permissions"},
        {"id": "HD-S008", "category": "Security", "severity": "medium", "description": "Sensitive resources need review"},
        {"id": "HD-S009", "category": "Security", "severity": "medium", "description": "automountServiceAccountToken usage"},
        {"id": "HD-S010", "category": "Security", "severity": "medium", "description": "NetworkPolicy rules validation"},
        {"id": "HD-S011", "category": "Security", "severity": "medium", "description": "NetworkPolicy should exist"},
        {"id": "HD-S012", "category": "Reliability", "severity": "low", "description": "PodDisruptionBudget should exist"},
        {"id": "HD-D001", "category": "Dependencies", "severity": "medium", "description": "Use Chart.yaml dependencies for v2"},
        {"id": "HD-D002", "category": "Dependencies", "severity": "high", "description": "Dependencies must be a list"},
        {"id": "HD-D003", "category": "Dependencies", "severity": "medium", "description": "Chart.lock should exist"},
        {"id": "HD-D004", "category": "Dependencies", "severity": "medium", "description": "charts/ directory should exist"},
        {"id": "HD-D005", "category": "Dependencies", "severity": "high", "description": "Dependency name is required"},
        {"id": "HD-D006", "category": "Dependencies", "severity": "high", "description": "Dependency version is required"},
        {"id": "HD-D007", "category": "Dependencies", "severity": "medium", "description": "Version constraint should be valid SemVer range"},
        {"id": "HD-D008", "category": "Dependencies", "severity": "high", "description": "Dependency repository is required"},
        {"id": "HD-D009", "category": "Dependencies", "severity": "info", "description": "Local file:// dependencies warning"},
        {"id": "HD-D010", "category": "Dependencies", "severity": "high", "description": "No duplicate dependency names"},
        {"id": "HD-D011", "category": "Dependencies", "severity": "info", "description": "Alias recommended for common charts"},
        {"id": "HD-D012", "category": "Dependencies", "severity": "low", "description": "Dependencies should have condition/tags"},
        {"id": "HD-X001", "category": "Chart Structure", "severity": "critical", "description": "Must be a valid Helm chart directory"},
        {"id": "HD-X002", "category": "Chart Structure", "severity": "low", "description": "Recommended files should exist"},
        {"id": "HD-X003", "category": "Chart Structure", "severity": "low", "description": ".helmignore should exist"},
        {"id": "HD-X004", "category": "Values", "severity": "info", "description": "values.schema.json recommended"},
        {"id": "HD-X005", "category": "Security", "severity": "critical", "description": "No sensitive files in chart"},
        {"id": "HD-X006", "category": "Chart Structure", "severity": "high", "description": "Chart size should be reasonable"},
        {"id": "HD-X007", "category": "Best Practices", "severity": "medium", "description": "CRDs belong in crds/ directory"},
    ]


if __name__ == "__main__":
    main()
