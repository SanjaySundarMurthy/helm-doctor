"""Rich terminal reporter for helm-doctor."""
from collections import Counter

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.columns import Columns
from rich.rule import Rule

from helm_doctor.models import (
    AnalysisReport, Category, Severity,
    SEVERITY_COLORS, SEVERITY_ICONS, CATEGORY_ICONS,
)


GRADE_COLORS = {
    "A+": "bright_green", "A": "green", "A-": "green",
    "B+": "bright_yellow", "B": "yellow", "B-": "yellow",
    "C+": "dark_orange", "C": "dark_orange", "C-": "dark_orange",
    "D+": "red", "D": "red", "D-": "red",
    "F": "bright_red",
}

BANNER = r"""[bright_cyan]
  _   _      _             ____             _
 | | | | ___| |_ __ ___   |  _ \  ___   ___| |_ ___  _ __
 | |_| |/ _ \ | '_ ` _ \  | | | |/ _ \ / __| __/ _ \| '__|
 |  _  |  __/ | | | | | | | |_| | (_) | (__| || (_) | |
 |_| |_|\___|_|_| |_| |_| |____/ \___/ \___|\__\___/|_|
[/bright_cyan]
[dim]  The Ultimate Helm Chart Linter, Validator & Security Scanner[/dim]
[dim]  v1.0.0 — 75+ rules across 11 categories[/dim]
"""


def print_report(report: AnalysisReport, console: Console, verbose: bool = False):
    """Print a beautiful terminal report."""
    console.print(BANNER)
    console.print()

    # Chart info panel
    _print_chart_info(report, console)
    console.print()

    # Score panel
    _print_score(report, console)
    console.print()

    # Summary by severity
    _print_severity_summary(report, console)
    console.print()

    # Summary by category
    _print_category_summary(report, console)
    console.print()

    # Issues table
    if report.issues:
        _print_issues(report, console, verbose)
        console.print()

    # Top recommendations
    _print_recommendations(report, console)
    console.print()

    # Footer
    _print_footer(report, console)


def _print_chart_info(report: AnalysisReport, console: Console):
    """Print chart metadata panel."""
    info = Table.grid(padding=(0, 2))
    info.add_column(style="bold cyan", justify="right")
    info.add_column()

    info.add_row("Chart:", report.chart_name)
    info.add_row("Version:", report.chart_version)
    if report.app_version:
        info.add_row("App Version:", report.app_version)
    info.add_row("Type:", report.chart_type)
    info.add_row("Path:", report.chart_path)

    panel = Panel(info, title="📦 Chart Information", border_style="cyan", padding=(1, 2))
    console.print(panel)


def _print_score(report: AnalysisReport, console: Console):
    """Print the health score with grade."""
    grade_color = GRADE_COLORS.get(report.grade, "white")

    score_text = Text()
    score_text.append("  Health Score: ", style="bold")
    score_text.append(f"{report.score}", style=f"bold {grade_color}")
    score_text.append(f" / 100", style="dim")
    score_text.append("    Grade: ", style="bold")
    score_text.append(f" {report.grade} ", style=f"bold white on {grade_color}")
    score_text.append(f"    Rules: ", style="bold")
    score_text.append(f"{report.passed_rules}", style="green")
    score_text.append(f" passed", style="dim")
    score_text.append(f" / ", style="dim")
    score_text.append(f"{report.failed_rules}", style="red")
    score_text.append(f" failed", style="dim")
    score_text.append(f" / ", style="dim")
    score_text.append(f"{report.total_rules}", style="bold")
    score_text.append(f" total", style="dim")

    # Score bar
    bar_width = 40
    filled = int(report.score / 100 * bar_width)
    bar = "█" * filled + "░" * (bar_width - filled)

    bar_text = Text()
    bar_text.append("  [", style="dim")
    bar_text.append(bar[:filled], style=grade_color)
    bar_text.append(bar[filled:], style="dim")
    bar_text.append("]", style="dim")

    panel_content = Text()
    panel_content.append_text(score_text)
    panel_content.append("\n")
    panel_content.append_text(bar_text)

    panel = Panel(panel_content, title="🏥 Health Report", border_style=grade_color, padding=(1, 2))
    console.print(panel)


def _print_severity_summary(report: AnalysisReport, console: Console):
    """Print severity breakdown."""
    table = Table(title="Issues by Severity", box=None, padding=(0, 3), show_header=True)
    table.add_column("Severity", style="bold")
    table.add_column("Count", justify="center")
    table.add_column("Bar", min_width=30)

    severity_counts = {
        Severity.CRITICAL: report.critical_count,
        Severity.HIGH: report.high_count,
        Severity.MEDIUM: report.medium_count,
        Severity.LOW: report.low_count,
        Severity.INFO: report.info_count,
    }

    max_count = max(severity_counts.values()) if severity_counts.values() else 1

    for sev, count in severity_counts.items():
        icon = SEVERITY_ICONS[sev]
        color = SEVERITY_COLORS[sev]
        bar_len = int(count / max(max_count, 1) * 25) if count > 0 else 0
        bar = "█" * bar_len

        table.add_row(
            f"{icon} {sev.value.upper()}",
            f"[{color}]{count}[/{color}]",
            f"[{color}]{bar}[/{color}]",
        )

    console.print(table)


def _print_category_summary(report: AnalysisReport, console: Console):
    """Print category breakdown."""
    cat_counts = Counter(i.category for i in report.issues)

    if not cat_counts:
        return

    table = Table(title="Issues by Category", box=None, padding=(0, 3), show_header=True)
    table.add_column("Category", style="bold")
    table.add_column("Count", justify="center")
    table.add_column("Severities", min_width=30)

    for cat in Category:
        count = cat_counts.get(cat, 0)
        if count == 0:
            continue

        icon = CATEGORY_ICONS.get(cat, "📌")
        cat_issues = [i for i in report.issues if i.category == cat]
        sev_breakdown = Counter(i.severity for i in cat_issues)

        sev_str = "  ".join(
            f"[{SEVERITY_COLORS[s]}]{SEVERITY_ICONS[s]} {c}[/{SEVERITY_COLORS[s]}]"
            for s, c in sorted(sev_breakdown.items(), key=lambda x: list(Severity).index(x[0]))
        )

        table.add_row(f"{icon} {cat.value}", str(count), sev_str)

    console.print(table)


def _print_issues(report: AnalysisReport, console: Console, verbose: bool):
    """Print detailed issues table."""
    # Sort: critical first, then high, etc.
    severity_order = list(Severity)
    sorted_issues = sorted(report.issues, key=lambda i: severity_order.index(i.severity))

    table = Table(
        title=f"🔍 Issues Found ({len(report.issues)})",
        show_lines=True,
        padding=(0, 1),
        title_style="bold",
    )
    table.add_column("Rule", style="bold cyan", width=9)
    table.add_column("Sev", width=5, justify="center")
    table.add_column("Category", width=20)
    table.add_column("File", style="dim", width=30)
    table.add_column("Message", min_width=40)

    if verbose:
        table.add_column("Suggestion", style="italic green", min_width=30)

    max_display = 50 if not verbose else len(sorted_issues)

    for issue in sorted_issues[:max_display]:
        sev_color = SEVERITY_COLORS[issue.severity]
        sev_icon = SEVERITY_ICONS[issue.severity]
        cat_icon = CATEGORY_ICONS.get(issue.category, "📌")

        file_str = issue.file_path
        if issue.line:
            file_str += f":{issue.line}"

        row = [
            issue.rule_id,
            f"[{sev_color}]{sev_icon}[/{sev_color}]",
            f"{cat_icon} {issue.category.value}",
            file_str,
            f"[{sev_color}]{issue.message}[/{sev_color}]",
        ]

        if verbose and issue.suggestion:
            row.append(issue.suggestion)

        table.add_row(*row)

    if len(sorted_issues) > max_display:
        console.print(f"\n  [dim]... and {len(sorted_issues) - max_display} more issues. Use --verbose to see all.[/dim]")

    console.print(table)


def _print_recommendations(report: AnalysisReport, console: Console):
    """Print top actionable recommendations."""
    if not report.issues:
        console.print(Panel(
            "[bright_green]✨ No issues found! Your Helm chart is in excellent shape.[/bright_green]",
            title="🎉 Perfect Score",
            border_style="bright_green",
        ))
        return

    # Get top 5 critical/high issues as recommendations
    priority_issues = [i for i in report.issues if i.severity in (Severity.CRITICAL, Severity.HIGH)]
    if not priority_issues:
        priority_issues = [i for i in report.issues if i.severity == Severity.MEDIUM]

    if not priority_issues:
        return

    recs = []
    seen = set()
    for issue in priority_issues[:5]:
        if issue.suggestion and issue.suggestion not in seen:
            seen.add(issue.suggestion)
            sev_icon = SEVERITY_ICONS[issue.severity]
            sev_color = SEVERITY_COLORS[issue.severity]
            recs.append(f"  [{sev_color}]{sev_icon} [{issue.rule_id}][/{sev_color}] {issue.suggestion}")

    if recs:
        rec_text = "\n".join(recs)
        console.print(Panel(
            rec_text,
            title="💡 Top Recommendations",
            border_style="yellow",
            padding=(1, 2),
        ))


def _print_footer(report: AnalysisReport, console: Console):
    """Print footer with summary."""
    console.print(Rule(style="dim"))
    total = len(report.issues)
    if total == 0:
        console.print("[bright_green]  ✅ All checks passed! Chart is production-ready.[/bright_green]")
    elif report.critical_count > 0:
        console.print(f"[bright_red]  ⛔ {report.critical_count} critical issue(s) must be fixed before deployment.[/bright_red]")
    elif report.high_count > 0:
        console.print(f"[red]  ⚠️  {report.high_count} high-severity issue(s) should be addressed.[/red]")
    else:
        console.print(f"[yellow]  💡 {total} suggestion(s) to improve your chart.[/yellow]")

    console.print(f"[dim]  helm-doctor v1.0.0 | 75+ rules | 11 categories | Made with ❤️  for the Helm community[/dim]")
    console.print()
