"""JSON & HTML report exporters for helm-doctor."""
import json
import os
from datetime import datetime, timezone
from collections import Counter

from helm_doctor.models import (
    AnalysisReport, Category, Severity,
    SEVERITY_COLORS, SEVERITY_ICONS, CATEGORY_ICONS,
)


def export_json(report: AnalysisReport, output_path: str):
    """Export report as JSON."""
    data = {
        "tool": "helm-doctor",
        "version": "1.0.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "chart": {
            "name": report.chart_name,
            "version": report.chart_version,
            "appVersion": report.app_version,
            "type": report.chart_type,
            "path": report.chart_path,
        },
        "score": report.score,
        "grade": report.grade,
        "summary": {
            "total_rules": report.total_rules,
            "passed": report.passed_rules,
            "failed": report.failed_rules,
            "issues_by_severity": {
                "critical": report.critical_count,
                "high": report.high_count,
                "medium": report.medium_count,
                "low": report.low_count,
                "info": report.info_count,
            },
        },
        "issues": [
            {
                "rule_id": i.rule_id,
                "severity": i.severity.value,
                "category": i.category.value,
                "message": i.message,
                "file": i.file_path,
                "line": i.line,
                "suggestion": i.suggestion,
                "doc_url": i.doc_url,
            }
            for i in report.issues
        ],
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def export_html(report: AnalysisReport, output_path: str):
    """Export report as interactive HTML dashboard."""
    severity_data = {
        "Critical": report.critical_count,
        "High": report.high_count,
        "Medium": report.medium_count,
        "Low": report.low_count,
        "Info": report.info_count,
    }

    cat_counts = Counter(i.category.value for i in report.issues)

    grade_color_map = {
        "A+": "#22c55e", "A": "#22c55e", "A-": "#4ade80",
        "B+": "#facc15", "B": "#eab308", "B-": "#ca8a04",
        "C+": "#f97316", "C": "#ea580c", "C-": "#dc2626",
        "D+": "#dc2626", "D": "#b91c1c", "D-": "#991b1b",
        "F": "#7f1d1d",
    }
    grade_color = grade_color_map.get(report.grade, "#6b7280")

    sev_colors = {
        "Critical": "#ef4444",
        "High": "#f97316",
        "Medium": "#eab308",
        "Low": "#06b6d4",
        "Info": "#9ca3af",
    }

    issues_rows = ""
    for i, issue in enumerate(sorted(report.issues, key=lambda x: list(Severity).index(x.severity))):
        sev_color = sev_colors.get(issue.severity.value.capitalize(), "#9ca3af")
        line_str = f":{issue.line}" if issue.line else ""
        suggestion_html = f'<div class="suggestion">{issue.suggestion}</div>' if issue.suggestion else ""
        issues_rows += f"""
        <tr>
            <td><code>{issue.rule_id}</code></td>
            <td><span class="badge" style="background:{sev_color}">{issue.severity.value.upper()}</span></td>
            <td>{issue.category.value}</td>
            <td><code>{issue.file_path}{line_str}</code></td>
            <td>{issue.message}{suggestion_html}</td>
        </tr>"""

    cat_labels = json.dumps(list(cat_counts.keys()))
    cat_values = json.dumps(list(cat_counts.values()))

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Helm Doctor Report — {report.chart_name}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f172a; color: #e2e8f0; padding: 2rem; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        h1 {{ font-size: 2rem; margin-bottom: 0.5rem; color: #38bdf8; }}
        .subtitle {{ color: #94a3b8; margin-bottom: 2rem; }}
        .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 1.5rem; margin-bottom: 2rem; }}
        .card {{ background: #1e293b; border-radius: 12px; padding: 1.5rem; border: 1px solid #334155; }}
        .card h3 {{ color: #94a3b8; font-size: 0.875rem; text-transform: uppercase; margin-bottom: 0.5rem; }}
        .score {{ font-size: 3rem; font-weight: bold; }}
        .grade {{ display: inline-block; padding: 0.25rem 1rem; border-radius: 8px; font-size: 1.5rem; font-weight: bold; background: {grade_color}; color: white; }}
        .stat {{ font-size: 2rem; font-weight: bold; color: #38bdf8; }}
        .stat-label {{ color: #64748b; font-size: 0.875rem; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 1rem; }}
        th {{ text-align: left; padding: 0.75rem; background: #1e293b; color: #94a3b8; font-size: 0.875rem; text-transform: uppercase; border-bottom: 2px solid #334155; }}
        td {{ padding: 0.75rem; border-bottom: 1px solid #1e293b; vertical-align: top; }}
        tr:hover {{ background: #1e293b; }}
        .badge {{ display: inline-block; padding: 0.15rem 0.5rem; border-radius: 4px; color: white; font-size: 0.75rem; font-weight: bold; }}
        code {{ background: #334155; padding: 0.15rem 0.4rem; border-radius: 4px; font-size: 0.85rem; }}
        .suggestion {{ color: #4ade80; font-size: 0.85rem; margin-top: 0.25rem; font-style: italic; }}
        .severity-bar {{ display: flex; gap: 1rem; flex-wrap: wrap; margin: 1rem 0; }}
        .sev-item {{ text-align: center; }}
        .sev-count {{ font-size: 1.5rem; font-weight: bold; }}
        .sev-label {{ font-size: 0.75rem; color: #94a3b8; }}
        .progress-bar {{ width: 100%; height: 8px; background: #334155; border-radius: 4px; overflow: hidden; margin-top: 0.5rem; }}
        .progress-fill {{ height: 100%; border-radius: 4px; transition: width 0.5s; }}
        .footer {{ text-align: center; color: #475569; margin-top: 2rem; padding-top: 1rem; border-top: 1px solid #1e293b; }}
        .filter-bar {{ margin: 1rem 0; display: flex; gap: 0.5rem; flex-wrap: wrap; }}
        .filter-btn {{ padding: 0.4rem 0.8rem; border: 1px solid #334155; background: #1e293b; color: #e2e8f0; border-radius: 6px; cursor: pointer; font-size: 0.85rem; }}
        .filter-btn:hover, .filter-btn.active {{ background: #38bdf8; color: #0f172a; border-color: #38bdf8; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🏥 Helm Doctor Report</h1>
        <p class="subtitle">{report.chart_name} v{report.chart_version} &mdash; Generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}</p>

        <div class="grid">
            <div class="card">
                <h3>Health Score</h3>
                <span class="score" style="color: {grade_color}">{report.score}</span><span style="color:#64748b">/100</span>
                <div class="progress-bar">
                    <div class="progress-fill" style="width:{report.score}%; background:{grade_color}"></div>
                </div>
            </div>
            <div class="card">
                <h3>Grade</h3>
                <span class="grade">{report.grade}</span>
            </div>
            <div class="card">
                <h3>Rules</h3>
                <span class="stat">{report.passed_rules}</span>
                <span class="stat-label"> passed</span>
                <span style="color:#64748b"> / </span>
                <span class="stat" style="color:#ef4444">{report.failed_rules}</span>
                <span class="stat-label"> failed</span>
            </div>
            <div class="card">
                <h3>Total Issues</h3>
                <span class="stat">{len(report.issues)}</span>
            </div>
        </div>

        <div class="card">
            <h3>Issues by Severity</h3>
            <div class="severity-bar">
                {"".join(f'<div class="sev-item"><div class="sev-count" style="color:{sev_colors[k]}">{v}</div><div class="sev-label">{k}</div></div>' for k, v in severity_data.items())}
            </div>
        </div>

        <div class="card" style="margin-top:1.5rem">
            <h3>All Issues ({len(report.issues)})</h3>
            <div class="filter-bar">
                <button class="filter-btn active" onclick="filterIssues('all')">All</button>
                <button class="filter-btn" onclick="filterIssues('CRITICAL')">Critical</button>
                <button class="filter-btn" onclick="filterIssues('HIGH')">High</button>
                <button class="filter-btn" onclick="filterIssues('MEDIUM')">Medium</button>
                <button class="filter-btn" onclick="filterIssues('LOW')">Low</button>
                <button class="filter-btn" onclick="filterIssues('INFO')">Info</button>
            </div>
            <table id="issuesTable">
                <thead>
                    <tr><th>Rule</th><th>Severity</th><th>Category</th><th>File</th><th>Message</th></tr>
                </thead>
                <tbody>{issues_rows}</tbody>
            </table>
        </div>

        <div class="footer">
            helm-doctor v1.0.0 &bull; 75+ rules &bull; 11 categories &bull; Made with ❤️ for the Helm community
        </div>
    </div>

    <script>
        function filterIssues(severity) {{
            const rows = document.querySelectorAll('#issuesTable tbody tr');
            const buttons = document.querySelectorAll('.filter-btn');
            buttons.forEach(b => b.classList.remove('active'));
            event.target.classList.add('active');

            rows.forEach(row => {{
                if (severity === 'all') {{
                    row.style.display = '';
                }} else {{
                    const badge = row.querySelector('.badge');
                    row.style.display = badge && badge.textContent === severity ? '' : 'none';
                }}
            }});
        }}
    </script>
</body>
</html>"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)
