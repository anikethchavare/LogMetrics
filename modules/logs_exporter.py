# LogMetrics (JSON-Based Log File Analyzer) - modules/logs_exporter.py

"""
Output Exporter & Visual Dashboard Engine

Converts processed insights, system health metrics, and anomaly scans into:
- Colorized ANSI terminal dashboard with ASCII distribution bars
- Machine-readable JSON summary
- Flagged incident CSV file
- Formatted Markdown audit report
- Interactive standalone HTML dashboard with visual charts
"""

# Imports
import csv
import json
from pathlib import Path
from datetime import datetime
from typing import Any, Dict, List, Optional

# Constants (Color Codes)
RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"

# Function 1: _get_status_color (Internal)
def _get_status_color(status_code: Optional[int]) -> str:
    """ Return ANSI color based on standard HTTP status code ranges. """
    
    if status_code is None:
        return RESET
    if status_code >= 500:
        return RED
    if status_code >= 400:
        return YELLOW
    if status_code >= 200 and status_code < 300:
        return GREEN
    
    return CYAN

# Function 2: _render_ascii_bar (Internal)
def _render_ascii_bar(count: int, total: int, max_length: int = 25) -> str:
    """ Generate proportional ASCII progress bar. """
    
    if total == 0:
        return ""
    
    filled = int(round((count / total) * max_length))
    
    return "#" * filled + "-" * (max_length - filled)

# Function 3: display_dashboard
def display_dashboard(summary_dict: Dict[str, Any], preview_limit: int = 15) -> None:
    """
    Renders an executive telemetry terminal dashboard with system health scores,
    ASCII status distributions, detected security threats, and a log stream preview.
    """
    
    total_logs = summary_dict.get("total_logs", 0)
    health = summary_dict.get("health", {})
    security = summary_dict.get("security", {})
    status_dist = summary_dict.get("status_distribution", {})
    top_endpoints = summary_dict.get("top_endpoints", [])
    top_ips = summary_dict.get("top_ips", [])
    insights = summary_dict.get("insights", [])
    logs = summary_dict.get("logs", [])

    print("\n" + "=" * 78)
    print(f"{BOLD}{CYAN}             LOGMETRICS: TELEMETRY & SECURITY DASHBOARD{RESET}")
    print("=" * 78)
    print(f" Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} UTC | Total Requests Monitored: {total_logs:,}")

    uptime = health.get("uptime_score", 100.0)
    grade = health.get("health_grade", "STABLE")
    grade_color = GREEN if grade in ("EXCELLENT", "STABLE") else (YELLOW if grade == "DEGRADED" else RED)

    print("\n" + "-" * 78)
    print(f"{BOLD}[1] SYSTEM HEALTH & RELIABILITY{RESET}")
    print(f" Uptime / Success Rate : {grade_color}{uptime}%{RESET} ({grade_color}{grade}{RESET})")
    print(f" Successful Requests    : {health.get('success_count', 0):,}")
    print(f" Client Errors (4xx)    : {health.get('client_error_count', 0):,}")
    print(f" Server Errors (5xx)    : {health.get('server_error_count', 0):,}")

    print("\n" + "-" * 78)
    print(f"{BOLD}[2] HTTP STATUS CODE BREAKDOWN{RESET}")
    
    for code, count in sorted(status_dist.items()):
        color = _get_status_color(code)
        pct = (count / total_logs) * 100 if total_logs > 0 else 0
        bar = _render_ascii_bar(count, total_logs, max_length=20)
        
        print(f" HTTP {color}{code}{RESET} : [{bar}] {count:>6,} ({pct:>5.1f}%)")

    brute_force = security.get("brute_force_warnings", [])
    
    print("\n" + "-" * 78)
    print(f"{BOLD}[3] SECURITY THREAT DETECTION{RESET}")
    
    if brute_force:
        print(f" {RED}{BOLD}[!] ALERT: {len(brute_force)} Suspicious Source IP(s) Detected:{RESET}")
        
        for alert in brute_force[:5]:
            print(f"   * IP: {RED}{alert['ip']:<18}{RESET} | Auth Failures: {alert['failures']} ({alert['threat']})")
    else:
        print(f" {GREEN}[OK] No active brute-force or unauthorized scanning patterns detected.{RESET}")

    print("\n" + "-" * 78)
    print(f"{BOLD}[4] TRAFFIC PROFILING{RESET}")
    print(" Top Routes / Endpoints:")
    
    for ep, count in top_endpoints[:5]:
        print(f"   * {ep:<40} : {count:>5,} hits")

    print("\n Top Active Client IPs:")
    
    for ip_addr, count in top_ips[:5]:
        print(f"   * {ip_addr:<20} : {count:>5,} requests")

    print("\n" + "-" * 78)
    print(f"{BOLD}[5] KEY PROCESSED INSIGHTS{RESET}")
    
    for insight in insights:
        print(f" * {insight}")

    print("\n" + "-" * 78)
    print(f"{BOLD}[6] LOG STREAM PREVIEW (Showing latest {min(len(logs), preview_limit)} records){RESET}")
    print(f"{'TIMESTAMP':<22} {'METHOD':<8} {'STATUS':<10} {'ENDPOINT'}")
    print("-" * 78)
    
    for log in logs[:preview_limit]:
        ts = log.get("timestamp", "-")
        method = log.get("method", "GET")
        code = log.get("status_code", 200)
        ep = log.get("endpoint", "/")
        color = _get_status_color(code)
        
        print(f"{ts:<22} {method:<8} {color}{code:<10}{RESET} {ep}")

    print("=" * 78 + "\n")

# Function 4: export_summary
def export_summary(summary_dict: Dict[str, Any], output_format: str = "json", filename: Optional[str] = None) -> str:
    """
    Exports analytics results in the specified format:
    - 'json': Complete data serialization.
    - 'csv' : Flagged security and error incidents (status >= 400).
    - 'md'  : Markdown audit report with summary tables.
    - 'html': Self-contained visual HTML dashboard with interactive charts.
    """
    
    fmt = output_format.lower()
    logs = summary_dict.get("logs", [])
    total_logs = summary_dict.get("total_logs", 0)

    if fmt == "json":
        target = filename or "summary.json"
        exportable = dict(summary_dict)
        exportable["logs"] = exportable.get("logs", [])[:500]
        
        with open(target, "w", encoding="utf-8") as f:
            json.dump(exportable, f, indent=4)

    elif fmt == "csv":
        target = filename or "flagged_errors.csv"
        flagged = [
            log for log in logs
            if (log.get("status_code") is not None and log.get("status_code") >= 400)
            or log.get("level") in ("WARN", "ERROR")
        ]
        fields = ["log_id", "timestamp", "ip", "method", "endpoint", "status_code", "level", "message"]
        
        with open(target, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(flagged)
    elif fmt in ("md", "markdown"):
        target = filename or "audit_summary.md"
        health = summary_dict.get("health", {})
        security = summary_dict.get("security", {})
        
        with open(target, "w", encoding="utf-8") as f:
            f.write("# LogMetrics System Audit & Telemetry Report\n\n")
            f.write(f"- **Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} UTC\n")
            f.write(f"- **Total Records Monitored:** {total_logs:,}\n")
            f.write(f"- **Server Reliability Score:** {health.get('uptime_score', 100.0)}% ({health.get('health_grade', 'STABLE')})\n\n")

            f.write("## Processed Analytical Insights\n\n")
            
            for ins in summary_dict.get("insights", []):
                f.write(f"- {ins}\n")

            f.write("\n## HTTP Status Code Distribution\n\n")
            f.write("| Status Code | Request Count | Percentage |\n")
            f.write("| :--- | :--- | :--- |\n")
            
            for code, count in sorted(summary_dict.get("status_distribution", {}).items()):
                pct = (count / total_logs) * 100 if total_logs > 0 else 0
                f.write(f"| HTTP {code} | {count:,} | {pct:.2f}% |\n")

            f.write("\n## Security & Threat Assessment\n\n")
            brute_force = security.get("brute_force_warnings", [])
            
            if brute_force:
                f.write("| Flagged Client IP | Failed Auth Requests | Threat Classification |\n")
                f.write("| :--- | :--- | :--- |\n")
                
                for alert in brute_force:
                    f.write(f"| `{alert['ip']}` | {alert['failures']} | {alert['threat']} |\n")
            else:
                f.write("No active security anomalies or unauthorized scanning activities detected.\n")
    elif fmt == "html":
        target = filename or "dashboard.html"
        health = summary_dict.get("health", {})
        status_dist = summary_dict.get("status_distribution", {})
        top_eps = summary_dict.get("top_endpoints", [])

        status_labels = [f"HTTP {code}" for code in sorted(status_dist.keys())]
        status_values = [status_dist[code] for code in sorted(status_dist.keys())]
        ep_labels = [item[0] for item in top_eps[:5]]
        ep_values = [item[1] for item in top_eps[:5]]

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>LogMetrics Visual Dashboard</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background: #0f172a; color: #f8fafc; padding: 2rem; }}
        .header {{ display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #334155; padding-bottom: 1rem; margin-bottom: 2rem; }}
        .cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin-bottom: 2rem; }}
        .card {{ background: #1e293b; padding: 1.5rem; border-radius: 0.5rem; border: 1px solid #334155; }}
        .card h3 {{ margin: 0 0 0.5rem 0; font-size: 0.875rem; color: #94a3b8; text-transform: uppercase; }}
        .card .value {{ font-size: 1.875rem; font-weight: bold; color: #38bdf8; }}
        .charts {{ display: grid; grid-template-columns: 1fr 1fr; gap: 2rem; margin-bottom: 2rem; }}
        .chart-box {{ background: #1e293b; padding: 1.5rem; border-radius: 0.5rem; border: 1px solid #334155; }}
    </style>
</head>
<body>
    <div class="header">
        <div>
            <h1 style="margin: 0; color: #38bdf8;">LogMetrics Analytics</h1>
            <p style="margin: 0.25rem 0 0 0; color: #94a3b8;">Automated Server & API Telemetry Report</p>
        </div>
        <div><span>{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} UTC</span></div>
    </div>
    <div class="cards">
        <div class="card"><h3>Total Requests</h3><div class="value">{total_logs:,}</div></div>
        <div class="card"><h3>Health Score</h3><div class="value" style="color: #4ade80;">{health.get('uptime_score', 100.0)}%</div></div>
        <div class="card"><h3>Server Errors (5xx)</h3><div class="value" style="color: #f87171;">{health.get('server_error_count', 0):,}</div></div>
        <div class="card"><h3>Client Errors (4xx)</h3><div class="value" style="color: #fbbf24;">{health.get('client_error_count', 0):,}</div></div>
    </div>
    <div class="charts">
        <div class="chart-box"><canvas id="statusChart"></canvas></div>
        <div class="chart-box"><canvas id="endpointsChart"></canvas></div>
    </div>
    <script>
        new Chart(document.getElementById('statusChart'), {{
            type: 'doughnut',
            data: {{
                labels: {json.dumps(status_labels)},
                datasets: [{{
                    data: {json.dumps(status_values)},
                    backgroundColor: ['#22c55e', '#3b82f6', '#06b6d4', '#eab308', '#ef4444', '#a855f7']
                }}]
            }},
            options: {{ responsive: true, plugins: {{ title: {{ display: true, text: 'Status Code Distribution', color: '#f8fafc' }} }} }}
        }});
        new Chart(document.getElementById('endpointsChart'), {{
            type: 'bar',
            data: {{
                labels: {json.dumps(ep_labels)},
                datasets: [{{
                    label: 'Hits',
                    data: {json.dumps(ep_values)},
                    backgroundColor: '#38bdf8'
                }}]
            }},
            options: {{ responsive: true, plugins: {{ title: {{ display: true, text: 'Top 5 Hit Routes', color: '#f8fafc' }} }} }}
        }});
    </script>
</body>
</html>"""
        
        with open(target, "w", encoding="utf-8") as f:
            f.write(html_content)
    else:
        raise ValueError(f"Unsupported format '{output_format}'. Choose 'json', 'csv', 'md', or 'html'.")

    print(f"Report exported successfully: {target}")
    
    return target

# Running the Application
if __name__ == "__main__":
    test_summary = {
        "total_logs": 2,
        "health": {"uptime_score": 50.0, "health_grade": "CRITICAL", "success_count": 1, "client_error_count": 0, "server_error_count": 1},
        "security": {"brute_force_warnings": [{"ip": "192.168.1.1", "failures": 5, "threat": "Brute Force / Scan Attempt"}], "traffic_spikes": [], "total_suspicious_ips": 1},
        "status_distribution": {200: 1, 500: 1},
        "top_endpoints": [("/api/v1/checkout", 1)],
        "top_ips": [("192.168.1.1", 2)],
        "insights": ["Monitored 2 events.", "Detected 1 brute force attempt."],
        "logs": [
            {"timestamp": "2024-03-21T10:00:00Z", "method": "GET", "status_code": 200, "endpoint": "/api/v1/checkout", "ip": "192.168.1.1", "message": "GET /api/v1/checkout -> 200"},
            {"timestamp": "2024-03-21T10:00:05Z", "method": "POST", "status_code": 500, "endpoint": "/api/v1/checkout", "ip": "192.168.1.1", "message": "POST /api/v1/checkout -> 500"},
        ],
    }
    
    display_dashboard(test_summary)