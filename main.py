# LogMetrics (JSON-Based Log File Analyzer) - main.py

"""
Ways to Run the Application:
1. python main.py
2. python main.py --file logs.json --export all
"""

# Imports
import sys
import argparse
from pathlib import Path

from modules.logs_loader import load_logs
from modules.logs_filter import filter_logs
from modules.logs_analytics import compute_analytics
from modules.logs_exporter import display_dashboard, export_summary

# Constants
DEFAULT_LOG_FILE = "logs.json"

# Function 1: run_interactive_pipeline
def run_interactive_pipeline(dataset_path: str = DEFAULT_LOG_FILE) -> None:
    """ Runs the interactive console menu for the LogMetrics suite. """
    
    print("\n" + "=" * 65)
    print("        LogMetrics: JSON-Based Log File Analyzer")
    print("=" * 65)
    print(f"[*] Ingesting log dataset from: '{dataset_path}'...")

    raw_logs, malformed = load_logs(dataset_path)
    
    if not raw_logs:
        print(f"[-] No valid logs loaded. Please check if '{dataset_path}' exists.")
        return

    print(f"[+] Ingestion complete: {len(raw_logs):,} valid entries loaded ({malformed} skipped/malformed).")

    active_logs = raw_logs

    while True:
        print("\n" + "-" * 50)
        print("                 MAIN MENU")
        print("-" * 50)
        print(f" Currently Active Logs: {len(active_logs):,} / {len(raw_logs):,}")
        print(" [1] View Telemetry Dashboard (Health, Statuses, Threats)")
        print(" [2] Quick Filter: Show Only Errors (HTTP 4xx & 5xx)")
        print(" [3] Quick Filter: Show Only Specific Route / Endpoint")
        print(" [4] Quick Filter: Filter by Client IP Address")
        print(" [5] Advanced Search: Regex Pattern or Keyword Match")
        print(" [6] Security Anomaly Scan (Brute-Force & Spike Audit)")
        print(" [7] Reset Filters (Restore All Logs)")
        print(" [8] Export Reports (JSON, CSV, Markdown, HTML Visual)")
        print(" [0] Exit Application")
        print("-" * 50)

        choice = input("Enter choice [0-8]: ").strip()

        if choice == "1":
            analytics = compute_analytics(active_logs)
            display_dashboard(analytics)

        elif choice == "2":
            active_logs = filter_logs(active_logs, status_code_min=400)
            print(f"[+] Applied: Error Filter (>= 400). Records matched: {len(active_logs):,}")
            analytics = compute_analytics(active_logs)
            display_dashboard(analytics, preview_limit=10)

        elif choice == "3":
            endpoint = input("Enter target endpoint route (e.g., /api/v1/products): ").strip()
            
            if endpoint:
                active_logs = filter_logs(active_logs, endpoint=endpoint)  
                print(f"[+] Applied: Route Filter ('{endpoint}'). Records matched: {len(active_logs):,}")
                analytics = compute_analytics(active_logs)
                display_dashboard(analytics, preview_limit=10)

        elif choice == "4":
            ip_query = input("Enter client IP address: ").strip()
            
            if ip_query:
                active_logs = filter_logs(active_logs, ip=ip_query)
                print(f"[+] Applied: IP Filter ('{ip_query}'). Records matched: {len(active_logs):,}")
                analytics = compute_analytics(active_logs)
                display_dashboard(analytics, preview_limit=10)

        elif choice == "5":
            pattern = input("Enter keyword or regex pattern: ").strip()
            
            if pattern:
                try:
                    active_logs = filter_logs(active_logs, regex=pattern)
                    print(f"[+] Applied Regex/Keyword Match. Records matched: {len(active_logs):,}")
                    analytics = compute_analytics(active_logs)
                    display_dashboard(analytics, preview_limit=10)
                except ValueError as err:
                    print(f"[-] Query error: {err}")

        elif choice == "6":
            print("\n[*] Performing deep security threat inspection...")
            
            analytics = compute_analytics(active_logs)
            sec = analytics["security"]
            brute = sec.get("brute_force_warnings", [])
            spikes = sec.get("traffic_spikes", [])

            print("\n--- SECURITY AUDIT REPORT ---")
            
            if brute:
                print(f"[!] Flagged {len(brute)} Suspicious IPs with repeated auth/forbidden failures:")
                
                for b in brute:
                    print(f"    - IP: {b['ip']} | Failed Attempts: {b['failures']} ({b['threat']})")
            else:
                print("[+] No brute-force or unauthorized scanning patterns detected.")

            if spikes:
                print("\n[!] Top Traffic Concentration Windows (5-min buckets):")
                
                for s in spikes:
                    print(f"    - Window: {s['window']} UTC | Volume: {s['request_count']} requests")
                    
            print("------------------------------")

        elif choice == "7":
            active_logs = raw_logs
            print(f"[+] Filters reset. All {len(active_logs):,} logs restored.")

        elif choice == "8":
            analytics = compute_analytics(active_logs)
            print("\nSelect export format:")
            print(" [a] Summary JSON (.json)")
            print(" [b] Flagged Errors CSV (.csv)")
            print(" [c] Markdown Audit Report (.md)")
            print(" [d] Interactive HTML Dashboard (.html with Chart.js)")
            print(" [e] Export All Formats")
            exp_choice = input("Enter export format [a/b/c/d/e]: ").strip().lower()

            if exp_choice == "a":
                export_summary(analytics, "json", "summary.json")
            elif exp_choice == "b":
                export_summary(analytics, "csv", "flagged_errors.csv")
            elif exp_choice == "c":
                export_summary(analytics, "md", "audit_summary.md")
            elif exp_choice == "d":
                export_summary(analytics, "html", "dashboard.html")
            elif exp_choice == "e":
                export_summary(analytics, "json", "summary.json")
                export_summary(analytics, "csv", "flagged_errors.csv")
                export_summary(analytics, "md", "audit_summary.md")
                export_summary(analytics, "html", "dashboard.html")
            else:
                print("[-] Invalid export selection.")

        elif choice == "0":
            print("[*] Exiting LogMetrics. Goodbye!")
            break
        else:
            print("[-] Invalid option. Please choose between 0 and 8.")

# Function 2: main
def main() -> None:
    """ Entry point supporting both CLI argument automation and interactive mode ."""
    
    parser = argparse.ArgumentParser(description="LogMetrics: Structured JSON Log Analyzer & Threat Profiler")
    parser.add_argument("-f", "--file", default=DEFAULT_LOG_FILE, help="Path to logs JSON or JSON-Lines file")
    parser.add_argument("--status", type=int, help="Filter by exact HTTP status code (e.g., 500)")
    parser.add_argument("--errors-only", action="store_true", help="Filter for only error responses (>= 400)")
    parser.add_argument("--ip", help="Filter by client IP address")
    parser.add_argument("--export", choices=["json", "csv", "md", "html", "all"], help="Auto-export summary format")
    args = parser.parse_args()

    if len(sys.argv) == 1:
        run_interactive_pipeline(args.file)
        return

    print(f"[*] Ingesting logs from: {args.file}")
    logs, malformed = load_logs(args.file)
    
    if not logs:
        print("[-] Failed to load logs. Aborting.")
        sys.exit(1)

    filtered = logs
    
    if args.errors_only:
        filtered = filter_logs(filtered, status_code_min=400)
    if args.status:
        filtered = filter_logs(filtered, status_code=args.status)
    if args.ip:
        filtered = filter_logs(filtered, ip=args.ip)

    analytics = compute_analytics(filtered)
    display_dashboard(analytics)

    if args.export:
        if args.export == "all":
            for fmt in ["json", "csv", "md", "html"]:
                export_summary(analytics, fmt)
        else:
            export_summary(analytics, args.export)

# Running the Application
if __name__ == "__main__":
    main()