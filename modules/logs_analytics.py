# LogMetrics (JSON-Based Log File Analyzer) - modules/logs_analytics.py

"""
Statistical Profiler & Security Anomaly Detection Engine

Generates numerical metrics, detects security anomalies, evaluates server uptime,
and profiles endpoint and IP distributions.
"""

# Imports
import math
from datetime import datetime
from collections import Counter, defaultdict
from typing import Any, Dict, List, Optional

# Function 1: _parse_timestamp (Internal)
def _parse_timestamp(val: Any) -> Optional[datetime]:
    """ Parse timestamp into datetime object for time-bucket analysis. """
    
    if not isinstance(val, str) or not val.strip():
        return None
    
    text = val.strip()
    
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
        
    try:
        return datetime.fromisoformat(text)
    except (ValueError, TypeError):
        return None

# Function 2: calculate_health_score
def calculate_health_score(status_counts: Dict[int, int]) -> Dict[str, Any]:
    """
    Computes server health metrics:
    1. Overall Reliability Score: Ratio of successful (2xx, 3xx) to total requests.
    2. Operational Health Score: Ratio of 200 OK vs 500 Internal Server Errors.
    """
    
    total = sum(status_counts.values())
    
    if total == 0:
        return {"uptime_score": 100.0, "status": "UNKNOWN", "healthy_requests": 0, "failed_requests": 0}

    successes = sum(count for code, count in status_counts.items() if 200 <= code < 400)
    server_errors = sum(count for code, count in status_counts.items() if code >= 500)
    client_errors = sum(count for code, count in status_counts.items() if 400 <= code < 500)

    uptime_score = round((successes / total) * 100, 2)

    ok_200 = status_counts.get(200, 0)
    err_500 = status_counts.get(500, 0)
    direct_ratio = round((ok_200 / (ok_200 + err_500)) * 100, 2) if (ok_200 + err_500) > 0 else 100.0

    if uptime_score >= 95.0:
        health_grade = "EXCELLENT"
    elif uptime_score >= 85.0:
        health_grade = "STABLE"
    elif uptime_score >= 70.0:
        health_grade = "DEGRADED"
    else:
        health_grade = "CRITICAL"

    return {
        "uptime_score": uptime_score,
        "direct_200_vs_500_score": direct_ratio,
        "health_grade": health_grade,
        "total_requests": total,
        "success_count": successes,
        "client_error_count": client_errors,
        "server_error_count": server_errors,
    }

# Function 3: detect_security_anomalies
def detect_security_anomalies(logs: List[dict]) -> Dict[str, Any]:
    """
    Detects potential security threats:
    - Brute Force / Scanning: High frequency of 401 Unauthorized or 403 Forbidden per IP.
    - Traffic Surge / Simulated DDoS: IP or bucket exceeding normal request thresholds.
    """
    
    auth_failures_by_ip = Counter()
    total_requests_by_ip = Counter()
    time_buckets = Counter()

    for log in logs:
        ip = log.get("ip", "UNKNOWN")
        status = log.get("status_code")
        total_requests_by_ip[ip] += 1

        if status in (401, 403):
            auth_failures_by_ip[ip] += 1

        dt = _parse_timestamp(log.get("timestamp"))
        
        if dt:
            minute_bucket = (dt.minute // 5) * 5
            bucket_key = dt.strftime(f"%Y-%m-%d %H:{minute_bucket:02d}")
            time_buckets[bucket_key] += 1

    flagged_brute_force = [
        {"ip": ip, "failures": count, "threat": "Brute Force / Auth Scan Attempt"}
        for ip, count in auth_failures_by_ip.most_common()
        if count >= 3
    ]

    flagged_surges = [
        {"window": window, "request_count": count, "threat": "Potential Traffic Surge / Spike"}
        for window, count in time_buckets.most_common(5)
    ]

    return {
        "brute_force_warnings": flagged_brute_force,
        "traffic_spikes": flagged_surges,
        "total_suspicious_ips": len(flagged_brute_force),
    }

# Function 4: compute_analytics
def compute_analytics(logs: List[dict]) -> Dict[str, Any]:
    """
    Computes full telemetry analytics:
    - Status code & log level distribution
    - Top 5 hit endpoints & top 5 active IPs
    - Bandwidth & payload consumption
    - Performance latency percentiles (if available)
    - Server uptime & security threat analysis
    """
    
    total_logs = len(logs)
    
    if total_logs == 0:
        return {
            "total_logs": 0,
            "insights": ["No logs available for analysis."],
            "health": calculate_health_score({}),
            "security": {"brute_force_warnings": [], "traffic_spikes": [], "total_suspicious_ips": 0},
            "level_distribution": {},
            "status_distribution": {},
            "top_endpoints": [],
            "top_ips": [],
            "bandwidth_bytes": 0,
            "latency_metrics": None,
            "logs": [],
        }

    status_counts = Counter()
    level_counts = Counter()
    endpoint_counts = Counter()
    ip_counts = Counter()
    method_counts = Counter()
    hourly_traffic = Counter()

    total_bandwidth = 0
    latencies: List[float] = []

    for log in logs:
        code = log.get("status_code")
        
        if code is not None:
            status_counts[code] += 1

        lvl = log.get("level", "INFO")
        level_counts[lvl] += 1

        ep = log.get("endpoint", "/")
        endpoint_counts[ep] += 1

        ip = log.get("ip", "UNKNOWN")
        ip_counts[ip] += 1

        method = log.get("method", "GET")
        method_counts[method] += 1

        total_bandwidth += log.get("bytes_sent", 0)
        latency = log.get("response_time_ms")
        
        if latency is not None:
            latencies.append(latency)

        dt = _parse_timestamp(log.get("timestamp"))
        
        if dt:
            hourly_traffic[dt.strftime("%H:00 UTC")] += 1

    latency_summary = None
    
    if latencies:
        latencies.sort()
        avg_lat = round(sum(latencies) / len(latencies), 2)
        p95_idx = int(math.ceil(0.95 * len(latencies))) - 1
        latency_summary = {
            "min_ms": round(latencies[0], 2),
            "avg_ms": avg_lat,
            "max_ms": round(latencies[-1], 2),
            "p95_ms": round(latencies[p95_idx], 2),
        }

    health = calculate_health_score(status_counts)
    security = detect_security_anomalies(logs)

    insights = [
        f"Analyzed {total_logs:,} total requests with a system health score of {health['uptime_score']}%.",
        f"Server uptime reliability is graded as: {health['health_grade']}.",
        f"Total bandwidth consumed across monitored traffic: {total_bandwidth / (1024 * 1024):.2f} MB.",
        f"Most frequently requested route: '{endpoint_counts.most_common(1)[0][0]}' with {endpoint_counts.most_common(1)[0][1]:,} hits.",
    ]

    if security["total_suspicious_ips"] > 0:
        insights.append(f"Security Alert: Flagged {security['total_suspicious_ips']} IP(s) exhibiting repeated unauthorized/forbidden attempts.")
    else:
        insights.append("No active credential brute-force or unauthorized scanning patterns detected.")

    if latency_summary:
        insights.append(f"Response latency average: {latency_summary['avg_ms']} ms (P95: {latency_summary['p95_ms']} ms).")

    return {
        "total_logs": total_logs,
        "insights": insights,
        "health": health,
        "security": security,
        "level_distribution": dict(level_counts),
        "status_distribution": dict(status_counts),
        "method_distribution": dict(method_counts),
        "top_endpoints": endpoint_counts.most_common(5),
        "top_ips": ip_counts.most_common(5),
        "hourly_traffic": dict(sorted(hourly_traffic.items())),
        "total_bandwidth_bytes": total_bandwidth,
        "latency_metrics": latency_summary,
        "logs": logs,
    }

# Running the Application
if __name__ == "__main__":
    import json
    from logs_loader import load_logs

    records, _ = load_logs("../logs.json")
    results = compute_analytics(records)
    
    print("Health Score:", results["health"])
    print("Security Anomalies:", results["security"]["total_suspicious_ips"])
    print("Top Endpoints:", results["top_endpoints"])