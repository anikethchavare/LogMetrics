# LogMetrics (JSON-Based Log File Analyzer) - modules/logs_loader.py

"""
Ingestion & Schema Normalization Engine

Safely loads JSON or JSON-Lines logs, handles malformed records,
and standardizes varying schemas into canonical LogMetrics records.
"""

# Imports
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Function 1: _normalize_entry (Internal)
def _normalize_entry(entry: Any) -> Optional[Dict[str, Any]]:
    """
    Normalizes a raw log entry dictionary into the canonical LogMetrics format.
    Accepts web server logs, API logs, and microservice format variants.
    """
    
    if not isinstance(entry, dict):
        return None

    timestamp = entry.get("timestamp") or entry.get("time") or entry.get("date")
    
    if not timestamp or not isinstance(timestamp, str):
        return None

    raw_status = entry.get("status_code", entry.get("status"))
    
    try:
        status_code = int(raw_status) if raw_status is not None else 200
    except (ValueError, TypeError):
        status_code = None

    raw_level = entry.get("level", entry.get("log_level"))
    
    if raw_level:
        level = str(raw_level).strip().upper()
    elif status_code is not None:
        if status_code >= 500:
            level = "ERROR"
        elif status_code >= 400:
            level = "WARN"
        else:
            level = "INFO"
    else:
        level = "INFO"

    endpoint = entry.get("endpoint", entry.get("path", entry.get("url", "")))
    
    if not endpoint:
        endpoint = "/"

    raw_bytes = entry.get("bytes_sent", entry.get("bytes", entry.get("size", 0)))
    
    try:
        bytes_sent = int(raw_bytes) if raw_bytes is not None else 0
    except (ValueError, TypeError):
        bytes_sent = 0

    raw_latency = entry.get("response_time_ms", entry.get("latency_ms", entry.get("response_time")))
    
    try:
        response_time_ms = float(raw_latency) if raw_latency is not None else None
    except (ValueError, TypeError):
        response_time_ms = None

    method = str(entry.get("method", "GET")).upper()
    message = entry.get("message")
    
    if not message:
        message = f"{method} {endpoint} -> {status_code or 'UNKNOWN'}"

    return {
        "log_id": str(entry.get("log_id", "")),
        "ip": str(entry.get("ip", entry.get("ip_address", "127.0.0.1"))),
        "timestamp": timestamp.strip(),
        "method": method,
        "endpoint": str(endpoint).strip(),
        "status_code": status_code,
        "bytes_sent": bytes_sent,
        "user_agent": str(entry.get("user_agent", "")),
        "referer": str(entry.get("referer", "")),
        "level": level,
        "response_time_ms": response_time_ms,
        "message": message,
    }

# Function 2: load_logs
def load_logs(filepath: str | Path) -> Tuple[List[Dict[str, Any]], int]:
    """
    Safely loads log records from:
      - Standard JSON with top-level {"logs": [...]} (Aayush's dataset)
      - Standard JSON containing a list [...]
      - Line-delimited JSON (.jsonl)

    Returns:
        valid_logs (list[dict]): Standardized log entries.
        malformed_count (int): Count of corrupt or unusable records skipped.
    """
    
    path = Path(filepath)
    
    if not path.is_file():
        print(f"[-] File not found: {path}")
        return [], 0

    valid_logs: List[Dict[str, Any]] = []
    malformed_count = 0

    try:
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
    except Exception as exc:
        print(f"[-] Error reading file '{path}': {exc}")
        return [], 0

    try:
        parsed = json.loads(content)
        raw_entries = []
        
        if isinstance(parsed, dict):
            if "logs" in parsed and isinstance(parsed["logs"], list):
                raw_entries = parsed["logs"]
            else:
                raw_entries = [parsed]
        elif isinstance(parsed, list):
            raw_entries = parsed

        for item in raw_entries:
            normalized = _normalize_entry(item)
            
            if normalized:
                valid_logs.append(normalized)
            else:
                malformed_count += 1

        return valid_logs, malformed_count
    except json.JSONDecodeError:
        pass

    for line in content.splitlines():
        line_str = line.strip()
        
        if not line_str:
            continue
        try:
            item = json.loads(line_str)
            normalized = _normalize_entry(item)
            
            if normalized:
                valid_logs.append(normalized)
            else:
                malformed_count += 1
        except json.JSONDecodeError:
            malformed_count += 1

    return valid_logs, malformed_count

# Running the Application
if __name__ == "__main__":
    import sys

    target = sys.argv[1] if len(sys.argv) > 1 else "../logs.json"
    logs, malformed = load_logs(target)
    
    print(f"Target: {target}")
    print(f"Loaded: {len(logs):,} records")
    print(f"Malformed: {malformed} records")
    
    if logs:
        print("\nSample canonical log record:")
        print(json.dumps(logs[0], indent=2))