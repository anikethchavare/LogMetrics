# LogMetrics (JSON-Based Log File Analyzer) - modules/logs_filter.py

"""
Query & Filtering Engine

Provides multi-criteria search and programmatic filtering over canonical logs:
- Status code matching & numeric bounds
- Timestamp range slicing (ISO-8601 UTC)
- Keyword & Regex pattern matching
- Field-specific exact matches (method, endpoint, ip)
"""

# Imports
import re
from datetime import datetime, timezone
from typing import Any, Iterable, List, Optional, Set

# Function 1: _parse_timestamp (Internal)
def _parse_timestamp(value: Any) -> Optional[datetime]:
    """ Safely parse an ISO-8601 timestamp into a UTC datetime object. """
    
    if not isinstance(value, str) or not value.strip():
        return None
    
    text = value.strip()
    
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
        
    try:
        parsed = datetime.fromisoformat(text)
        
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
            
        return parsed.astimezone(timezone.utc)
    except (ValueError, TypeError, OverflowError):
        return None

# Function 2: _status (Internal)
def _status(log: dict) -> Optional[int]:
    """ Read status code from canonical log dictionary. """
    
    value = log.get("status_code", log.get("status"))
    
    try:
        return int(value)
    except (TypeError, ValueError, OverflowError):
        return None

# Function 3: _searchable_text (Internal)
def _searchable_text(log: dict) -> str:
    """ Build composite text string for keyword and regex inspection. """
    
    fields = (
        "message", "endpoint", "path", "method", "ip",
        "user_agent", "referer", "protocol", "level"
    )
    parts = []
    
    for field in fields:
        val = log.get(field)
        
        if val is not None:
            parts.append(str(val))
            
    return " ".join(parts)

# Function 4: filter_logs
def filter_logs(logs: Iterable[dict], **kwargs) -> List[dict]:
    """
    Return log entries matching all supplied filter criteria.

    Supported keyword arguments:
      - level (str): "ERROR", "WARN", "INFO"
      - start_time (str): Earliest ISO-8601 timestamp (inclusive)
      - end_time (str): Latest ISO-8601 timestamp (inclusive)
      - status_code (int): Exact HTTP status code
      - status_code_min (int): Minimum status code (inclusive, e.g. 400)
      - status_code_max (int): Maximum status code (inclusive, e.g. 499)
      - keyword (str): Case-insensitive substring match
      - regex (str): Regular expression pattern match
      - method (str): HTTP method (e.g. "GET", "POST", "DELETE")
      - endpoint (str) / path (str): Target path/route
      - ip (str): Client IP address
    """
    
    allowed_keys: Set[str] = {
        "level", "start_time", "end_time",
        "status_code_min", "status_code_max", "status_code", "status",
        "keyword", "regex", "method", "endpoint", "path", "ip"
    }
    unknown = set(kwargs) - allowed_keys
    
    if unknown:
        raise ValueError(f"Unsupported filter parameter(s): {', '.join(sorted(unknown))}")

    start_dt = None
    end_dt = None
    
    if kwargs.get("start_time") is not None:
        start_dt = _parse_timestamp(kwargs["start_time"])
        
        if start_dt is None:
            raise ValueError("start_time must be a valid ISO-8601 timestamp")
        
    if kwargs.get("end_time") is not None:
        end_dt = _parse_timestamp(kwargs["end_time"])
        
        if end_dt is None:
            raise ValueError("end_time must be a valid ISO-8601 timestamp")
        
    if start_dt and end_dt and start_dt > end_dt:
        raise ValueError("start_time must be earlier than or equal to end_time")

    pattern = None
    
    if kwargs.get("regex") is not None:
        try:
            pattern = re.compile(str(kwargs["regex"]), re.IGNORECASE)
        except re.error as exc:
            raise ValueError(f"Invalid regular expression: {exc}") from exc

    raw_exact_status = kwargs.get("status_code", kwargs.get("status"))
    exact_status = int(raw_exact_status) if raw_exact_status is not None else None
    min_status = int(kwargs["status_code_min"]) if kwargs.get("status_code_min") is not None else None
    max_status = int(kwargs["status_code_max"]) if kwargs.get("status_code_max") is not None else None
    target_endpoint = kwargs.get("endpoint", kwargs.get("path"))

    filtered: List[dict] = []
    
    for log in logs:
        if not isinstance(log, dict):
            continue

        if kwargs.get("level") is not None:
            expected_lvl = str(kwargs["level"]).strip().upper()
            actual_lvl = str(log.get("level", "")).strip().upper()
            
            if actual_lvl != expected_lvl:
                continue

        if start_dt or end_dt:
            dt = _parse_timestamp(log.get("timestamp"))
            
            if dt is None:
                continue
            if start_dt and dt < start_dt:
                continue
            if end_dt and dt > end_dt:
                continue

        code = _status(log)
        
        if exact_status is not None and code != exact_status:
            continue
        if min_status is not None and (code is None or code < min_status):
            continue
        if max_status is not None and (code is None or code > max_status):
            continue

        if kwargs.get("method") is not None:
            if str(log.get("method", "")).upper() != str(kwargs["method"]).upper():
                continue

        if target_endpoint is not None:
            curr_ep = log.get("endpoint", log.get("path", ""))
            
            if str(curr_ep).casefold() != str(target_endpoint).casefold():
                continue

        if kwargs.get("ip") is not None:
            if str(log.get("ip", "")).strip() != str(kwargs["ip"]).strip():
                continue

        if kwargs.get("keyword") or pattern:
            searchable = _searchable_text(log)
            
            if kwargs.get("keyword") and str(kwargs["keyword"]).casefold() not in searchable.casefold():
                continue
            if pattern and pattern.search(searchable) is None:
                continue

        filtered.append(log)

    return filtered

# Running the Application
if __name__ == "__main__":
    from logs_loader import load_logs

    sample_logs, _ = load_logs("../logs.json")
    print(f"Total Loaded Logs: {len(sample_logs)}")

    server_errors = filter_logs(sample_logs, status_code_min=500)
    print(f"Server Errors (5xx): {len(server_errors)}")

    auth_requests = filter_logs(sample_logs, keyword="profile")
    print(f"Profile API requests: {len(auth_requests)}")