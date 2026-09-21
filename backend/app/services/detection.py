"""
Backend Ransomware Behavioral Detection Engine
-----------------------------------------------
Evaluates incoming file events on the FastAPI backend using sliding window
heuristics to calculate real-time risk scores and classify severities:
  - Rapid file modifications
  - Mass file modifications
  - Rapid file renames
  - Mass deletion
  - Suspicious extension changes
  - Protected-file modification
  - Excessive file activity within a short period

Returns:
  - risk_score (0-100)
  - severity (NORMAL, SUSPICIOUS, HIGH, CRITICAL)
  - reason
  - recommended_action (NONE, MONITOR, ALERT, CONTAIN)
"""

import os
from datetime import datetime, timedelta
from typing import List, Dict, Any

SUSPICIOUS_EXTENSIONS = [
    ".locked", ".crypto", ".enc", ".crypted", ".ransom",
    ".wnry", ".crypt", ".locky", ".darkness", ".payme"
]

def calculate_severity(score: int) -> str:
    if score >= 80:
        return "CRITICAL"
    elif score >= 60:
        return "HIGH"
    elif score >= 30:
        return "SUSPICIOUS"
    else:
        return "NORMAL"

def evaluate_backend_behavior(
    recent_events: List[Dict[str, Any]],
    protected_paths: List[str] = None,
    time_window_seconds: int = 15
) -> Dict[str, Any]:
    """
    Evaluates file system events in the rolling time window.
    """
    score = 10
    reasons: List[str] = []
    protected_set = set([p.lower() for p in (protected_paths or [])])

    # Filter events within rolling time window
    now = datetime.utcnow()
    cutoff = now - timedelta(seconds=time_window_seconds)

    window_events = []
    for ev in recent_events:
        ts_str = ev.get("timestamp")
        if not ts_str:
            continue
        try:
            # Handle ISO string variations
            cleaned = ts_str.replace("Z", "+00:00")
            ev_dt = datetime.fromisoformat(cleaned)
            # Make timezone naive if needed for comparison
            if ev_dt.tzinfo is not None:
                ev_dt = ev_dt.astimezone().replace(tzinfo=None)
            if ev_dt >= cutoff:
                window_events.append(ev)
        except Exception:
            # If date parse fails, include if in first 10 events
            if len(window_events) < 10:
                window_events.append(ev)

    mod_count = 0
    rename_count = 0
    delete_count = 0
    create_count = 0
    has_ransomware_ext = False
    protected_tampered = False
    matched_extensions = []

    for ev in window_events:
        ev_type = str(ev.get("event_type", "")).upper()
        f_path = str(ev.get("file_path", "")).lower()
        old_path = str(ev.get("old_path", "")).lower()

        if "MODIFY" in ev_type:
            mod_count += 1
        elif "RENAME" in ev_type or "MOVE" in ev_type:
            rename_count += 1
        elif "DELETE" in ev_type:
            delete_count += 1
        elif "CREATE" in ev_type:
            create_count += 1

        for ext in SUSPICIOUS_EXTENSIONS:
            if f_path.endswith(ext):
                has_ransomware_ext = True
                matched_extensions.append(ext)

        # Check protected file tamper
        if ev.get("is_protected") or any(prot in f_path for prot in protected_set) or (old_path and any(prot in old_path for prot in protected_set)):
            if any(k in ev_type for k in ["MODIFY", "DELETE", "RENAME", "MOVE"]):
                protected_tampered = True

    total_activity = len(window_events)

    # 1 & 2: Rapid vs Mass modifications
    if mod_count >= 10:
        score += 55
        reasons.append(f"Mass file modifications ({mod_count} in {time_window_seconds}s)")
    elif mod_count >= 4:
        score += 30
        reasons.append(f"Rapid file modifications ({mod_count} in {time_window_seconds}s)")

    # 3: Rapid file renames
    if rename_count >= 4:
        score += 50
        reasons.append(f"Rapid file renames ({rename_count} in {time_window_seconds}s)")
    elif rename_count >= 2:
        score += 25
        reasons.append(f"Multiple file renames ({rename_count})")

    # 4: Mass deletion
    if delete_count >= 4:
        score += 50
        reasons.append(f"Mass deletion detected ({delete_count} files removed)")
    elif delete_count >= 2:
        score += 25
        reasons.append(f"Multiple deletions detected ({delete_count})")

    # 5: Suspicious extension changes
    if has_ransomware_ext:
        score += 72
        reasons.append(f"Suspicious extension changes detected ({', '.join(set(matched_extensions))})")

    # 6: Protected-file modification
    if protected_tampered:
        score += 52
        reasons.append("Protected-file modification detected on prioritized asset")

    # 7: Excessive file activity within a short period
    if total_activity >= 12:
        score += 52
        reasons.append(f"Excessive file activity burst ({total_activity} events in {time_window_seconds}s)")

    if mod_count == 1 and rename_count == 0 and delete_count == 0 and not has_ransomware_ext and not protected_tampered:
        score = 15

    risk_score = max(0, min(100, score))
    severity = calculate_severity(risk_score)

    recommended_action = "NONE"
    if severity == "CRITICAL":
        recommended_action = "CONTAIN"
    elif severity == "HIGH":
        recommended_action = "ALERT"
    elif severity == "SUSPICIOUS":
        recommended_action = "MONITOR"

    return {
        "risk_score": risk_score,
        "severity": severity,
        "reason": "; ".join(reasons) if reasons else "Normal file activity observed",
        "recommended_action": recommended_action
    }
