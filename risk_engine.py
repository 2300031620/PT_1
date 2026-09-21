"""
Ransomware Behavioral Detection Engine
---------------------------------------
Simple rule-based behavioral detection engine monitoring:
  1. Rapid file modifications
  2. Mass file modifications
  3. Rapid file renames
  4. Mass deletion
  5. Suspicious extension changes
  6. Protected-file modification
  7. Excessive file activity within a short period

Generates a 0-100 risk score and classifies severity:
  - NORMAL     (0-29)
  - SUSPICIOUS (30-59)
  - HIGH       (60-79)
  - CRITICAL   (80-100)

Returns:
  - risk_score
  - severity
  - reason
  - recommended_action
"""

from typing import Dict, Any, List

def calculate_severity(score: int) -> str:
    """Classify 0-100 score into severity bands."""
    if score >= 80:
        return "CRITICAL"
    elif score >= 60:
        return "HIGH"
    elif score >= 30:
        return "SUSPICIOUS"
    else:
        return "NORMAL"

def evaluate_risk(
    mod_count: int = 0,
    rename_count: int = 0,
    delete_count: int = 0,
    create_count: int = 0,
    total_activity_count: int = 0,
    has_ransomware_extension: bool = False,
    protected_file_tampered: bool = False,
    time_window: int = 10,
    matched_suspicious_files: List[str] = None
) -> Dict[str, Any]:
    """
    Rule-based ransomware behavioral detection engine.
    Calculates 0-100 risk score and returns structured detection diagnostics.
    """
    score = 10  # Baseline nominal background activity
    reasons: List[str] = []

    # Calculate total activity if not passed explicitly
    if total_activity_count <= 0:
        total_activity_count = mod_count + rename_count + delete_count + create_count

    # Rule 1 & 2: Rapid file modifications vs Mass file modifications
    if mod_count >= 10:
        score += 55
        reasons.append(f"Mass file modifications ({mod_count} in {time_window}s)")
    elif mod_count >= 4:
        score += 30
        reasons.append(f"Rapid file modifications ({mod_count} in {time_window}s)")
    elif mod_count >= 1 and total_activity_count <= 2 and not has_ransomware_extension and not protected_file_tampered:
        # Benign baseline file modification
        score = 15

    # Rule 3: Rapid file renames
    if rename_count >= 4:
        score += 50
        reasons.append(f"Rapid file renames ({rename_count} in {time_window}s)")
    elif rename_count >= 2:
        score += 25
        reasons.append(f"Multiple file renames detected ({rename_count} in {time_window}s)")

    # Rule 4: Mass deletion
    if delete_count >= 4:
        score += 50
        reasons.append(f"Mass deletion detected ({delete_count} files removed in {time_window}s)")
    elif delete_count >= 2:
        score += 25
        reasons.append(f"Multiple deletions detected ({delete_count} files in {time_window}s)")

    # Rule 5: Suspicious extension changes
    if has_ransomware_extension:
        score += 72
        ext_desc = f": {', '.join(matched_suspicious_files[:3])}" if matched_suspicious_files else ""
        reasons.append(f"Suspicious extension changes detected (known ransomware signature{ext_desc})")

    # Rule 6: Protected-file modification
    if protected_file_tampered:
        score += 52
        reasons.append("Protected-file modification detected on prioritized asset")

    # Rule 7: Excessive file activity within a short period
    if total_activity_count >= 12:
        score += 52
        reasons.append(f"Excessive file activity within a short period ({total_activity_count} operations in {time_window}s)")

    # Normalize and clamp score strictly between 0 and 100
    risk_score = max(0, min(100, score))
    severity = calculate_severity(risk_score)

    # Determine recommended automated / operational containment action
    if severity == "CRITICAL":
        recommended_action = "CONTAIN"
    elif severity == "HIGH":
        recommended_action = "ALERT"
    elif severity == "SUSPICIOUS":
        recommended_action = "MONITOR"
    else:
        recommended_action = "NONE"

    reason_str = "; ".join(reasons) if reasons else "Normal file activity observed"

    return {
        "risk_score": risk_score,
        "severity": severity,
        "reason": reason_str,
        "recommended_action": recommended_action
    }
