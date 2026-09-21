#!/usr/bin/env python3
"""
Unit test suite verifying the 7 Ransomware Behavioral Detection Rules.
Ensures risk_score (0-100), severity, reason, and recommended_action are strictly returned.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

try:
    from detector import RansomwareDetector
    from risk_engine import evaluate_risk, calculate_severity
except ImportError:
    from endpoint_agent.detector import RansomwareDetector
    from endpoint_agent.risk_engine import evaluate_risk, calculate_severity

def test_risk_engine_direct():
    print("=== Direct Rule Evaluation Verification ===")
    
    # Baseline Normal
    res = evaluate_risk(mod_count=1, total_activity_count=1)
    print("1. Normal Edit:", res)
    assert res["severity"] == "NORMAL"
    assert res["recommended_action"] == "NONE"
    assert 0 <= res["risk_score"] <= 29

    # 1. Rapid File Modifications (e.g. 5 edits in window)
    res = evaluate_risk(mod_count=5)
    print("2. Rapid File Modifications:", res)
    assert res["severity"] in ["SUSPICIOUS", "HIGH"]
    assert "Rapid file modifications" in res["reason"]

    # 2. Mass File Modifications (e.g. 11 edits in window)
    res = evaluate_risk(mod_count=11)
    print("3. Mass File Modifications:", res)
    assert res["severity"] in ["HIGH", "CRITICAL"]
    assert "Mass file modifications" in res["reason"]

    # 3. Rapid File Renames (e.g. 4 renames)
    res = evaluate_risk(rename_count=4)
    print("4. Rapid File Renames:", res)
    assert "Rapid file renames" in res["reason"]
    assert res["risk_score"] >= 45

    # 4. Mass Deletions (e.g. 4 deletions)
    res = evaluate_risk(delete_count=4)
    print("5. Mass Deletion:", res)
    assert "Mass deletion" in res["reason"]
    assert res["risk_score"] >= 45

    # 5. Suspicious Extension Changes (.locked, .enc)
    res = evaluate_risk(has_ransomware_extension=True, matched_suspicious_files=["data.xlsx.locked"])
    print("6. Suspicious Extension (.locked):", res)
    assert "Suspicious extension changes" in res["reason"]
    assert res["risk_score"] >= 70

    # 6. Protected-File Modification (database.sql)
    res = evaluate_risk(protected_file_tampered=True)
    print("7. Protected-File Modification:", res)
    assert "Protected-file modification" in res["reason"]
    assert res["risk_score"] >= 40

    # 7. Excessive File Activity Burst (14 ops)
    res = evaluate_risk(total_activity_count=14)
    print("8. Excessive Activity:", res)
    assert "Excessive file activity" in res["reason"]
    assert res["risk_score"] >= 35

    # Combined Ransomware Attack Pattern (.locked + rapid renames + mass edits)
    res = evaluate_risk(
        mod_count=10,
        rename_count=6,
        has_ransomware_extension=True,
        protected_file_tampered=True,
        total_activity_count=16
    )
    print("9. Full Ransomware Pattern:", res)
    assert res["severity"] == "CRITICAL"
    assert res["recommended_action"] == "CONTAIN"
    assert res["risk_score"] >= 80

    print("[+] All 7 Behavioral Rules Verified Successfully!\n")

def test_detector_stream():
    print("=== Stateful Rolling Window Detector Verification ===")
    detector = RansomwareDetector(window_seconds=10)

    # Ingest normal event
    d1 = detector.process_event("MODIFY", "C:\\Users\\User\\Documents\\readme.txt")
    print("D1 (Normal):", d1["severity"], d1["risk_score"], d1["recommended_action"])
    assert d1["severity"] == "NORMAL"

    # Ingest rapid edits
    for i in range(5):
        detector.process_event("MODIFY", f"C:\\Users\\User\\Documents\\test_{i}.csv")
    d2 = detector.process_event("MODIFY", "C:\\Users\\User\\Documents\\test_final.csv")
    print("D2 (Rapid Mods):", d2["severity"], d2["risk_score"], d2["reason"])
    assert d2["severity"] in ["SUSPICIOUS", "HIGH"]

    # Ingest ransomware extension rename
    d3 = detector.process_event("RENAME", "C:\\Users\\User\\Documents\\database.sql.locked", old_path="C:\\Users\\User\\Documents\\database.sql")
    print("D3 (Ransomware .locked):", d3["severity"], d3["risk_score"], d3["recommended_action"])
    assert d3["severity"] == "CRITICAL"
    assert d3["recommended_action"] == "CONTAIN"

    print("[+] Stateful Detector Rolling Stream Verified Successfully!\n")

if __name__ == "__main__":
    test_risk_engine_direct()
    test_detector_stream()
