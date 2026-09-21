"""
Ransomware Behavioral Detector
------------------------------
Monitors real-time file system events from watchdog within a rolling time window
and applies the rule-based behavioral detection engine.

Detects:
  - Rapid file modifications
  - Mass file modifications
  - Rapid file renames
  - Mass deletion
  - Suspicious extension changes (.locked, .crypto, .enc, etc.)
  - Protected-file modification (database.sql, project.zip, etc.)
  - Excessive file activity within a short period
"""

import os
import time
from collections import deque
from typing import Dict, Any, List, Optional

try:
    from .config import (
        TIME_WINDOW_SECONDS,
        SUSPICIOUS_EXTENSIONS,
        PROTECTED_FILENAMES
    )
    from .risk_engine import evaluate_risk
except ImportError:
    from config import (
        TIME_WINDOW_SECONDS,
        SUSPICIOUS_EXTENSIONS,
        PROTECTED_FILENAMES
    )
    from risk_engine import evaluate_risk


class RansomwareDetector:
    """
    Stateful rolling sliding-window behavioral detector for file system events.
    """

    def __init__(self, window_seconds: int = TIME_WINDOW_SECONDS):
        self.window_seconds = window_seconds
        # Rolling event window items: (timestamp, event_type, path, is_protected, is_susp_ext)
        self.events_window = deque()
        self.contained = False

    def is_protected_file(self, filepath: str) -> bool:
        """Checks if file is on the prioritized critical protected files list."""
        basename = os.path.basename(filepath).lower()
        return any(basename == p.lower() for p in PROTECTED_FILENAMES)

    def has_ransomware_extension(self, filepath: str) -> bool:
        """Checks if filename ends with known ransomware/encryption extensions."""
        lower = filepath.lower()
        return any(lower.endswith(ext.lower()) for ext in SUSPICIOUS_EXTENSIONS)

    def prune_stale_events(self):
        """Discards events outside the active sliding time window."""
        cutoff = time.time() - self.window_seconds
        while self.events_window and self.events_window[0][0] < cutoff:
            self.events_window.popleft()

    def process_event(self, event_type: str, filepath: str, old_path: Optional[str] = None) -> Dict[str, Any]:
        """
        Ingests a new event from watchdog, updates rolling sliding window,
        and recalculates the real-time ransomware risk score and diagnostics.
        """
        now = time.time()
        is_prot = self.is_protected_file(filepath) or (old_path is not None and self.is_protected_file(old_path))
        is_susp_ext = self.has_ransomware_extension(filepath)

        self.events_window.append((now, event_type, filepath, is_prot, is_susp_ext))
        self.prune_stale_events()

        # Aggregate counts in the rolling window
        mod_count = 0
        rename_count = 0
        delete_count = 0
        create_count = 0
        matched_suspicious_files: List[str] = []
        has_susp_ext_in_window = False
        protected_tampered_in_window = False

        for (ts, ev_t, path, prot, susp_ext) in self.events_window:
            norm_type = ev_t.upper()
            if "MODIFY" in norm_type:
                mod_count += 1
            elif "RENAME" in norm_type or "MOVE" in norm_type:
                rename_count += 1
            elif "DELETE" in norm_type:
                delete_count += 1
            elif "CREATE" in norm_type:
                create_count += 1

            if susp_ext:
                has_susp_ext_in_window = True
                matched_suspicious_files.append(os.path.basename(path))

            if prot and any(k in norm_type for k in ["MODIFY", "DELETE", "RENAME", "MOVE"]):
                protected_tampered_in_window = True

        total_activity_count = len(self.events_window)

        # Run behavioral detection engine
        evaluation = evaluate_risk(
            mod_count=mod_count,
            rename_count=rename_count,
            delete_count=delete_count,
            create_count=create_count,
            total_activity_count=total_activity_count,
            has_ransomware_extension=has_susp_ext_in_window,
            protected_file_tampered=protected_tampered_in_window,
            time_window=self.window_seconds,
            matched_suspicious_files=matched_suspicious_files
        )

        return {
            **evaluation,
            "window_summary": {
                "window_seconds": self.window_seconds,
                "total_events": total_activity_count,
                "modifications": mod_count,
                "renames": rename_count,
                "deletions": delete_count,
                "creations": create_count,
                "is_current_file_protected": is_prot,
                "is_current_file_suspicious_extension": is_susp_ext
            }
        }
