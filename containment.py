"""
Endpoint Safe Containment Module
--------------------------------
Provides non-destructive endpoint containment and host isolation logic
designed specifically for cybersecurity student demonstrations.

When risk becomes CRITICAL:
1. An incident is reported.
2. The device is marked as CONTAINED.
3. The reason is recorded.
4. The timestamp is recorded.
5. Telemetry is sent to the backend / dashboard alert.

Safety Design:
- Avoids destructive system-wide actions (no killing arbitrary OS processes,
  no crashing system services, no cutting container networking).
- Simulates network and process quarantine via a persisted state manifest
  and console firewall emulation for student demonstration.
"""

import json
import os
from datetime import datetime, timezone
from typing import Dict, Any, Optional

STATE_FILE = os.path.join(os.path.dirname(__file__), "containment_state.json")


class SafeContainmentManager:
    """
    Manages the containment state of the local endpoint agent.
    Keeps operations strictly non-destructive for safe classroom/lab demonstration.
    """

    def __init__(self, device_id: str = "WINDOWS-PC-01"):
        self.device_id = device_id
        self.is_contained: bool = False
        self.contained_at: Optional[str] = None
        self.containment_reason: Optional[str] = None
        self.contained_by: Optional[str] = None
        self._load_state()

    def _load_state(self):
        """Loads persistent containment state if present."""
        if os.path.exists(STATE_FILE):
            try:
                with open(STATE_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    self.is_contained = data.get("is_contained", False)
                    self.contained_at = data.get("contained_at")
                    self.containment_reason = data.get("containment_reason")
                    self.contained_by = data.get("contained_by")
            except Exception:
                pass

    def _save_state(self):
        """Persists containment state to a local JSON file."""
        try:
            with open(STATE_FILE, "w", encoding="utf-8") as f:
                json.dump({
                    "device_id": self.device_id,
                    "is_contained": self.is_contained,
                    "status": "CONTAINED" if self.is_contained else "PROTECTED",
                    "contained_at": self.contained_at,
                    "containment_reason": self.containment_reason,
                    "contained_by": self.contained_by,
                    "safe_demo_mode": True,
                    "last_updated": datetime.now(timezone.utc).isoformat()
                }, f, indent=2)
        except Exception as err:
            print(f"[!] Warning: Failed to save containment state file: {err}")

    def contain_device(
        self,
        reason: str,
        operator: str = "Automated Heuristic Engine",
        role: str = "admin"
    ) -> Dict[str, Any]:
        """
        Executes safe student-demonstration containment.
        Marks the endpoint as CONTAINED, records the reason and timestamp,
        and displays simulated host isolation feedback.
        """
        now_iso = datetime.now(timezone.utc).isoformat()
        self.is_contained = True
        self.contained_at = now_iso
        self.containment_reason = reason
        self.contained_by = f"{operator} ({role})"
        self._save_state()

        print("\n" + "#" * 74)
        print("  [!] PREVENTIVE CONTAINMENT ACTIVATED - HOST ISOLATION ENFORCED")
        print("#" * 74)
        print(f"  Device ID        : {self.device_id}")
        print(f"  Status           : CONTAINED")
        print(f"  Timestamp        : {now_iso}")
        print(f"  Operator/Trigger : {self.contained_by}")
        print(f"  Reason           : {reason}")
        print("  Containment Actions (Safe Student Demonstration):")
        print("    [+] Simulated Outbound C2 Traffic Block: ENABLED")
        print("    [+] Monitored Directory Write-Protection Alert: ACTIVE")
        print("    [+] Simulated Ingress Port Filtering: RESTRICTED")
        print("    [+] System-Safe Guarantee: Non-destructive academic simulation mode.")
        print("#" * 74 + "\n")

        return {
            "status": "CONTAINED",
            "device_id": self.device_id,
            "contained_at": self.contained_at,
            "containment_reason": self.containment_reason,
            "contained_by": self.contained_by,
            "simulated_rules_applied": [
                "BLOCK_C2_OUTBOUND",
                "ISOLATE_MONITORED_PATHS",
                "FIREWALL_DEMO_RESTRICT_LATERAL"
            ]
        }

    def release_device(
        self,
        operator: str = "Security Admin",
        role: str = "admin"
    ) -> Dict[str, Any]:
        """
        Releases the endpoint from containment and restores normal monitoring.
        """
        now_iso = datetime.now(timezone.utc).isoformat()
        prev_reason = self.containment_reason
        self.is_contained = False
        self.contained_at = None
        self.containment_reason = None
        self.contained_by = None
        self._save_state()

        print("\n" + "=" * 74)
        print("  [+] ENDPOINT CONTAINMENT RELEASED - NORMAL MONITORING RESTORED")
        print("=" * 74)
        print(f"  Device ID        : {self.device_id}")
        print(f"  Status           : PROTECTED")
        print(f"  Released At      : {now_iso}")
        print(f"  Released By      : {operator} ({role})")
        print(f"  Previous Reason  : {prev_reason}")
        print("  Firewall Restrictions Removed. Normal Telemetry Resumed.")
        print("=" * 74 + "\n")

        return {
            "status": "PROTECTED",
            "device_id": self.device_id,
            "released_at": now_iso,
            "released_by": f"{operator} ({role})"
        }

    def get_status(self) -> Dict[str, Any]:
        """Returns the current containment status summary."""
        return {
            "device_id": self.device_id,
            "is_contained": self.is_contained,
            "status": "CONTAINED" if self.is_contained else "PROTECTED",
            "contained_at": self.contained_at,
            "containment_reason": self.containment_reason,
            "contained_by": self.contained_by,
            "safe_demo_mode": True
        }
