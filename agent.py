"""
Windows Python Endpoint Agent
-----------------------------
Monitors user-configured directories using watchdog for file system events:
  - CREATE
  - MODIFY
  - DELETE
  - MOVE/RENAME

Applies the rule-based Ransomware Behavioral Detection Engine in real time,
evaluating:
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

Streams events and suspicious activity directly to the FastAPI backend service.
"""

import os
import sys
import time
import argparse
from datetime import datetime, timezone
from typing import Optional

try:
    import requests
except ImportError:
    print("[!] ERROR: 'requests' library is not installed.")
    print("    Please run: pip install -r requirements.txt")
    sys.exit(1)

try:
    from .config import get_agent_config, validate_and_resolve_directories
    from .file_monitor import EndpointFileMonitor
    from .detector import RansomwareDetector
    from .containment import SafeContainmentManager
except ImportError:
    # Direct execution support (e.g. `python agent.py` from inside endpoint_agent directory)
    from config import get_agent_config, validate_and_resolve_directories
    from file_monitor import EndpointFileMonitor
    from detector import RansomwareDetector
    from containment import SafeContainmentManager


class EndpointAgent:
    """
    Main Endpoint Agent orchestrator.
    Configures watchdog file system monitoring and applies behavioral detection.
    """

    def __init__(
        self,
        custom_dirs: Optional[list] = None,
        backend_url: Optional[str] = None,
        dry_run: bool = False
    ):
        self.config = get_agent_config(custom_dirs=custom_dirs, backend_url=backend_url)
        self.dry_run = dry_run
        self.events_url = f"{self.config['backend_api_url']}/events"
        self.incidents_url = f"{self.config['backend_api_url']}/incidents"
        self.containment_url = f"{self.config['backend_api_url']}/containment"
        self.monitor: Optional[EndpointFileMonitor] = None
        self.detector = RansomwareDetector()
        self.containment = SafeContainmentManager(device_id=self.config["device_hostname"])
        self.total_events_sent = 0
        self.backend_reachable = True
        self.last_reported_incident_time = 0.0

    def trigger_containment(self, reason: str, operator: str = "Automated Rule Engine"):
        """
        Executes endpoint containment when critical risk is reached.
        Marks device as CONTAINED, records reason and timestamp,
        and alerts backend/dashboard.
        """
        res = self.containment.contain_device(
            reason=reason,
            operator=operator,
            role="admin"
        )
        if not self.dry_run:
            payload = {
                "device_id": self.config["device_hostname"],
                "contained": True,
                "reason": reason
            }
            try:
                requests.post(self.containment_url, json=payload, timeout=3.0)
            except Exception as err:
                print(f"[-] Backend containment notification failed: {err}")
        return res

    def send_event_to_backend(self, payload: dict) -> bool:
        """
        Dispatches file system event payload to the FastAPI backend.
        Fails gracefully if backend is offline or unreachable.
        """
        if self.dry_run:
            return True

        try:
            response = requests.post(self.events_url, json=payload, timeout=3.0)
            if response.status_code in [200, 201]:
                self.total_events_sent += 1
                if not self.backend_reachable:
                    print("[+] Backend connection restored. Events streaming successfully.")
                    self.backend_reachable = True
                return True
            else:
                print(f"[-] Backend returned status {response.status_code}: {response.text}")
                return False
        except requests.exceptions.RequestException as err:
            if self.backend_reachable:
                print(f"[-] Backend unreachable at {self.events_url}: {err}")
                print("    (Agent will keep monitoring locally and retry on next event)")
                self.backend_reachable = False
            return False

    def report_incident(
        self,
        risk_score: int,
        severity: str,
        reason: str,
        recommended_action: str,
        status: str = "OPEN"
    ):
        """
        Reports detected high or critical ransomware incidents to the backend.
        Throttled to avoid overwhelming backend on rapid events.
        """
        if self.dry_run:
            return

        now = time.time()
        if now - self.last_reported_incident_time < 5.0:
            return  # Throttle incident creation within 5 seconds

        incident_payload = {
            "device_id": self.config["device_hostname"],
            "risk_score": risk_score,
            "severity": severity,
            "files_affected": self.detector.events_window.__len__(),
            "reason": reason,
            "recommended_action": recommended_action,
            "status": status
        }

        try:
            res = requests.post(self.incidents_url, json=incident_payload, timeout=3.0)
            if res.status_code in [200, 201]:
                self.last_reported_incident_time = now
                print(f"[!] Successfully filed {severity} security incident with backend.")
        except Exception:
            pass

    def handle_file_event(
        self,
        event_type: str,
        file_path: str,
        old_path: Optional[str] = None,
        details: Optional[str] = None
    ):
        """
        Invoked by file_monitor whenever a CREATE, MODIFY, DELETE, or MOVE/RENAME occurs.
        Runs behavioral detection engine and transmits telemetry to the backend.
        """
        now_str = datetime.now().strftime("%H:%M:%S")
        filename = os.path.basename(file_path)

        # 1. Run Behavioral Detection Engine
        detection = self.detector.process_event(event_type, file_path, old_path)
        risk_score = detection["risk_score"]
        severity = detection["severity"]
        reason = detection["reason"]
        recommended_action = detection["recommended_action"]
        window_summary = detection.get("window_summary", {})
        is_protected = window_summary.get("is_current_file_protected", False)

        # 2. Visual console formatting
        badge = {
            "CREATE": "[+] CREATE     ",
            "MODIFY": "[*] MODIFY     ",
            "DELETE": "[-] DELETE     ",
            "MOVE/RENAME": "[>] MOVE/RENAME"
        }.get(event_type, f"[{event_type}]")

        if self.containment.is_contained:
            badge = "[CONTAINED] " + badge

        if old_path:
            old_name = os.path.basename(old_path)
            print(f"{badge} | {now_str} | {old_name} -> {filename} | Path: {file_path}")
        else:
            print(f"{badge} | {now_str} | {filename:<22} | Path: {file_path}")

        # 3. Highlight suspicious activity or elevated risk scores
        if severity != "NORMAL":
            sev_color = {
                "SUSPICIOUS": "\033[33m",  # Yellow
                "HIGH": "\033[35m",        # Magenta
                "CRITICAL": "\033[31m"      # Red
            }.get(severity, "")
            reset_color = "\033[0m"

            print(
                f"  {sev_color}[BEHAVIORAL DETECTION] Severity: {severity} | "
                f"Risk Score: {risk_score}/100 | Action: {recommended_action}{reset_color}\n"
                f"  {sev_color}Reason: {reason}{reset_color}"
            )

        # 4. Construct FastAPI EventCreate payload
        payload = {
            "device_id": self.config["device_hostname"],
            "event_type": event_type,
            "file_path": file_path,
            "old_path": old_path,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "is_protected": is_protected,
            "is_suspicious": (severity != "NORMAL"),
            "details": f"[{severity} - Score {risk_score}] {details or reason}",
            "process_name": "watchdog_agent"
        }

        # 5. Send event to FastAPI backend
        self.send_event_to_backend(payload)

        # 6. If High or Critical, report incident; if CRITICAL, trigger prevention & containment
        if severity in ["HIGH", "CRITICAL"]:
            incident_status = "CONTAINED" if severity == "CRITICAL" else "OPEN"
            self.report_incident(risk_score, severity, reason, recommended_action, status=incident_status)

            # Automatically contain endpoint on critical behavioral risk
            if severity == "CRITICAL" and not self.containment.is_contained:
                self.trigger_containment(reason=reason, operator="Automated Behavioral Heuristics")

    def start(self):
        """
        Starts the watchdog monitor and enters the main event loop.
        """
        dirs = self.config["monitored_directories"]
        backend = self.config["backend_api_url"]
        hostname = self.config["device_hostname"]
        ip = self.config["device_ip"]
        os_name = self.config["device_os"]

        print("=" * 72)
        print("    WINDOWS PYTHON ENDPOINT AGENT (BEHAVIORAL DETECTION ENGINE)")
        print("=" * 72)
        print(f"  Device Hostname : {hostname}")
        print(f"  IP Address      : {ip}")
        print(f"  Operating System: {os_name}")
        print(f"  Backend API URL : {backend} (Dry Run: {self.dry_run})")
        print("  Monitored Folders:")
        for idx, d in enumerate(dirs, 1):
            print(f"    {idx}. {d}")
        print("=" * 72)
        print("  Active Behavioral Detection Rules:")
        print("    - Rapid file modifications")
        print("    - Mass file modifications")
        print("    - Rapid file renames")
        print("    - Mass deletion")
        print("    - Suspicious extension changes")
        print("    - Protected-file modification")
        print("    - Excessive file activity within short period")
        print("  Risk Score Range: 0-100 (NORMAL, SUSPICIOUS, HIGH, CRITICAL)")
        print("  Press Ctrl+C to terminate the agent.")
        print("=" * 72 + "\n")

        # Initial test ping to backend
        if not self.dry_run:
            try:
                test_ping = requests.get(backend.replace("/api", "") + "/", timeout=2.0)
                if test_ping.status_code == 200:
                    print(f"[+] Connected to FastAPI Backend at {backend}")
                else:
                    print(f"[!] Backend ping returned code {test_ping.status_code}")
            except Exception:
                print(f"[!] Warning: Backend at {backend} is not reachable right now.")
                print("    Start the backend with: uvicorn backend.app.main:app --host 0.0.0.0 --port 8000")
                print("    The agent will continue monitoring and dispatch events when available.\n")

        # Initialize and start file monitor
        self.monitor = EndpointFileMonitor(
            directories=dirs,
            event_callback=self.handle_file_event
        )
        self.monitor.start()

        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n[*] Caught shutdown signal (Ctrl+C). Exiting...")
        finally:
            if self.monitor:
                self.monitor.stop()
            print(f"[*] Agent stopped cleanly. Total events transmitted: {self.total_events_sent}")


def parse_args():
    parser = argparse.ArgumentParser(
        description="Windows Python Endpoint File Monitoring Agent with Behavioral Detection."
    )
    parser.add_argument(
        "--dirs", "-d",
        nargs="+",
        help="One or more directories to monitor (e.g. --dirs 'C:\\TestFolder' 'C:\\Users\\User\\Documents')."
    )
    parser.add_argument(
        "--backend", "-b",
        type=str,
        help="FastAPI backend URL (default: http://localhost:8000/api or env BACKEND_API_URL)."
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Log file events locally without dispatching HTTP requests to backend."
    )
    return parser.parse_args()


def main():
    args = parse_args()
    agent = EndpointAgent(
        custom_dirs=args.dirs,
        backend_url=args.backend,
        dry_run=args.dry_run
    )
    agent.start()


if __name__ == "__main__":
    main()
