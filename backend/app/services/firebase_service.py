import os
import json
from datetime import datetime
from typing import List, Dict, Any, Optional
from .detection import evaluate_backend_behavior

# In-memory store ensuring FastAPI runs immediately out-of-the-box without requiring complex service-account keys
class StorageService:
    def __init__(self):
        self.devices: Dict[str, Dict[str, Any]] = {
            "WINDOWS-PC-01": {
                "id": "dev-001",
                "hostname": "WINDOWS-PC-01",
                "os": "Windows 11 Pro 23H2 (x64)",
                "ip_address": "192.168.1.104",
                "status": "PROTECTED",
                "risk_score": 18,
                "monitored_folders": [
                    "C:\\Users\\User\\Documents",
                    "C:\\Users\\User\\Desktop",
                    "C:\\ProtectedFiles"
                ],
                "last_heartbeat": datetime.utcnow().isoformat()
            }
        }
        self.events: List[Dict[str, Any]] = [
            {
                "id": "evt-001",
                "device_id": "WINDOWS-PC-01",
                "event_type": "MODIFY",
                "file_path": "C:\\Users\\User\\Documents\\notes.txt",
                "timestamp": datetime.utcnow().isoformat(),
                "is_protected": True,
                "is_suspicious": False,
                "details": "Standard file modification",
                "process_name": "explorer.exe"
            }
        ]
        self.incidents: List[Dict[str, Any]] = []
        self.protected_files: List[Dict[str, Any]] = [
            {
                "id": "pf-1",
                "name": "database.sql",
                "path": "C:\\ProtectedFiles\\database.sql",
                "priority": "CRITICAL",
                "sha256": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
                "size_bytes": 15420800,
                "last_verified": datetime.utcnow().isoformat()
            },
            {
                "id": "pf-2",
                "name": "project.zip",
                "path": "C:\\Users\\User\\Desktop\\project.zip",
                "priority": "CRITICAL",
                "sha256": "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
                "size_bytes": 48920110,
                "last_verified": datetime.utcnow().isoformat()
            },
            {
                "id": "pf-3",
                "name": "report.docx",
                "path": "C:\\Users\\User\\Documents\\report.docx",
                "priority": "HIGH",
                "sha256": "4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a",
                "size_bytes": 2450000,
                "last_verified": datetime.utcnow().isoformat()
            },
            {
                "id": "pf-4",
                "name": "notes.txt",
                "path": "C:\\Users\\User\\Documents\\notes.txt",
                "priority": "LOW",
                "sha256": "ef2d127de37b942baad06145e54b0c619a1f22327b2ebbcfbec78f5564afe39d",
                "size_bytes": 4210,
                "last_verified": datetime.utcnow().isoformat()
            }
        ]
        self.archives: List[Dict[str, Any]] = [
            {
                "id": "arch-001",
                "archive_id": "ARCH-2026-001",
                "created_at": datetime.utcnow().isoformat(),
                "files_included": ["database.sql", "project.zip"],
                "file_hashes": [
                    "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
                    "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
                ],
                "archive_size": "61.4 MB",
                "format": "ZIP",
                "status": "READY"
            }
        ]
        self.audit_logs: List[Dict[str, Any]] = [
            {
                "id": "log-1",
                "timestamp": datetime.utcnow().isoformat(),
                "user": "system",
                "action": "backend initialized",
                "device": "BACKEND-API",
                "result": "SUCCESS"
            }
        ]

    def add_audit_log(self, action: str, user: str, device: str, result: str):
        entry = {
            "id": f"log-{len(self.audit_logs) + 1}",
            "timestamp": datetime.utcnow().isoformat(),
            "user": user,
            "action": action,
            "device": device,
            "result": result
        }
        self.audit_logs.insert(0, entry)
        return entry

    def record_event(self, event_data: dict) -> dict:
        event = {
            **event_data,
            "id": f"evt-{len(self.events) + 1}-{int(datetime.utcnow().timestamp())}",
            "timestamp": event_data.get("timestamp") or datetime.utcnow().isoformat()
        }
        self.events.insert(0, event)

        dev_id = event_data.get("device_id", "WINDOWS-PC-01")
        if dev_id in self.devices:
            self.devices[dev_id]["last_heartbeat"] = datetime.utcnow().isoformat()

        # Run behavioral detection across recent events window
        prot_paths = [p["path"] for p in self.protected_files]
        eval_result = evaluate_backend_behavior(self.events[:30], protected_paths=prot_paths)
        risk_score = eval_result["risk_score"]
        severity = eval_result["severity"]

        if severity != "NORMAL":
            event["is_suspicious"] = True

        if dev_id in self.devices:
            self.devices[dev_id]["risk_score"] = risk_score
            if severity == "CRITICAL":
                self.devices[dev_id]["status"] = "CONTAINED"

        # If HIGH or CRITICAL risk and no active open incident with the same reason recently, create incident
        if severity in ["HIGH", "CRITICAL"]:
            recent_same_inc = any(
                inc.get("device_id") == dev_id and inc.get("status") == "OPEN" and inc.get("severity") == severity
                for inc in self.incidents[:3]
            )
            if not recent_same_inc:
                self.create_incident({
                    "device_id": dev_id,
                    "risk_score": risk_score,
                    "severity": severity,
                    "files_affected": min(len(self.events), 15),
                    "reason": eval_result["reason"],
                    "recommended_action": eval_result["recommended_action"],
                    "status": "CONTAINED" if severity == "CRITICAL" else "OPEN"
                })

        return event

    def create_incident(self, inc_data: dict) -> dict:
        count = len(self.incidents) + 1
        incident = {
            **inc_data,
            "id": f"inc-{count}",
            "incident_id": f"INC-{str(count).padStart(3, '0') if hasattr(str(count), 'padStart') else f'{count:03d}'}",
            "timestamp": datetime.utcnow().isoformat()
        }
        self.incidents.insert(0, incident)
        # Update device risk
        dev_id = inc_data.get("device_id", "WINDOWS-PC-01")
        if dev_id in self.devices:
            self.devices[dev_id]["risk_score"] = inc_data.get("risk_score", 90)
            if inc_data.get("severity") == "CRITICAL":
                self.devices[dev_id]["status"] = "CONTAINED"
        self.add_audit_log("incident created", "system", dev_id, f"Severity: {inc_data.get('severity')}")
        return incident

    def set_containment(
        self,
        device_id: str,
        contained: bool,
        reason: Optional[str] = None,
        operator: str = "admin",
        role: str = "admin"
    ) -> dict:
        now_iso = datetime.utcnow().isoformat()
        if device_id in self.devices:
            self.devices[device_id]["status"] = "CONTAINED" if contained else "PROTECTED"
            if contained:
                self.devices[device_id]["contained_at"] = now_iso
                self.devices[device_id]["containment_reason"] = reason or "Endpoint containment triggered"
                self.devices[device_id]["contained_by"] = f"{operator} ({role})"
            else:
                self.devices[device_id]["risk_score"] = min(self.devices[device_id].get("risk_score", 0), 15)
                self.devices[device_id].pop("contained_at", None)
                self.devices[device_id].pop("containment_reason", None)
                self.devices[device_id].pop("contained_by", None)
            dev_status = self.devices[device_id]["status"]
        else:
            dev_status = "CONTAINED" if contained else "PROTECTED"

        # If contained, ensure an incident is recorded with reason and timestamp
        if contained:
            recent_contained_inc = any(
                inc.get("device_id") == device_id and inc.get("status") == "CONTAINED"
                for inc in self.incidents[:3]
            )
            if not recent_contained_inc:
                self.create_incident({
                    "device_id": device_id,
                    "risk_score": 90,
                    "severity": "CRITICAL",
                    "files_affected": min(len(self.events), 6),
                    "reason": reason or "Endpoint contained via prevention and containment module",
                    "recommended_action": "CONTAIN",
                    "status": "CONTAINED"
                })
        else:
            # When releasing, update open contained incidents
            for inc in self.incidents:
                if inc.get("device_id") == device_id and inc.get("status") == "CONTAINED":
                    inc["status"] = "RESOLVED"
                    inc["resolved_at"] = now_iso

        action = "containment triggered" if contained else "device released"
        details = (
            f"Host isolated via safe firewall containment by {operator} ({role}). Reason: {reason or 'Administrator command'}"
            if contained else
            f"Host containment released by {operator} ({role}). Normal monitoring restored."
        )
        self.add_audit_log(action, f"{operator} ({role})", device_id, details)
        return {
            "status": "success",
            "device_id": device_id,
            "device_status": dev_status,
            "message": f"Device {device_id} {'safely contained from network' if contained else 'released to normal monitoring'}",
            "timestamp": now_iso
        }

db_service = StorageService()
