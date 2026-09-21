from pydantic import BaseModel, Field
from typing import List, Optional
from datetime import datetime

class EventCreate(BaseModel):
    device_id: str = Field(..., example="WINDOWS-PC-01")
    event_type: str = Field(..., example="MODIFY") # CREATE, MODIFY, DELETE, RENAME
    file_path: str = Field(..., example="C:\\Users\\User\\Documents\\report.docx")
    old_path: Optional[str] = None
    timestamp: Optional[str] = None
    is_protected: bool = False
    is_suspicious: bool = False
    details: Optional[str] = "File operation detected by Watchdog"
    process_name: Optional[str] = "unknown"

class EventResponse(EventCreate):
    id: str
    timestamp: str

class IncidentCreate(BaseModel):
    device_id: str = Field(..., example="WINDOWS-PC-01")
    risk_score: int = Field(..., ge=0, le=100, example=87)
    severity: str = Field(..., example="CRITICAL") # NORMAL, SUSPICIOUS, HIGH, CRITICAL
    files_affected: int = Field(default=1, example=57)
    reason: str = Field(..., example="Large number of files modified and renamed within a short period")
    recommended_action: str = Field(default="CONTAIN", example="CONTAIN")
    status: str = Field(default="OPEN", example="OPEN")

class IncidentResponse(IncidentCreate):
    id: str
    incident_id: str
    timestamp: str

class DeviceResponse(BaseModel):
    id: str
    hostname: str
    os: str
    ip_address: str
    status: str # PROTECTED, MONITORING, CONTAINED, OFFLINE
    risk_score: int
    monitored_folders: List[str]
    last_heartbeat: str

class ProtectedFileCreate(BaseModel):
    name: str = Field(..., example="database.sql")
    path: str = Field(..., example="C:\\ProtectedFiles\\database.sql")
    priority: str = Field(..., example="CRITICAL") # CRITICAL, HIGH, MEDIUM, LOW
    sha256: Optional[str] = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    size_bytes: Optional[int] = 15420800

class ProtectedFileResponse(ProtectedFileCreate):
    id: str
    last_verified: str

class ArchiveCreate(BaseModel):
    file_ids: List[str]
    format: str = "ZIP"

class ArchiveResponse(BaseModel):
    id: str
    archive_id: str
    created_at: str
    files_included: List[str]
    file_hashes: List[str]
    archive_size: str
    format: str
    status: str

class ContainmentRequest(BaseModel):
    device_id: str
    contained: bool
    reason: Optional[str] = "Manual operator or automated detection threshold containment"
    operator: Optional[str] = "admin"
    role: Optional[str] = "admin"

class ContainmentResponse(BaseModel):
    status: str
    device_id: str
    device_status: str
    message: str
    timestamp: str
