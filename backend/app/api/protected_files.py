from fastapi import APIRouter
from typing import List
from datetime import datetime
from ..models.schemas import ProtectedFileCreate, ProtectedFileResponse
from ..services.firebase_service import db_service

router = APIRouter(prefix="/api/protected-files", tags=["protected-files"])

@router.get("", response_model=List[ProtectedFileResponse])
def get_protected_files():
    """Retrieve prioritized and protected files."""
    return db_service.protected_files

@router.post("", response_model=ProtectedFileResponse, status_code=201)
def add_protected_file(file: ProtectedFileCreate):
    """Add a file to the protected files list."""
    new_entry = {
        "id": f"pf-{len(db_service.protected_files) + 1}",
        "name": file.name,
        "path": file.path,
        "priority": file.priority,
        "sha256": file.sha256 or "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
        "size_bytes": file.size_bytes or 1048576,
        "last_verified": datetime.utcnow().isoformat()
    }
    db_service.protected_files.append(new_entry)
    db_service.add_audit_log("file added to protected list", "analyst", "API", f"File: {file.name}")
    return new_entry
