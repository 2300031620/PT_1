from fastapi import APIRouter
from typing import List
from datetime import datetime
from ..models.schemas import ArchiveCreate, ArchiveResponse
from ..services.firebase_service import db_service

router = APIRouter(prefix="/api/archives", tags=["archives"])

@router.get("", response_model=List[ArchiveResponse])
def get_archives():
    """Retrieve file snapshots and archives."""
    return db_service.archives

@router.post("", response_model=ArchiveResponse, status_code=201)
def create_archive(req: ArchiveCreate):
    """Create a backup archive for specified protected files."""
    count = len(db_service.archives) + 1
    targeted = [f for f in db_service.protected_files if f["id"] in req.file_ids]
    if not targeted:
        targeted = db_service.protected_files[:2]

    archive_entry = {
        "id": f"arch-{count}",
        "archive_id": f"ARCH-2026-{count:03d}",
        "created_at": datetime.utcnow().isoformat(),
        "files_included": [f["name"] for f in targeted],
        "file_hashes": [f["sha256"] for f in targeted],
        "archive_size": "24.5 MB",
        "format": req.format or "ZIP",
        "status": "READY"
    }
    db_service.archives.insert(0, archive_entry)
    db_service.add_audit_log("archive created", "operator", "API", f"{archive_entry['archive_id']} ({len(targeted)} files)")
    return archive_entry
