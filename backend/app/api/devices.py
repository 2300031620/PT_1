from fastapi import APIRouter
from typing import List
from ..models.schemas import DeviceResponse
from ..services.firebase_service import db_service

router = APIRouter(prefix="/api/devices", tags=["devices"])

@router.get("", response_model=List[DeviceResponse])
def get_devices():
    """Retrieve monitored endpoints and their protection status."""
    return list(db_service.devices.values())
