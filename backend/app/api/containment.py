from fastapi import APIRouter
from ..models.schemas import ContainmentRequest, ContainmentResponse
from ..services.firebase_service import db_service

router = APIRouter(prefix="/api/containment", tags=["containment"])

@router.post("", response_model=ContainmentResponse)
def trigger_containment(req: ContainmentRequest):
    """
    Isolate or release a Windows endpoint.
    When contained=True, network activity and monitored file tampering are restricted safely.
    """
    res = db_service.set_containment(
        device_id=req.device_id,
        contained=req.contained,
        reason=req.reason,
        operator=req.operator or "admin",
        role=req.role or "admin"
    )
    return res
