from fastapi import APIRouter
from typing import List
from ..models.schemas import IncidentCreate, IncidentResponse
from ..services.firebase_service import db_service

router = APIRouter(prefix="/api/incidents", tags=["incidents"])

@router.get("", response_model=List[IncidentResponse])
def get_incidents():
    """Retrieve security incidents."""
    return db_service.incidents

@router.post("", response_model=IncidentResponse, status_code=201)
def create_incident(incident: IncidentCreate):
    """Create a security incident from the risk engine."""
    return db_service.create_incident(incident.model_dump())
