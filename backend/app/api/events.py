from fastapi import APIRouter, HTTPException
from typing import List
from ..models.schemas import EventCreate, EventResponse
from ..services.firebase_service import db_service

router = APIRouter(prefix="/api/events", tags=["events"])

@router.get("", response_model=List[EventResponse])
def get_events(limit: int = 50):
    """Retrieve recent security file events."""
    return db_service.events[:limit]

@router.post("", response_model=EventResponse, status_code=201)
def record_event(event: EventCreate):
    """Record a file system event from the Windows watchdog agent."""
    created = db_service.record_event(event.model_dump())
    return created
