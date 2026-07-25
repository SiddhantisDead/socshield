from datetime import datetime

from pydantic import BaseModel, ConfigDict

from app.models.enums import IncidentStatus
from app.schemas.alert import AlertOut


class IncidentNoteCreate(BaseModel):
    comment: str = ""
    next_action: str = ""


class IncidentNoteOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    author: str
    comment: str
    next_action: str
    status_at_time: str
    created_at: datetime


class IncidentCreate(BaseModel):
    alert_id: int
    title: str = ""
    assigned_to_id: int | None = None


class IncidentUpdate(BaseModel):
    status: IncidentStatus | None = None
    assigned_to_id: int | None = None
    resolution: str | None = None
    evidence: list[str] | None = None
    title: str | None = None


class IncidentOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    alert_id: int
    title: str
    assigned_to_id: int | None
    assigned_to_username: str | None = None
    status: IncidentStatus
    resolution: str
    evidence: list
    created_at: datetime
    updated_at: datetime
    alert: AlertOut | None = None
    notes: list[IncidentNoteOut] = []


class IncidentListResponse(BaseModel):
    total: int
    items: list[IncidentOut]
