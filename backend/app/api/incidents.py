from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.incident import Incident, IncidentNote
from app.models.alert import Alert
from app.models.user import User
from app.models.enums import IncidentStatus
from app.schemas.incident import (
    IncidentCreate,
    IncidentUpdate,
    IncidentOut,
    IncidentListResponse,
    IncidentNoteCreate,
    IncidentNoteOut,
)
from app.schemas.alert import AlertOut
from app.auth.deps import get_current_user

router = APIRouter(tags=["incidents"])


def _to_out(incident: Incident, db: Session) -> IncidentOut:
    out = IncidentOut.model_validate(incident)
    if incident.assignee:
        out.assigned_to_username = incident.assignee.username
    if incident.alert:
        alert_out = AlertOut.model_validate(incident.alert)
        alert_out.has_incident = True
        out.alert = alert_out
    return out


@router.post("/incident", response_model=IncidentOut, status_code=201)
@router.post("/incidents", response_model=IncidentOut, status_code=201)
def create_incident(payload: IncidentCreate, db: Session = Depends(get_db), current_user=Depends(get_current_user)):
    alert = db.get(Alert, payload.alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    if alert.incident:
        raise HTTPException(status_code=400, detail="Incident already exists for this alert")

    incident = Incident(
        alert_id=payload.alert_id,
        title=payload.title or f"{alert.rule_name} — {alert.hostname or alert.source_ip}",
        assigned_to_id=payload.assigned_to_id,
    )
    db.add(incident)
    db.commit()
    db.refresh(incident)
    return _to_out(incident, db)


@router.get("/incidents", response_model=IncidentListResponse)
def list_incidents(
    status: IncidentStatus | None = None,
    assigned_to_id: int | None = None,
    limit: int = Query(50, le=500),
    offset: int = 0,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    q = db.query(Incident)
    if status:
        q = q.filter(Incident.status == status)
    if assigned_to_id:
        q = q.filter(Incident.assigned_to_id == assigned_to_id)

    total = q.count()
    items = q.order_by(Incident.created_at.desc()).offset(offset).limit(limit).all()
    return IncidentListResponse(total=total, items=[_to_out(i, db) for i in items])


@router.get("/incidents/{incident_id}", response_model=IncidentOut)
def get_incident(incident_id: int, db: Session = Depends(get_db), current_user=Depends(get_current_user)):
    incident = db.get(Incident, incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return _to_out(incident, db)


@router.put("/incident/{incident_id}", response_model=IncidentOut)
@router.put("/incidents/{incident_id}", response_model=IncidentOut)
def update_incident(
    incident_id: int, payload: IncidentUpdate, db: Session = Depends(get_db), current_user=Depends(get_current_user)
):
    incident = db.get(Incident, incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    data = payload.model_dump(exclude_unset=True)
    for key, value in data.items():
        setattr(incident, key, value)

    db.commit()
    db.refresh(incident)
    return _to_out(incident, db)


@router.post("/incidents/{incident_id}/notes", response_model=IncidentNoteOut, status_code=201)
def add_note(
    incident_id: int,
    payload: IncidentNoteCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    incident = db.get(Incident, incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    note = IncidentNote(
        incident_id=incident_id,
        author=current_user.username,
        comment=payload.comment,
        next_action=payload.next_action,
        status_at_time=incident.status.value,
    )
    db.add(note)
    db.commit()
    db.refresh(note)
    return note
