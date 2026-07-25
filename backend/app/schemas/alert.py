from datetime import datetime

from pydantic import BaseModel, ConfigDict

from app.models.enums import Severity, AlertStatus


class AlertOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    rule_id: str
    rule_name: str
    severity: Severity
    status: AlertStatus
    timestamp: datetime
    description: str
    mitre_id: str
    mitre_technique: str
    source_ip: str
    hostname: str
    log_id: int | None
    has_incident: bool = False


class AlertListResponse(BaseModel):
    total: int
    items: list[AlertOut]


class AlertStatusUpdate(BaseModel):
    status: AlertStatus
