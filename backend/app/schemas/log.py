from datetime import datetime

from pydantic import BaseModel, ConfigDict

from app.models.enums import Severity, LogType


class LogOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    timestamp: datetime
    hostname: str
    source_ip: str
    severity: Severity
    event_id: str
    log_type: LogType
    source_file: str
    raw_log: str
    parsed_fields: dict


class LogUploadResult(BaseModel):
    filename: str
    log_type: LogType
    ingested: int
    alerts_generated: int
    errors: list[str] = []


class LogListResponse(BaseModel):
    total: int
    items: list[LogOut]
