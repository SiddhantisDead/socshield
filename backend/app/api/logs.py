import csv
import io
import json
from datetime import datetime

from fastapi import APIRouter, Depends, UploadFile, File, Form, HTTPException, Query
from fastapi.responses import StreamingResponse
from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.log import Log
from app.models.alert import Alert
from app.models.enums import Severity, LogType
from app.schemas.log import LogOut, LogListResponse, LogUploadResult
from app.auth.deps import get_current_user
from app.parsers import parse_log_file
from app.detection.sigma_engine import get_engine
from app.detection.correlation import detect_brute_force
from app.config import settings

router = APIRouter(tags=["logs"])


def _run_detection(db: Session, logs: list[Log]) -> int:
    engine = get_engine(settings.sigma_rules_dir)
    alerts_created = 0

    for log in logs:
        fields = dict(log.parsed_fields)
        fields.setdefault("Hostname", log.hostname)
        fields.setdefault("LogType", log.log_type.value if hasattr(log.log_type, "value") else log.log_type)

        for rule in engine.evaluate(fields):
            alert = Alert(
                rule_id=rule.rule_id,
                rule_name=rule.title,
                severity=rule.severity,
                description=rule.description,
                mitre_id=rule.mitre_id,
                mitre_technique=rule.mitre_technique,
                source_ip=log.source_ip,
                hostname=log.hostname,
                log_id=log.id,
                timestamp=log.timestamp,
            )
            db.add(alert)
            alerts_created += 1

    if alerts_created:
        db.commit()
    return alerts_created


@router.post("/upload-log", response_model=LogUploadResult)
async def upload_log(
    log_type: LogType = Form(...),
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    content = await file.read()
    try:
        records = parse_log_file(log_type.value, content, file.filename or "upload")
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Failed to parse log file: {exc}")

    if not records:
        return LogUploadResult(filename=file.filename or "", log_type=log_type, ingested=0, alerts_generated=0,
                                errors=["No records could be parsed from this file"])

    logs = [Log(**rec) for rec in records]
    db.add_all(logs)
    db.commit()
    for log in logs:
        db.refresh(log)

    alerts_generated = _run_detection(db, logs)
    alerts_generated += detect_brute_force(db)

    return LogUploadResult(
        filename=file.filename or "",
        log_type=log_type,
        ingested=len(logs),
        alerts_generated=alerts_generated,
    )


@router.get("/logs", response_model=LogListResponse)
def list_logs(
    search: str = Query("", description="Full-text search across raw log content"),
    severity: Severity | None = None,
    hostname: str = "",
    source_ip: str = "",
    log_type: LogType | None = None,
    start: datetime | None = None,
    end: datetime | None = None,
    limit: int = Query(50, le=500),
    offset: int = 0,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    q = db.query(Log)
    if search:
        q = q.filter(Log.raw_log.ilike(f"%{search}%"))
    if severity:
        q = q.filter(Log.severity == severity)
    if hostname:
        q = q.filter(Log.hostname.ilike(f"%{hostname}%"))
    if source_ip:
        q = q.filter(Log.source_ip == source_ip)
    if log_type:
        q = q.filter(Log.log_type == log_type)
    if start:
        q = q.filter(Log.timestamp >= start)
    if end:
        q = q.filter(Log.timestamp <= end)

    total = q.count()
    items = q.order_by(Log.timestamp.desc()).offset(offset).limit(limit).all()
    return LogListResponse(total=total, items=items)


@router.get("/logs/export")
def export_logs(
    format: str = Query("csv", pattern="^(csv|json)$"),
    search: str = "",
    severity: Severity | None = None,
    hostname: str = "",
    source_ip: str = "",
    log_type: LogType | None = None,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    q = db.query(Log)
    if search:
        q = q.filter(Log.raw_log.ilike(f"%{search}%"))
    if severity:
        q = q.filter(Log.severity == severity)
    if hostname:
        q = q.filter(Log.hostname.ilike(f"%{hostname}%"))
    if source_ip:
        q = q.filter(Log.source_ip == source_ip)
    if log_type:
        q = q.filter(Log.log_type == log_type)

    logs = q.order_by(Log.timestamp.desc()).limit(5000).all()

    if format == "json":
        payload = [
            {
                "id": l.id,
                "timestamp": l.timestamp.isoformat(),
                "hostname": l.hostname,
                "source_ip": l.source_ip,
                "severity": l.severity.value,
                "event_id": l.event_id,
                "log_type": l.log_type.value,
                "raw_log": l.raw_log,
            }
            for l in logs
        ]
        stream = io.StringIO(json.dumps(payload, indent=2))
        return StreamingResponse(
            iter([stream.getvalue()]),
            media_type="application/json",
            headers={"Content-Disposition": "attachment; filename=logs_export.json"},
        )

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["id", "timestamp", "hostname", "source_ip", "severity", "event_id", "log_type", "raw_log"])
    for l in logs:
        writer.writerow([l.id, l.timestamp.isoformat(), l.hostname, l.source_ip, l.severity.value, l.event_id, l.log_type.value, l.raw_log])
    buf.seek(0)
    return StreamingResponse(
        iter([buf.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=logs_export.csv"},
    )
