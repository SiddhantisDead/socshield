from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.alert import Alert
from app.models.log import Log
from app.models.enums import Severity, AlertStatus
from app.schemas.alert import AlertOut, AlertListResponse, AlertStatusUpdate
from app.auth.deps import get_current_user, require_admin
from app.detection.sigma_engine import get_engine, reload_engine
from app.detection.correlation import detect_brute_force
from app.config import settings

router = APIRouter(tags=["alerts"])


def _to_out(alert: Alert) -> AlertOut:
    out = AlertOut.model_validate(alert)
    out.has_incident = alert.incident is not None
    return out


@router.get("/alerts", response_model=AlertListResponse)
def list_alerts(
    severity: Severity | None = None,
    status: AlertStatus | None = None,
    mitre_id: str = "",
    search: str = "",
    limit: int = Query(50, le=500),
    offset: int = 0,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    q = db.query(Alert)
    if severity:
        q = q.filter(Alert.severity == severity)
    if status:
        q = q.filter(Alert.status == status)
    if mitre_id:
        q = q.filter(Alert.mitre_id == mitre_id)
    if search:
        q = q.filter(Alert.rule_name.ilike(f"%{search}%"))

    total = q.count()
    items = q.order_by(Alert.timestamp.desc()).offset(offset).limit(limit).all()
    return AlertListResponse(total=total, items=[_to_out(a) for a in items])


@router.get("/alerts/{alert_id}", response_model=AlertOut)
def get_alert(alert_id: int, db: Session = Depends(get_db), current_user=Depends(get_current_user)):
    alert = db.get(Alert, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return _to_out(alert)


@router.put("/alerts/{alert_id}/status", response_model=AlertOut)
def update_alert_status(
    alert_id: int, payload: AlertStatusUpdate, db: Session = Depends(get_db), current_user=Depends(get_current_user)
):
    alert = db.get(Alert, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    alert.status = payload.status
    db.commit()
    db.refresh(alert)
    return _to_out(alert)


@router.post("/alerts/rescan")
def rescan_logs(db: Session = Depends(get_db), current_user=Depends(require_admin)):
    """Reloads Sigma rules from disk and re-runs detection across all
    ingested logs. Useful after adding/editing a rule file without
    re-uploading logs."""
    errors = reload_engine(settings.sigma_rules_dir)
    engine = get_engine(settings.sigma_rules_dir)

    logs = db.query(Log).all()
    existing_pairs = {(a.log_id, a.rule_id) for a in db.query(Alert).all()}
    created = 0

    for log in logs:
        fields = dict(log.parsed_fields)
        fields.setdefault("Hostname", log.hostname)
        for rule in engine.evaluate(fields):
            if (log.id, rule.rule_id) in existing_pairs:
                continue
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
            existing_pairs.add((log.id, rule.rule_id))
            created += 1

    db.commit()
    created += detect_brute_force(db)
    return {"rules_loaded": len(engine.rules), "rule_errors": errors, "logs_scanned": len(logs), "alerts_created": created}
