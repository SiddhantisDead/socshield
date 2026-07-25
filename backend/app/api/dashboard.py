from collections import Counter, defaultdict
from datetime import timedelta

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.log import Log
from app.models.alert import Alert
from app.models.incident import Incident
from app.models.enums import Severity, IncidentStatus
from app.schemas.dashboard import (
    DashboardStats,
    SeverityBreakdown,
    TimelinePoint,
    TopIp,
    MitreHeatmapCell,
)
from app.auth.deps import get_current_user

router = APIRouter(tags=["dashboard"])


@router.get("/dashboard", response_model=DashboardStats)
def dashboard(db: Session = Depends(get_db), current_user=Depends(get_current_user)):
    total_logs = db.query(Log).count()
    alerts = db.query(Alert).all()
    incidents = db.query(Incident).all()

    total_alerts = len(alerts)
    high_severity_alerts = sum(1 for a in alerts if a.severity in (Severity.high, Severity.critical))
    open_incidents = sum(1 for i in incidents if i.status != IncidentStatus.closed)
    closed_incidents = sum(1 for i in incidents if i.status == IncidentStatus.closed)

    severity_counts = Counter(a.severity for a in alerts)
    severity_breakdown = SeverityBreakdown(
        critical=severity_counts.get(Severity.critical, 0),
        high=severity_counts.get(Severity.high, 0),
        medium=severity_counts.get(Severity.medium, 0),
        low=severity_counts.get(Severity.low, 0),
        informational=severity_counts.get(Severity.informational, 0),
    )

    # Attack timeline: alert counts bucketed by hour over the last 48h of data present
    hourly = defaultdict(int)
    for a in alerts:
        bucket = a.timestamp.strftime("%Y-%m-%d %H:00")
        hourly[bucket] += 1
    attack_timeline = [TimelinePoint(bucket=k, count=v) for k, v in sorted(hourly.items())][-48:]

    # Alert trend: daily counts
    daily = defaultdict(int)
    for a in alerts:
        bucket = a.timestamp.strftime("%Y-%m-%d")
        daily[bucket] += 1
    alert_trend = [TimelinePoint(bucket=k, count=v) for k, v in sorted(daily.items())][-30:]

    ip_counts = Counter(a.source_ip for a in alerts if a.source_ip)
    top_source_ips = [TopIp(ip=ip, count=c) for ip, c in ip_counts.most_common(10)]

    mitre_counts = Counter((a.mitre_id, a.mitre_technique) for a in alerts if a.mitre_id)
    mitre_heatmap = [
        MitreHeatmapCell(mitre_id=mid, technique=tech, count=c)
        for (mid, tech), c in sorted(mitre_counts.items(), key=lambda kv: -kv[1])
    ]

    return DashboardStats(
        total_logs=total_logs,
        total_alerts=total_alerts,
        high_severity_alerts=high_severity_alerts,
        open_incidents=open_incidents,
        closed_incidents=closed_incidents,
        severity_breakdown=severity_breakdown,
        attack_timeline=attack_timeline,
        alert_trend=alert_trend,
        top_source_ips=top_source_ips,
        mitre_heatmap=mitre_heatmap,
    )
