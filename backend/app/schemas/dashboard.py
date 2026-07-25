from pydantic import BaseModel


class SeverityBreakdown(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    informational: int = 0


class TimelinePoint(BaseModel):
    bucket: str
    count: int


class TopIp(BaseModel):
    ip: str
    count: int


class MitreHeatmapCell(BaseModel):
    mitre_id: str
    technique: str
    count: int


class DashboardStats(BaseModel):
    total_logs: int
    total_alerts: int
    high_severity_alerts: int
    open_incidents: int
    closed_incidents: int
    severity_breakdown: SeverityBreakdown
    attack_timeline: list[TimelinePoint]
    alert_trend: list[TimelinePoint]
    top_source_ips: list[TopIp]
    mitre_heatmap: list[MitreHeatmapCell]
