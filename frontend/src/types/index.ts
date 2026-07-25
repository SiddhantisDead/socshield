export type UserRole = 'admin' | 'analyst'

export interface User {
  id: number
  username: string
  email: string
  role: UserRole
  created_at: string
}

export type Severity = 'Critical' | 'High' | 'Medium' | 'Low' | 'Informational'
export type AlertStatus = 'Open' | 'Acknowledged' | 'Closed'
export type IncidentStatus = 'Open' | 'Investigating' | 'Resolved' | 'Closed'
export type LogType = 'windows' | 'linux' | 'apache' | 'firewall' | 'dns' | 'json' | 'syslog'

export interface LogEntry {
  id: number
  timestamp: string
  hostname: string
  source_ip: string
  severity: Severity
  event_id: string
  log_type: LogType
  source_file: string
  raw_log: string
  parsed_fields: Record<string, unknown>
}

export interface LogListResponse {
  total: number
  items: LogEntry[]
}

export interface LogUploadResult {
  filename: string
  log_type: LogType
  ingested: number
  alerts_generated: number
  errors: string[]
}

export interface AlertItem {
  id: number
  rule_id: string
  rule_name: string
  severity: Severity
  status: AlertStatus
  timestamp: string
  description: string
  mitre_id: string
  mitre_technique: string
  source_ip: string
  hostname: string
  log_id: number | null
  has_incident: boolean
}

export interface AlertListResponse {
  total: number
  items: AlertItem[]
}

export interface IncidentNote {
  id: number
  author: string
  comment: string
  next_action: string
  status_at_time: string
  created_at: string
}

export interface Incident {
  id: number
  alert_id: number
  title: string
  assigned_to_id: number | null
  assigned_to_username: string | null
  status: IncidentStatus
  resolution: string
  evidence: string[]
  created_at: string
  updated_at: string
  alert: AlertItem | null
  notes: IncidentNote[]
}

export interface IncidentListResponse {
  total: number
  items: Incident[]
}

export interface SeverityBreakdown {
  critical: number
  high: number
  medium: number
  low: number
  informational: number
}

export interface TimelinePoint {
  bucket: string
  count: number
}

export interface TopIp {
  ip: string
  count: number
}

export interface MitreHeatmapCell {
  mitre_id: string
  technique: string
  count: number
}

export interface DashboardStats {
  total_logs: number
  total_alerts: number
  high_severity_alerts: number
  open_incidents: number
  closed_incidents: number
  severity_breakdown: SeverityBreakdown
  attack_timeline: TimelinePoint[]
  alert_trend: TimelinePoint[]
  top_source_ips: TopIp[]
  mitre_heatmap: MitreHeatmapCell[]
}

export interface IpReputationResult {
  ip: string
  source: string
  is_mock: boolean
  malicious_score: number
  country: string
  asn: string
  isp: string
  total_reports: number
  last_reported: string | null
  tags: string[]
}

export interface FileScanResult {
  filename: string
  sha256: string
  matched_rules: Array<{
    rule: string
    namespace: string
    tags: string[]
    severity: string
    description: string
    mitre_id: string
  }>
  severity: string
  is_malicious: boolean
}
