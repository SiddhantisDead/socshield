import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { FileStack, ShieldAlert, Flame, FolderOpen, CheckCircle2, RefreshCw } from 'lucide-react'
import { dashboardApi, alertsApi } from '../services/api'
import type { DashboardStats, AlertItem } from '../types'
import StatCard from '../components/StatCard'
import SeverityBadge from '../components/SeverityBadge'
import { AttackTimelineChart, AlertTrendChart, TopSourceIpsChart, MitreHeatmap } from '../components/Charts'

function timeAgo(iso: string) {
  const diffMs = Date.now() - new Date(iso + (iso.endsWith('Z') ? '' : 'Z')).getTime()
  const mins = Math.floor(diffMs / 60000)
  if (mins < 1) return 'just now'
  if (mins < 60) return `${mins}m ago`
  const hrs = Math.floor(mins / 60)
  if (hrs < 24) return `${hrs}h ago`
  return `${Math.floor(hrs / 24)}d ago`
}

export default function Dashboard() {
  const [stats, setStats] = useState<DashboardStats | null>(null)
  const [recentAlerts, setRecentAlerts] = useState<AlertItem[]>([])
  const [loading, setLoading] = useState(true)
  const [rescanning, setRescanning] = useState(false)

  async function load() {
    setLoading(true)
    const [s, a] = await Promise.all([dashboardApi.get(), alertsApi.list({ limit: 8 })])
    setStats(s)
    setRecentAlerts(a.items)
    setLoading(false)
  }

  useEffect(() => {
    load()
  }, [])

  async function handleRescan() {
    setRescanning(true)
    await alertsApi.rescan()
    await load()
    setRescanning(false)
  }

  if (loading || !stats) {
    return <div className="text-sm text-slate-500">Loading dashboard…</div>
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <p className="text-sm text-slate-500">Real-time overview across ingested logs, alerts, and incidents.</p>
        <button
          onClick={handleRescan}
          disabled={rescanning}
          className="flex cursor-pointer items-center gap-2 rounded-md border border-border bg-surface px-3 py-1.5 text-xs font-medium text-slate-300 hover:border-primary hover:text-primary disabled:opacity-50"
        >
          <RefreshCw size={13} className={rescanning ? 'animate-spin' : ''} />
          Rescan logs
        </button>
      </div>

      <div className="grid grid-cols-2 gap-4 md:grid-cols-3 lg:grid-cols-5">
        <StatCard label="Total Logs" value={stats.total_logs} icon={FileStack} accent="primary" />
        <StatCard label="Total Alerts" value={stats.total_alerts} icon={ShieldAlert} accent="high" />
        <StatCard label="High Severity" value={stats.high_severity_alerts} icon={Flame} accent="critical" />
        <StatCard label="Open Incidents" value={stats.open_incidents} icon={FolderOpen} accent="info" />
        <StatCard label="Closed Incidents" value={stats.closed_incidents} icon={CheckCircle2} accent="success" />
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <div className="rounded-lg border border-border bg-surface p-4 lg:col-span-2">
          <h2 className="mb-3 text-sm font-semibold text-slate-200">Attack Timeline (hourly)</h2>
          <AttackTimelineChart data={stats.attack_timeline} />
        </div>
        <div className="rounded-lg border border-border bg-surface p-4">
          <h2 className="mb-3 text-sm font-semibold text-slate-200">Severity Breakdown</h2>
          <div className="space-y-2">
            {(
              [
                ['Critical', stats.severity_breakdown.critical],
                ['High', stats.severity_breakdown.high],
                ['Medium', stats.severity_breakdown.medium],
                ['Low', stats.severity_breakdown.low],
                ['Informational', stats.severity_breakdown.informational],
              ] as const
            ).map(([label, count]) => {
              const max = Math.max(1, stats.total_alerts)
              return (
                <div key={label} className="flex items-center gap-2">
                  <div className="w-24 shrink-0">
                    <SeverityBadge severity={label} compact />
                  </div>
                  <div className="h-2 flex-1 overflow-hidden rounded-full bg-bg-elevated">
                    <div
                      className="h-full rounded-full bg-current opacity-70"
                      style={{ width: `${(count / max) * 100}%`, color: 'var(--color-primary)' }}
                    />
                  </div>
                  <span className="w-6 shrink-0 text-right font-mono-nums text-xs text-slate-400">{count}</span>
                </div>
              )
            })}
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <div className="rounded-lg border border-border bg-surface p-4">
          <h2 className="mb-3 text-sm font-semibold text-slate-200">Alert Trend (daily)</h2>
          <AlertTrendChart data={stats.alert_trend} />
        </div>
        <div className="rounded-lg border border-border bg-surface p-4">
          <h2 className="mb-3 text-sm font-semibold text-slate-200">Top Source IPs</h2>
          <TopSourceIpsChart data={stats.top_source_ips} />
        </div>
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <div className="rounded-lg border border-border bg-surface p-4 lg:col-span-2">
          <h2 className="mb-3 text-sm font-semibold text-slate-200">MITRE ATT&amp;CK Heatmap</h2>
          <MitreHeatmap data={stats.mitre_heatmap} />
        </div>
        <div className="rounded-lg border border-border bg-surface p-4">
          <div className="mb-3 flex items-center justify-between">
            <h2 className="text-sm font-semibold text-slate-200">Live Alert Feed</h2>
            <Link to="/alerts" className="text-xs text-primary hover:underline">
              View all
            </Link>
          </div>
          <div className="max-h-[280px] space-y-2 overflow-y-auto pr-1">
            {recentAlerts.length === 0 && <p className="text-xs text-slate-600">No alerts yet.</p>}
            {recentAlerts.map((a) => (
              <Link
                key={a.id}
                to="/alerts"
                className="block rounded-md border border-border bg-bg-elevated p-2.5 transition-colors hover:border-primary/50"
              >
                <div className="mb-1 flex items-center justify-between gap-2">
                  <SeverityBadge severity={a.severity} compact />
                  <span className="text-[10px] text-slate-500">{timeAgo(a.timestamp)}</span>
                </div>
                <div className="truncate text-xs font-medium text-slate-200">{a.rule_name}</div>
                <div className="truncate font-mono-nums text-[11px] text-slate-500">
                  {a.hostname || a.source_ip || '—'}
                </div>
              </Link>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}
