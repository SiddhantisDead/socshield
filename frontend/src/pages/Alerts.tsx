import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Search, ClipboardPlus, Loader2 } from 'lucide-react'
import { alertsApi, incidentsApi } from '../services/api'
import type { AlertItem, AlertStatus, Severity } from '../types'
import SeverityBadge from '../components/SeverityBadge'

const SEVERITIES: Severity[] = ['Critical', 'High', 'Medium', 'Low', 'Informational']
const STATUSES: AlertStatus[] = ['Open', 'Acknowledged', 'Closed']

function fmtTime(iso: string) {
  return new Date(iso + (iso.endsWith('Z') ? '' : 'Z')).toLocaleString()
}

export default function Alerts() {
  const navigate = useNavigate()
  const [items, setItems] = useState<AlertItem[]>([])
  const [total, setTotal] = useState(0)
  const [loading, setLoading] = useState(true)
  const [severity, setSeverity] = useState<Severity | ''>('')
  const [status, setStatus] = useState<AlertStatus | ''>('')
  const [search, setSearch] = useState('')
  const [creatingId, setCreatingId] = useState<number | null>(null)

  async function load() {
    setLoading(true)
    const res = await alertsApi.list({
      severity: severity || undefined,
      status: status || undefined,
      search: search || undefined,
      limit: 100,
    })
    setItems(res.items)
    setTotal(res.total)
    setLoading(false)
  }

  useEffect(() => {
    load()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [severity, status])

  async function handleStatusChange(alert: AlertItem, next: AlertStatus) {
    const updated = await alertsApi.updateStatus(alert.id, next)
    setItems((prev) => prev.map((a) => (a.id === alert.id ? updated : a)))
  }

  async function handleCreateIncident(alert: AlertItem) {
    setCreatingId(alert.id)
    try {
      const incident = await incidentsApi.create(alert.id)
      setItems((prev) => prev.map((a) => (a.id === alert.id ? { ...a, has_incident: true } : a)))
      navigate(`/incidents?open=${incident.id}`)
    } finally {
      setCreatingId(null)
    }
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-2">
        <div className="relative flex-1 min-w-[200px]">
          <Search size={14} className="pointer-events-none absolute left-2.5 top-2.5 text-slate-500" />
          <input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && load()}
            placeholder="Search rule name…"
            className="w-full rounded-md border border-border bg-surface py-1.5 pl-8 pr-3 text-sm text-slate-200 outline-none focus:border-primary"
          />
        </div>
        <select
          value={severity}
          onChange={(e) => setSeverity(e.target.value as Severity | '')}
          className="cursor-pointer rounded-md border border-border bg-surface px-3 py-1.5 text-sm text-slate-300 outline-none focus:border-primary"
        >
          <option value="">All severities</option>
          {SEVERITIES.map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>
        <select
          value={status}
          onChange={(e) => setStatus(e.target.value as AlertStatus | '')}
          className="cursor-pointer rounded-md border border-border bg-surface px-3 py-1.5 text-sm text-slate-300 outline-none focus:border-primary"
        >
          <option value="">All statuses</option>
          {STATUSES.map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>
        <span className="text-xs text-slate-500">{total} alert(s)</span>
      </div>

      <div className="overflow-x-auto rounded-lg border border-border bg-surface">
        <table className="w-full text-left text-sm">
          <thead>
            <tr className="border-b border-border text-xs uppercase tracking-wide text-slate-500">
              <th className="px-4 py-2.5 font-medium">Severity</th>
              <th className="px-4 py-2.5 font-medium">Rule</th>
              <th className="px-4 py-2.5 font-medium">MITRE</th>
              <th className="px-4 py-2.5 font-medium">Source</th>
              <th className="px-4 py-2.5 font-medium">Time</th>
              <th className="px-4 py-2.5 font-medium">Status</th>
              <th className="px-4 py-2.5 font-medium">Action</th>
            </tr>
          </thead>
          <tbody>
            {loading && (
              <tr>
                <td colSpan={7} className="px-4 py-8 text-center text-slate-500">
                  <Loader2 className="mx-auto animate-spin" size={18} />
                </td>
              </tr>
            )}
            {!loading && items.length === 0 && (
              <tr>
                <td colSpan={7} className="px-4 py-8 text-center text-sm text-slate-600">
                  No alerts match these filters.
                </td>
              </tr>
            )}
            {items.map((a) => (
              <tr key={a.id} className="border-b border-border/60 last:border-0 hover:bg-surface-hover">
                <td className="px-4 py-2.5">
                  <SeverityBadge severity={a.severity} />
                </td>
                <td className="max-w-[260px] truncate px-4 py-2.5 font-medium text-slate-200" title={a.description}>
                  {a.rule_name}
                </td>
                <td className="px-4 py-2.5">
                  {a.mitre_id ? (
                    <span
                      className="rounded border border-border px-1.5 py-0.5 font-mono-nums text-[11px] text-slate-400"
                      title={a.mitre_technique}
                    >
                      {a.mitre_id}
                    </span>
                  ) : (
                    <span className="text-slate-600">—</span>
                  )}
                </td>
                <td className="px-4 py-2.5 font-mono-nums text-xs text-slate-400">
                  {a.hostname || a.source_ip || '—'}
                </td>
                <td className="px-4 py-2.5 text-xs text-slate-500">{fmtTime(a.timestamp)}</td>
                <td className="px-4 py-2.5">
                  <select
                    value={a.status}
                    onChange={(e) => handleStatusChange(a, e.target.value as AlertStatus)}
                    className="cursor-pointer rounded border border-border bg-bg-elevated px-1.5 py-1 text-xs text-slate-300 outline-none focus:border-primary"
                  >
                    {STATUSES.map((s) => (
                      <option key={s} value={s}>
                        {s}
                      </option>
                    ))}
                  </select>
                </td>
                <td className="px-4 py-2.5">
                  {a.has_incident ? (
                    <span className="text-xs text-slate-600">Incident opened</span>
                  ) : (
                    <button
                      onClick={() => handleCreateIncident(a)}
                      disabled={creatingId === a.id}
                      className="flex cursor-pointer items-center gap-1 rounded border border-primary/40 px-2 py-1 text-xs text-primary hover:bg-primary/10 disabled:opacity-50"
                    >
                      {creatingId === a.id ? <Loader2 size={12} className="animate-spin" /> : <ClipboardPlus size={12} />}
                      Create Incident
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
