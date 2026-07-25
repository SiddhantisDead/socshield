import { Fragment, useEffect, useState } from 'react'
import { Search, Download, Loader2, ChevronDown, ChevronRight } from 'lucide-react'
import { logsApi } from '../services/api'
import type { LogEntry, LogType, Severity } from '../types'
import SeverityBadge from './SeverityBadge'

const SEVERITIES: Severity[] = ['Critical', 'High', 'Medium', 'Low', 'Informational']
const LOG_TYPES: LogType[] = ['windows', 'linux', 'apache', 'firewall', 'dns']

function fmtTime(iso: string) {
  return new Date(iso + (iso.endsWith('Z') ? '' : 'Z')).toLocaleString()
}

export default function LogViewer({ refreshKey }: { refreshKey: number }) {
  const [items, setItems] = useState<LogEntry[]>([])
  const [total, setTotal] = useState(0)
  const [loading, setLoading] = useState(true)
  const [search, setSearch] = useState('')
  const [severity, setSeverity] = useState<Severity | ''>('')
  const [hostname, setHostname] = useState('')
  const [sourceIp, setSourceIp] = useState('')
  const [logType, setLogType] = useState<LogType | ''>('')
  const [expanded, setExpanded] = useState<number | null>(null)

  const filters = {
    search: search || undefined,
    severity: severity || undefined,
    hostname: hostname || undefined,
    source_ip: sourceIp || undefined,
    log_type: logType || undefined,
    limit: 100,
  }

  async function load() {
    setLoading(true)
    const res = await logsApi.list(filters)
    setItems(res.items)
    setTotal(res.total)
    setLoading(false)
  }

  useEffect(() => {
    load()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [severity, logType, refreshKey])

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <div className="relative min-w-[180px] flex-1">
          <Search size={14} className="pointer-events-none absolute left-2.5 top-2.5 text-slate-500" />
          <input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && load()}
            placeholder="Search raw log content…"
            className="w-full rounded-md border border-border bg-surface py-1.5 pl-8 pr-3 text-sm text-slate-200 outline-none focus:border-primary"
          />
        </div>
        <input
          value={hostname}
          onChange={(e) => setHostname(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && load()}
          placeholder="Hostname"
          className="w-28 rounded-md border border-border bg-surface px-2.5 py-1.5 text-sm text-slate-200 outline-none focus:border-primary"
        />
        <input
          value={sourceIp}
          onChange={(e) => setSourceIp(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && load()}
          placeholder="Source IP"
          className="w-32 rounded-md border border-border bg-surface px-2.5 py-1.5 font-mono-nums text-sm text-slate-200 outline-none focus:border-primary"
        />
        <select
          value={severity}
          onChange={(e) => setSeverity(e.target.value as Severity | '')}
          className="cursor-pointer rounded-md border border-border bg-surface px-2.5 py-1.5 text-sm text-slate-300 outline-none focus:border-primary"
        >
          <option value="">All severities</option>
          {SEVERITIES.map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>
        <select
          value={logType}
          onChange={(e) => setLogType(e.target.value as LogType | '')}
          className="cursor-pointer rounded-md border border-border bg-surface px-2.5 py-1.5 text-sm text-slate-300 outline-none focus:border-primary"
        >
          <option value="">All types</option>
          {LOG_TYPES.map((t) => (
            <option key={t} value={t}>
              {t}
            </option>
          ))}
        </select>
        <button
          onClick={load}
          className="cursor-pointer rounded-md border border-border bg-surface px-3 py-1.5 text-xs text-slate-300 hover:border-primary hover:text-primary"
        >
          Apply
        </button>
        <a
          href={logsApi.exportUrl('csv', filters)}
          className="flex cursor-pointer items-center gap-1 rounded-md border border-border bg-surface px-2.5 py-1.5 text-xs text-slate-300 hover:border-primary hover:text-primary"
        >
          <Download size={12} /> CSV
        </a>
        <a
          href={logsApi.exportUrl('json', filters)}
          className="flex cursor-pointer items-center gap-1 rounded-md border border-border bg-surface px-2.5 py-1.5 text-xs text-slate-300 hover:border-primary hover:text-primary"
        >
          <Download size={12} /> JSON
        </a>
        <span className="text-xs text-slate-500">{total} log(s)</span>
      </div>

      <div className="overflow-hidden rounded-lg border border-border bg-surface">
        <table className="w-full text-left text-sm">
          <thead>
            <tr className="border-b border-border text-xs uppercase tracking-wide text-slate-500">
              <th className="w-8 px-3 py-2.5"></th>
              <th className="px-2 py-2.5 font-medium">Severity</th>
              <th className="px-2 py-2.5 font-medium">Time</th>
              <th className="px-2 py-2.5 font-medium">Type</th>
              <th className="px-2 py-2.5 font-medium">Host</th>
              <th className="px-2 py-2.5 font-medium">Source IP</th>
              <th className="px-2 py-2.5 font-medium">Event</th>
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
                  No logs match these filters. Upload a sample log file above to get started.
                </td>
              </tr>
            )}
            {items.map((log) => (
              <Fragment key={log.id}>
                <tr
                  onClick={() => setExpanded(expanded === log.id ? null : log.id)}
                  className="cursor-pointer border-b border-border/60 last:border-0 hover:bg-surface-hover"
                >
                  <td className="px-3 py-2 text-slate-600">
                    {expanded === log.id ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
                  </td>
                  <td className="px-2 py-2">
                    <SeverityBadge severity={log.severity} compact />
                  </td>
                  <td className="whitespace-nowrap px-2 py-2 text-xs text-slate-500">{fmtTime(log.timestamp)}</td>
                  <td className="px-2 py-2 text-xs text-slate-400">{log.log_type}</td>
                  <td className="px-2 py-2 font-mono-nums text-xs text-slate-300">{log.hostname || '—'}</td>
                  <td className="px-2 py-2 font-mono-nums text-xs text-slate-300">{log.source_ip || '—'}</td>
                  <td className="max-w-[240px] truncate px-2 py-2 text-xs text-slate-400">{log.event_id}</td>
                </tr>
                {expanded === log.id && (
                  <tr className="border-b border-border/60 bg-bg-elevated">
                    <td colSpan={7} className="px-4 py-3">
                      <pre className="max-h-48 overflow-auto whitespace-pre-wrap break-all font-mono text-[11px] text-slate-400">
                        {log.raw_log}
                      </pre>
                    </td>
                  </tr>
                )}
              </Fragment>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
