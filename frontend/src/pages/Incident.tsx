import { useEffect, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { Loader2, ClipboardList, Send } from 'lucide-react'
import { incidentsApi } from '../services/api'
import type { Incident as IncidentType, IncidentStatus } from '../types'
import SeverityBadge from '../components/SeverityBadge'

const STATUSES: IncidentStatus[] = ['Open', 'Investigating', 'Resolved', 'Closed']

const STATUS_DOT: Record<IncidentStatus, string> = {
  Open: 'bg-critical',
  Investigating: 'bg-medium',
  Resolved: 'bg-success',
  Closed: 'bg-info',
}

function fmtTime(iso: string) {
  return new Date(iso + (iso.endsWith('Z') ? '' : 'Z')).toLocaleString()
}

export default function Incident() {
  const [searchParams, setSearchParams] = useSearchParams()
  const [items, setItems] = useState<IncidentType[]>([])
  const [selected, setSelected] = useState<IncidentType | null>(null)
  const [loading, setLoading] = useState(true)
  const [resolution, setResolution] = useState('')
  const [comment, setComment] = useState('')
  const [nextAction, setNextAction] = useState('')
  const [savingNote, setSavingNote] = useState(false)

  async function load() {
    setLoading(true)
    const res = await incidentsApi.list({ limit: 100 })
    setItems(res.items)

    const openId = searchParams.get('open')
    if (openId) {
      const found = res.items.find((i) => i.id === Number(openId))
      if (found) setSelected(found)
      setSearchParams({}, { replace: true })
    } else if (res.items.length && !selected) {
      setSelected(res.items[0])
    }
    setLoading(false)
  }

  useEffect(() => {
    load()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  useEffect(() => {
    setResolution(selected?.resolution ?? '')
  }, [selected?.id])

  async function selectIncident(id: number) {
    const full = await incidentsApi.get(id)
    setSelected(full)
  }

  async function handleStatusChange(status: IncidentStatus) {
    if (!selected) return
    const updated = await incidentsApi.update(selected.id, { status })
    setSelected(updated)
    setItems((prev) => prev.map((i) => (i.id === updated.id ? updated : i)))
  }

  async function handleSaveResolution() {
    if (!selected) return
    const updated = await incidentsApi.update(selected.id, { resolution })
    setSelected(updated)
    setItems((prev) => prev.map((i) => (i.id === updated.id ? updated : i)))
  }

  async function handleAddNote() {
    if (!selected || (!comment && !nextAction)) return
    setSavingNote(true)
    try {
      await incidentsApi.addNote(selected.id, comment, nextAction)
      const full = await incidentsApi.get(selected.id)
      setSelected(full)
      setComment('')
      setNextAction('')
    } finally {
      setSavingNote(false)
    }
  }

  if (loading) {
    return <Loader2 className="animate-spin text-slate-500" size={20} />
  }

  return (
    <div className="grid h-full grid-cols-1 gap-4 lg:grid-cols-[320px_1fr]">
      <div className="overflow-y-auto rounded-lg border border-border bg-surface">
        <div className="border-b border-border px-4 py-2.5 text-xs font-semibold uppercase tracking-wide text-slate-500">
          {items.length} Incident(s)
        </div>
        {items.length === 0 && (
          <p className="p-4 text-xs text-slate-600">
            No incidents yet. Open the Alerts page and click "Create Incident" on an alert.
          </p>
        )}
        {items.map((i) => (
          <button
            key={i.id}
            onClick={() => selectIncident(i.id)}
            className={`block w-full cursor-pointer border-b border-border/60 px-4 py-3 text-left transition-colors hover:bg-surface-hover ${
              selected?.id === i.id ? 'bg-primary/10' : ''
            }`}
          >
            <div className="mb-1 flex items-center gap-2">
              <span className={`h-1.5 w-1.5 rounded-full ${STATUS_DOT[i.status]}`} />
              <span className="text-xs text-slate-500">{i.status}</span>
              <span className="ml-auto text-[10px] text-slate-600">{fmtTime(i.created_at)}</span>
            </div>
            <div className="truncate text-sm font-medium text-slate-200">{i.title}</div>
            {i.alert && (
              <div className="mt-1">
                <SeverityBadge severity={i.alert.severity} compact />
              </div>
            )}
          </button>
        ))}
      </div>

      <div className="overflow-y-auto rounded-lg border border-border bg-surface p-5">
        {!selected ? (
          <div className="flex h-full flex-col items-center justify-center text-slate-600">
            <ClipboardList size={28} />
            <p className="mt-2 text-sm">Select an incident to view details</p>
          </div>
        ) : (
          <div className="space-y-5">
            <div>
              <div className="flex items-start justify-between gap-4">
                <div>
                  <h2 className="text-base font-semibold text-slate-100">{selected.title}</h2>
                  <p className="mt-1 text-xs text-slate-500">
                    Incident #{selected.id} · Alert #{selected.alert_id} · Created {fmtTime(selected.created_at)}
                  </p>
                </div>
                <select
                  value={selected.status}
                  onChange={(e) => handleStatusChange(e.target.value as IncidentStatus)}
                  className="cursor-pointer rounded-md border border-border bg-bg-elevated px-2.5 py-1.5 text-xs font-medium text-slate-200 outline-none focus:border-primary"
                >
                  {STATUSES.map((s) => (
                    <option key={s} value={s}>
                      {s}
                    </option>
                  ))}
                </select>
              </div>
            </div>

            {selected.alert && (
              <div className="rounded-md border border-border bg-bg-elevated p-3">
                <div className="mb-2 flex items-center gap-2">
                  <SeverityBadge severity={selected.alert.severity} />
                  {selected.alert.mitre_id && (
                    <span className="rounded border border-border px-1.5 py-0.5 font-mono-nums text-[11px] text-slate-400">
                      {selected.alert.mitre_id} · {selected.alert.mitre_technique}
                    </span>
                  )}
                </div>
                <p className="text-sm text-slate-300">{selected.alert.description}</p>
                <div className="mt-2 grid grid-cols-2 gap-x-4 gap-y-1 font-mono-nums text-xs text-slate-500">
                  <span>Host: {selected.alert.hostname || '—'}</span>
                  <span>Source IP: {selected.alert.source_ip || '—'}</span>
                </div>
              </div>
            )}

            <div>
              <label className="mb-1 block text-xs font-medium text-slate-400">Resolution</label>
              <textarea
                value={resolution}
                onChange={(e) => setResolution(e.target.value)}
                onBlur={handleSaveResolution}
                rows={2}
                placeholder="Summarize root cause and remediation once resolved…"
                className="w-full resize-none rounded-md border border-border bg-bg-elevated px-3 py-2 text-sm text-slate-200 outline-none focus:border-primary"
              />
            </div>

            <div>
              <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-slate-500">
                Timeline &amp; Analyst Notes
              </h3>
              <div className="space-y-2">
                {selected.notes.length === 0 && (
                  <p className="text-xs text-slate-600">No notes yet — add the first investigation update below.</p>
                )}
                {selected.notes.map((n) => (
                  <div key={n.id} className="rounded-md border border-border bg-bg-elevated p-3">
                    <div className="mb-1 flex items-center justify-between text-[11px] text-slate-500">
                      <span className="font-medium text-slate-400">{n.author}</span>
                      <span>{fmtTime(n.created_at)}</span>
                    </div>
                    {n.comment && <p className="text-sm text-slate-300">{n.comment}</p>}
                    {n.next_action && (
                      <p className="mt-1 text-xs text-primary">
                        <span className="font-medium">Next action:</span> {n.next_action}
                      </p>
                    )}
                  </div>
                ))}
              </div>

              <div className="mt-3 space-y-2 rounded-md border border-dashed border-border p-3">
                <textarea
                  value={comment}
                  onChange={(e) => setComment(e.target.value)}
                  rows={2}
                  placeholder="Add investigation comment…"
                  className="w-full resize-none rounded-md border border-border bg-bg-elevated px-3 py-2 text-sm text-slate-200 outline-none focus:border-primary"
                />
                <input
                  value={nextAction}
                  onChange={(e) => setNextAction(e.target.value)}
                  placeholder="Next action (optional)…"
                  className="w-full rounded-md border border-border bg-bg-elevated px-3 py-2 text-sm text-slate-200 outline-none focus:border-primary"
                />
                <button
                  onClick={handleAddNote}
                  disabled={savingNote || (!comment && !nextAction)}
                  className="flex cursor-pointer items-center gap-2 rounded-md bg-primary px-3 py-1.5 text-xs font-medium text-white hover:bg-primary-dark disabled:cursor-not-allowed disabled:opacity-50"
                >
                  {savingNote ? <Loader2 size={13} className="animate-spin" /> : <Send size={13} />}
                  Add note
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
