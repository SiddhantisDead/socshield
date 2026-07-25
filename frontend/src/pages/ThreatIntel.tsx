import { useState, type FormEvent } from 'react'
import { Search, Loader2, Globe2, ShieldAlert, Info } from 'lucide-react'
import { threatIntelApi } from '../services/api'
import type { IpReputationResult } from '../types'

function scoreColor(score: number) {
  if (score >= 75) return { text: 'text-critical', bg: 'bg-critical-bg', bar: 'bg-critical' }
  if (score >= 40) return { text: 'text-high', bg: 'bg-high-bg', bar: 'bg-high' }
  if (score > 0) return { text: 'text-medium', bg: 'bg-medium-bg', bar: 'bg-medium' }
  return { text: 'text-success', bg: 'bg-success/10', bar: 'bg-success' }
}

export default function ThreatIntel() {
  const [ip, setIp] = useState('')
  const [result, setResult] = useState<IpReputationResult | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [history, setHistory] = useState<IpReputationResult[]>([])

  async function handleSubmit(e: FormEvent) {
    e.preventDefault()
    if (!ip.trim()) return
    setLoading(true)
    setError('')
    try {
      const res = await threatIntelApi.lookup(ip.trim())
      setResult(res)
      setHistory((prev) => [res, ...prev.filter((r) => r.ip !== res.ip)].slice(0, 6))
    } catch {
      setError('Lookup failed — check the IP address format.')
    } finally {
      setLoading(false)
    }
  }

  const colors = result ? scoreColor(result.malicious_score) : null

  return (
    <div className="max-w-2xl space-y-5">
      <div className="rounded-lg border border-border bg-surface p-4">
        <h2 className="mb-1 text-sm font-semibold text-slate-200">IP Reputation Lookup</h2>
        <p className="mb-3 text-xs text-slate-500">
          Backed by VirusTotal / AbuseIPDB when API keys are configured server-side; otherwise falls back to a
          deterministic demo response.
        </p>
        <form onSubmit={handleSubmit} className="flex gap-2">
          <div className="relative flex-1">
            <Search size={14} className="pointer-events-none absolute left-2.5 top-2.5 text-slate-500" />
            <input
              value={ip}
              onChange={(e) => setIp(e.target.value)}
              placeholder="e.g. 203.0.113.7"
              className="w-full rounded-md border border-border bg-bg-elevated py-1.5 pl-8 pr-3 font-mono-nums text-sm text-slate-200 outline-none focus:border-primary"
            />
          </div>
          <button
            type="submit"
            disabled={loading}
            className="flex cursor-pointer items-center gap-2 rounded-md bg-primary px-4 py-1.5 text-sm font-medium text-white hover:bg-primary-dark disabled:opacity-50"
          >
            {loading ? <Loader2 size={14} className="animate-spin" /> : <Globe2 size={14} />}
            Check
          </button>
        </form>
        {error && <p className="mt-2 text-xs text-critical">{error}</p>}
      </div>

      {result && colors && (
        <div className="rounded-lg border border-border bg-surface p-5">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <span className="font-mono-nums text-lg font-semibold text-slate-100">{result.ip}</span>
              {result.is_mock && (
                <span className="rounded border border-border px-1.5 py-0.5 text-[10px] uppercase text-slate-500">
                  Mock data
                </span>
              )}
            </div>
            <span className={`rounded-md px-2.5 py-1 text-xs font-semibold ${colors.text} ${colors.bg}`}>
              {result.malicious_score}/100 malicious score
            </span>
          </div>

          <div className="mt-3 h-2 overflow-hidden rounded-full bg-bg-elevated">
            <div className={`h-full ${colors.bar}`} style={{ width: `${result.malicious_score}%` }} />
          </div>

          <div className="mt-4 grid grid-cols-2 gap-x-6 gap-y-2 text-sm sm:grid-cols-3">
            <div>
              <div className="text-[11px] uppercase text-slate-500">Country</div>
              <div className="text-slate-200">{result.country || '—'}</div>
            </div>
            <div>
              <div className="text-[11px] uppercase text-slate-500">ASN</div>
              <div className="font-mono-nums text-slate-200">{result.asn || '—'}</div>
            </div>
            <div>
              <div className="text-[11px] uppercase text-slate-500">ISP</div>
              <div className="text-slate-200">{result.isp || '—'}</div>
            </div>
            <div>
              <div className="text-[11px] uppercase text-slate-500">Total Reports</div>
              <div className="font-mono-nums text-slate-200">{result.total_reports}</div>
            </div>
            <div>
              <div className="text-[11px] uppercase text-slate-500">Last Reported</div>
              <div className="text-slate-200">
                {result.last_reported ? new Date(result.last_reported).toLocaleDateString() : '—'}
              </div>
            </div>
            <div>
              <div className="text-[11px] uppercase text-slate-500">Source</div>
              <div className="text-slate-200">{result.source}</div>
            </div>
          </div>

          {result.tags.length > 0 && (
            <div className="mt-4 flex items-center gap-2">
              <ShieldAlert size={14} className="text-critical" />
              <div className="flex flex-wrap gap-1.5">
                {result.tags.map((t) => (
                  <span key={t} className="rounded bg-critical-bg px-2 py-0.5 text-[11px] text-critical">
                    {t}
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {history.length > 1 && (
        <div>
          <h3 className="mb-2 flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wide text-slate-500">
            <Info size={12} /> Recent lookups
          </h3>
          <div className="space-y-1.5">
            {history.slice(1).map((r) => {
              const c = scoreColor(r.malicious_score)
              return (
                <button
                  key={r.ip}
                  onClick={() => setResult(r)}
                  className="flex w-full cursor-pointer items-center justify-between rounded-md border border-border bg-surface px-3 py-2 text-left hover:bg-surface-hover"
                >
                  <span className="font-mono-nums text-sm text-slate-300">{r.ip}</span>
                  <span className={`text-xs font-medium ${c.text}`}>{r.malicious_score}/100</span>
                </button>
              )
            })}
          </div>
        </div>
      )}
    </div>
  )
}
