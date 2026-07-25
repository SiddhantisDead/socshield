import { useRef, useState } from 'react'
import { UploadCloud, Loader2, CheckCircle2, AlertTriangle } from 'lucide-react'
import { logsApi } from '../services/api'
import type { LogType, LogUploadResult } from '../types'
import LogViewer from '../components/LogViewer'

const LOG_TYPES: { value: LogType; label: string; hint: string }[] = [
  { value: 'windows', label: 'Windows Event Log (JSON)', hint: 'wevtutil qe /f:json export' },
  { value: 'linux', label: 'Linux auth.log', hint: 'syslog-style SSH/sudo/useradd' },
  { value: 'apache', label: 'Apache/Nginx access log', hint: 'combined log format' },
  { value: 'firewall', label: 'Firewall log (JSON/CSV)', hint: 'Action, SourceIp, DestinationPort…' },
  { value: 'dns', label: 'DNS query log (JSON/CSV)', hint: 'QueryName, ResponseCode…' },
]

export default function LogViewerPage() {
  const fileRef = useRef<HTMLInputElement>(null)
  const [logType, setLogType] = useState<LogType>('windows')
  const [uploading, setUploading] = useState(false)
  const [result, setResult] = useState<LogUploadResult | null>(null)
  const [error, setError] = useState('')
  const [refreshKey, setRefreshKey] = useState(0)

  async function handleUpload() {
    const file = fileRef.current?.files?.[0]
    if (!file) return
    setUploading(true)
    setError('')
    setResult(null)
    try {
      const res = await logsApi.upload(file, logType)
      setResult(res)
      setRefreshKey((k) => k + 1)
      if (fileRef.current) fileRef.current.value = ''
    } catch {
      setError('Upload failed — check the file format matches the selected log type.')
    } finally {
      setUploading(false)
    }
  }

  return (
    <div className="space-y-5">
      <div className="rounded-lg border border-border bg-surface p-4">
        <h2 className="mb-3 text-sm font-semibold text-slate-200">Upload Log File</h2>
        <div className="flex flex-wrap items-end gap-3">
          <div>
            <label className="mb-1 block text-xs font-medium text-slate-400">Log type</label>
            <select
              value={logType}
              onChange={(e) => setLogType(e.target.value as LogType)}
              className="cursor-pointer rounded-md border border-border bg-bg-elevated px-2.5 py-1.5 text-sm text-slate-200 outline-none focus:border-primary"
            >
              {LOG_TYPES.map((t) => (
                <option key={t.value} value={t.value}>
                  {t.label}
                </option>
              ))}
            </select>
          </div>
          <div>
            <label className="mb-1 block text-xs font-medium text-slate-400">File</label>
            <input
              ref={fileRef}
              type="file"
              className="block cursor-pointer text-xs text-slate-400 file:mr-3 file:cursor-pointer file:rounded-md file:border-0 file:bg-primary/15 file:px-3 file:py-1.5 file:text-xs file:font-medium file:text-primary hover:file:bg-primary/25"
            />
          </div>
          <button
            onClick={handleUpload}
            disabled={uploading}
            className="flex cursor-pointer items-center gap-2 rounded-md bg-primary px-4 py-1.5 text-sm font-medium text-white hover:bg-primary-dark disabled:cursor-not-allowed disabled:opacity-50"
          >
            {uploading ? <Loader2 size={14} className="animate-spin" /> : <UploadCloud size={14} />}
            Upload &amp; Analyze
          </button>
        </div>
        <p className="mt-2 text-[11px] text-slate-500">
          {LOG_TYPES.find((t) => t.value === logType)?.hint} — sample files available in{' '}
          <code className="text-slate-400">datasets/</code>
        </p>

        {result && (
          <div className="mt-3 flex items-center gap-2 rounded-md border border-success/30 bg-success/10 px-3 py-2 text-xs text-success">
            <CheckCircle2 size={14} />
            Ingested {result.ingested} record(s) from {result.filename} — {result.alerts_generated} alert(s)
            generated.
          </div>
        )}
        {error && (
          <div className="mt-3 flex items-center gap-2 rounded-md border border-critical/30 bg-critical-bg px-3 py-2 text-xs text-critical">
            <AlertTriangle size={14} />
            {error}
          </div>
        )}
      </div>

      <LogViewer refreshKey={refreshKey} />
    </div>
  )
}
