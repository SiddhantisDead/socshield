import { useRef, useState } from 'react'
import { Bug, UploadCloud, Loader2, ShieldCheck, ShieldAlert } from 'lucide-react'
import { scanApi } from '../services/api'
import type { FileScanResult, Severity } from '../types'
import SeverityBadge from '../components/SeverityBadge'

export default function Scan() {
  const fileRef = useRef<HTMLInputElement>(null)
  const [scanning, setScanning] = useState(false)
  const [result, setResult] = useState<FileScanResult | null>(null)
  const [error, setError] = useState('')

  async function handleScan() {
    const file = fileRef.current?.files?.[0]
    if (!file) return
    setScanning(true)
    setError('')
    setResult(null)
    try {
      const res = await scanApi.scanFile(file)
      setResult(res)
      if (fileRef.current) fileRef.current.value = ''
    } catch {
      setError('Scan failed — the file may be too large or unreadable.')
    } finally {
      setScanning(false)
    }
  }

  return (
    <div className="max-w-2xl space-y-5">
      <div className="rounded-lg border border-border bg-surface p-4">
        <h2 className="mb-1 flex items-center gap-2 text-sm font-semibold text-slate-200">
          <Bug size={16} className="text-primary" /> YARA Malware Scanner
        </h2>
        <p className="mb-3 text-xs text-slate-500">
          Upload a file to scan it against the bundled YARA ruleset (credential-dumping tool strings, PHP webshell
          patterns, PowerShell downloaders, EICAR test signature). Try the safe sample files in{' '}
          <code className="text-slate-400">datasets/malware/</code>.
        </p>
        <div className="flex flex-wrap items-center gap-3">
          <input
            ref={fileRef}
            type="file"
            className="block cursor-pointer text-xs text-slate-400 file:mr-3 file:cursor-pointer file:rounded-md file:border-0 file:bg-primary/15 file:px-3 file:py-1.5 file:text-xs file:font-medium file:text-primary hover:file:bg-primary/25"
          />
          <button
            onClick={handleScan}
            disabled={scanning}
            className="flex cursor-pointer items-center gap-2 rounded-md bg-primary px-4 py-1.5 text-sm font-medium text-white hover:bg-primary-dark disabled:cursor-not-allowed disabled:opacity-50"
          >
            {scanning ? <Loader2 size={14} className="animate-spin" /> : <UploadCloud size={14} />}
            Scan File
          </button>
        </div>
        {error && <p className="mt-2 text-xs text-critical">{error}</p>}
      </div>

      {result && (
        <div className="rounded-lg border border-border bg-surface p-5">
          <div className="flex items-center justify-between">
            <div>
              <div className="text-sm font-medium text-slate-200">{result.filename}</div>
              <div className="font-mono-nums text-[11px] text-slate-500">{result.sha256}</div>
            </div>
            {result.is_malicious ? (
              <span className="flex items-center gap-1.5 rounded-md bg-critical-bg px-2.5 py-1 text-xs font-semibold text-critical">
                <ShieldAlert size={14} /> Malicious indicators found
              </span>
            ) : (
              <span className="flex items-center gap-1.5 rounded-md bg-success/10 px-2.5 py-1 text-xs font-semibold text-success">
                <ShieldCheck size={14} /> No YARA matches
              </span>
            )}
          </div>

          {result.matched_rules.length > 0 && (
            <div className="mt-4 space-y-2">
              {result.matched_rules.map((m) => (
                <div key={m.rule} className="rounded-md border border-border bg-bg-elevated p-3">
                  <div className="mb-1 flex items-center gap-2">
                    <SeverityBadge
                      severity={(m.severity.charAt(0).toUpperCase() + m.severity.slice(1)) as Severity}
                      compact
                    />
                    <span className="font-mono-nums text-sm font-medium text-slate-200">{m.rule}</span>
                    {m.mitre_id && (
                      <span className="ml-auto rounded border border-border px-1.5 py-0.5 font-mono-nums text-[11px] text-slate-400">
                        {m.mitre_id}
                      </span>
                    )}
                  </div>
                  <p className="text-xs text-slate-400">{m.description}</p>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  )
}
