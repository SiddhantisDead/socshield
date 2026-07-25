import { AlertOctagon, AlertTriangle, AlertCircle, Info, CircleDot } from 'lucide-react'
import type { Severity } from '../types'

const CONFIG: Record<Severity, { text: string; bg: string; icon: typeof AlertOctagon }> = {
  Critical: { text: 'text-critical', bg: 'bg-critical-bg', icon: AlertOctagon },
  High: { text: 'text-high', bg: 'bg-high-bg', icon: AlertTriangle },
  Medium: { text: 'text-medium', bg: 'bg-medium-bg', icon: AlertCircle },
  Low: { text: 'text-low', bg: 'bg-low-bg', icon: Info },
  Informational: { text: 'text-info', bg: 'bg-info-bg', icon: CircleDot },
}

export default function SeverityBadge({ severity, compact = false }: { severity: Severity; compact?: boolean }) {
  const cfg = CONFIG[severity] ?? CONFIG.Informational
  const Icon = cfg.icon
  return (
    <span
      className={`inline-flex items-center gap-1 rounded-md border border-border px-2 py-0.5 text-xs font-medium ${cfg.text} ${cfg.bg}`}
    >
      <Icon size={12} strokeWidth={2.5} />
      {!compact && severity}
    </span>
  )
}
