import type { LucideIcon } from 'lucide-react'

interface StatCardProps {
  label: string
  value: number | string
  icon: LucideIcon
  accent?: 'primary' | 'critical' | 'high' | 'success' | 'info'
  sublabel?: string
}

const ACCENT_CLASSES: Record<string, string> = {
  primary: 'text-primary bg-primary/10',
  critical: 'text-critical bg-critical-bg',
  high: 'text-high bg-high-bg',
  success: 'text-success bg-success/10',
  info: 'text-info bg-info-bg',
}

export default function StatCard({ label, value, icon: Icon, accent = 'primary', sublabel }: StatCardProps) {
  return (
    <div className="flex items-center gap-4 rounded-lg border border-border bg-surface p-4">
      <div className={`flex h-11 w-11 shrink-0 items-center justify-center rounded-lg ${ACCENT_CLASSES[accent]}`}>
        <Icon size={20} strokeWidth={2} />
      </div>
      <div className="min-w-0">
        <div className="font-mono-nums text-2xl font-semibold text-slate-100">{value}</div>
        <div className="truncate text-xs text-slate-400">{label}</div>
        {sublabel && <div className="truncate text-[11px] text-slate-500">{sublabel}</div>}
      </div>
    </div>
  )
}
