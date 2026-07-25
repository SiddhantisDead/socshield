import {
  ResponsiveContainer,
  AreaChart,
  Area,
  LineChart,
  Line,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
} from 'recharts'
import type { TimelinePoint, TopIp, MitreHeatmapCell } from '../types'

const TOOLTIP_STYLE = {
  background: '#10161f',
  border: '1px solid #1f2937',
  borderRadius: 6,
  fontSize: 12,
  color: '#e2e8f0',
}

const AXIS_TICK = { fill: '#6b7280', fontSize: 11 }

export function EmptyChartState({ label }: { label: string }) {
  return (
    <div className="flex h-full min-h-[160px] items-center justify-center text-xs text-slate-600">{label}</div>
  )
}

export function AttackTimelineChart({ data }: { data: TimelinePoint[] }) {
  if (!data.length) return <EmptyChartState label="No timeline data yet — upload logs to populate" />
  return (
    <ResponsiveContainer width="100%" height={220}>
      <AreaChart data={data} margin={{ top: 8, right: 8, left: -20, bottom: 0 }}>
        <defs>
          <linearGradient id="timelineFill" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="#3b82f6" stopOpacity={0.35} />
            <stop offset="100%" stopColor="#3b82f6" stopOpacity={0} />
          </linearGradient>
        </defs>
        <CartesianGrid stroke="#1f2937" strokeDasharray="3 3" vertical={false} />
        <XAxis dataKey="bucket" tick={AXIS_TICK} axisLine={{ stroke: '#1f2937' }} tickLine={false} minTickGap={30} />
        <YAxis tick={AXIS_TICK} axisLine={{ stroke: '#1f2937' }} tickLine={false} allowDecimals={false} width={30} />
        <Tooltip contentStyle={TOOLTIP_STYLE} labelStyle={{ color: '#94a3b8' }} />
        <Area type="monotone" dataKey="count" stroke="#3b82f6" strokeWidth={2} fill="url(#timelineFill)" name="Alerts" />
      </AreaChart>
    </ResponsiveContainer>
  )
}

export function AlertTrendChart({ data }: { data: TimelinePoint[] }) {
  if (!data.length) return <EmptyChartState label="No trend data yet" />
  return (
    <ResponsiveContainer width="100%" height={220}>
      <LineChart data={data} margin={{ top: 8, right: 8, left: -20, bottom: 0 }}>
        <CartesianGrid stroke="#1f2937" strokeDasharray="3 3" vertical={false} />
        <XAxis dataKey="bucket" tick={AXIS_TICK} axisLine={{ stroke: '#1f2937' }} tickLine={false} />
        <YAxis tick={AXIS_TICK} axisLine={{ stroke: '#1f2937' }} tickLine={false} allowDecimals={false} width={30} />
        <Tooltip contentStyle={TOOLTIP_STYLE} labelStyle={{ color: '#94a3b8' }} />
        <Line type="monotone" dataKey="count" stroke="#d97706" strokeWidth={2} dot={{ r: 3 }} name="Alerts/day" />
      </LineChart>
    </ResponsiveContainer>
  )
}

export function TopSourceIpsChart({ data }: { data: TopIp[] }) {
  if (!data.length) return <EmptyChartState label="No source IP activity yet" />
  return (
    <ResponsiveContainer width="100%" height={220}>
      <BarChart data={data} layout="vertical" margin={{ top: 8, right: 16, left: 8, bottom: 0 }}>
        <CartesianGrid stroke="#1f2937" strokeDasharray="3 3" horizontal={false} />
        <XAxis type="number" tick={AXIS_TICK} axisLine={{ stroke: '#1f2937' }} tickLine={false} allowDecimals={false} />
        <YAxis
          type="category"
          dataKey="ip"
          tick={{ ...AXIS_TICK, fontFamily: 'Fira Code, monospace' }}
          axisLine={{ stroke: '#1f2937' }}
          tickLine={false}
          width={100}
        />
        <Tooltip contentStyle={TOOLTIP_STYLE} labelStyle={{ color: '#94a3b8' }} cursor={{ fill: '#1f293733' }} />
        <Bar dataKey="count" fill="#ea580c" radius={[0, 4, 4, 0]} name="Alerts" />
      </BarChart>
    </ResponsiveContainer>
  )
}

function heatColor(count: number, max: number) {
  const ratio = max > 0 ? count / max : 0
  if (ratio > 0.75) return { bg: 'bg-critical-bg', text: 'text-critical', border: 'border-critical/40' }
  if (ratio > 0.45) return { bg: 'bg-high-bg', text: 'text-high', border: 'border-high/40' }
  if (ratio > 0.15) return { bg: 'bg-medium-bg', text: 'text-medium', border: 'border-medium/40' }
  return { bg: 'bg-low-bg', text: 'text-low', border: 'border-low/40' }
}

export function MitreHeatmap({ data }: { data: MitreHeatmapCell[] }) {
  if (!data.length) return <EmptyChartState label="No MITRE ATT&CK techniques observed yet" />
  const max = Math.max(...data.map((d) => d.count))

  return (
    <div className="grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-4">
      {data.map((cell) => {
        const colors = heatColor(cell.count, max)
        return (
          <div
            key={cell.mitre_id}
            className={`rounded-md border p-3 ${colors.bg} ${colors.border}`}
            title={`${cell.mitre_id} — ${cell.technique}: ${cell.count} alert(s)`}
          >
            <div className="flex items-center justify-between">
              <span className="font-mono-nums text-xs font-semibold text-slate-300">{cell.mitre_id}</span>
              <span className={`font-mono-nums text-sm font-bold ${colors.text}`}>{cell.count}</span>
            </div>
            <div className="mt-1 truncate text-[11px] text-slate-400">{cell.technique}</div>
          </div>
        )
      })}
    </div>
  )
}
