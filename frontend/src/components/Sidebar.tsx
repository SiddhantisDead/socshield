import { NavLink } from 'react-router-dom'
import { LayoutDashboard, ShieldAlert, ClipboardList, FileText, Globe2, Bug, ShieldHalf } from 'lucide-react'

const NAV_ITEMS = [
  { to: '/', label: 'Dashboard', icon: LayoutDashboard, end: true },
  { to: '/alerts', label: 'Alerts', icon: ShieldAlert },
  { to: '/incidents', label: 'Incidents', icon: ClipboardList },
  { to: '/logs', label: 'Log Viewer', icon: FileText },
  { to: '/threat-intel', label: 'Threat Intel', icon: Globe2 },
  { to: '/scan', label: 'Malware Scan', icon: Bug },
]

export default function Sidebar() {
  return (
    <aside className="flex h-full w-60 shrink-0 flex-col border-r border-border bg-bg-elevated">
      <div className="flex items-center gap-2 px-5 py-5">
        <ShieldHalf className="text-primary" size={26} strokeWidth={2} />
        <div>
          <div className="text-sm font-semibold tracking-wide text-slate-100">SOCShield</div>
          <div className="text-[10px] uppercase tracking-wider text-slate-500">SOC Analyst Console</div>
        </div>
      </div>

      <nav className="flex-1 space-y-1 px-3 py-2">
        {NAV_ITEMS.map(({ to, label, icon: Icon, end }) => (
          <NavLink
            key={to}
            to={to}
            end={end}
            className={({ isActive }) =>
              `flex items-center gap-3 rounded-md px-3 py-2 text-sm font-medium transition-colors duration-150 ${
                isActive
                  ? 'bg-primary/15 text-primary'
                  : 'text-slate-400 hover:bg-surface-hover hover:text-slate-100'
              }`
            }
          >
            <Icon size={17} strokeWidth={2} />
            {label}
          </NavLink>
        ))}
      </nav>

      <div className="border-t border-border px-4 py-3 text-[11px] text-slate-600">
        Sigma · YARA · MITRE ATT&CK
      </div>
    </aside>
  )
}
