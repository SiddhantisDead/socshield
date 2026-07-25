import { useState } from 'react'
import { LogOut, ShieldCheck, ChevronDown } from 'lucide-react'
import { useAuth } from '../context/AuthContext'

export default function Navbar({ title }: { title: string }) {
  const { user, logout } = useAuth()
  const [menuOpen, setMenuOpen] = useState(false)

  return (
    <header className="flex h-14 shrink-0 items-center justify-between border-b border-border bg-bg-elevated px-6">
      <h1 className="text-base font-semibold text-slate-100">{title}</h1>

      <div className="relative">
        <button
          onClick={() => setMenuOpen((v) => !v)}
          className="flex cursor-pointer items-center gap-2 rounded-md px-2 py-1.5 text-sm text-slate-300 hover:bg-surface-hover"
        >
          <span className="flex h-7 w-7 items-center justify-center rounded-full bg-primary/15 text-primary">
            <ShieldCheck size={15} />
          </span>
          <span className="font-medium text-slate-200">{user?.username}</span>
          <span className="rounded border border-border px-1.5 py-0.5 text-[10px] uppercase text-slate-500">
            {user?.role}
          </span>
          <ChevronDown size={14} className="text-slate-500" />
        </button>

        {menuOpen && (
          <div className="absolute right-0 top-full z-20 mt-1 w-44 overflow-hidden rounded-md border border-border bg-surface shadow-lg">
            <button
              onClick={logout}
              className="flex w-full cursor-pointer items-center gap-2 px-3 py-2 text-left text-sm text-slate-300 hover:bg-surface-hover hover:text-critical"
            >
              <LogOut size={14} />
              Log out
            </button>
          </div>
        )}
      </div>
    </header>
  )
}
