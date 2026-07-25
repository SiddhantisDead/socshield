import { useState, type FormEvent } from 'react'
import { useNavigate } from 'react-router-dom'
import { ShieldHalf, Loader2 } from 'lucide-react'
import { useAuth } from '../context/AuthContext'

export default function Login() {
  const { login } = useAuth()
  const navigate = useNavigate()
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  async function handleSubmit(e: FormEvent) {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      await login(username, password)
      navigate('/')
    } catch {
      setError('Invalid username or password')
    } finally {
      setLoading(false)
    }
  }

  function fillDemo(role: 'owner' | 'analyst') {
    setUsername(role === 'owner' ? 'bladewasworthit' : 'analyst')
    setPassword(role === 'owner' ? 'socblade' : 'analyst123')
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-bg px-4">
      <div className="w-full max-w-sm">
        <div className="mb-8 flex flex-col items-center gap-2">
          <ShieldHalf className="text-primary" size={40} strokeWidth={1.8} />
          <h1 className="text-xl font-semibold text-slate-100">SOCShield</h1>
          <p className="text-sm text-slate-500">SOC Analyst Simulation Platform</p>
        </div>

        <form
          onSubmit={handleSubmit}
          className="space-y-4 rounded-lg border border-border bg-surface p-6 shadow-xl shadow-black/20"
        >
          <div>
            <label htmlFor="username" className="mb-1 block text-xs font-medium text-slate-400">
              Username
            </label>
            <input
              id="username"
              autoComplete="username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              required
              className="w-full rounded-md border border-border bg-bg-elevated px-3 py-2 text-sm text-slate-100 outline-none focus:border-primary focus:ring-1 focus:ring-primary"
            />
          </div>
          <div>
            <label htmlFor="password" className="mb-1 block text-xs font-medium text-slate-400">
              Password
            </label>
            <input
              id="password"
              type="password"
              autoComplete="current-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              className="w-full rounded-md border border-border bg-bg-elevated px-3 py-2 text-sm text-slate-100 outline-none focus:border-primary focus:ring-1 focus:ring-primary"
            />
          </div>

          {error && (
            <p role="alert" className="text-xs text-critical">
              {error}
            </p>
          )}

          <button
            type="submit"
            disabled={loading}
            className="flex w-full cursor-pointer items-center justify-center gap-2 rounded-md bg-primary py-2 text-sm font-medium text-white transition-colors hover:bg-primary-dark disabled:cursor-not-allowed disabled:opacity-60"
          >
            {loading && <Loader2 size={15} className="animate-spin" />}
            Sign in
          </button>

          <div className="border-t border-border pt-3 text-center text-[11px] text-slate-500">
            Demo accounts
            <div className="mt-2 flex justify-center gap-2">
              <button
                type="button"
                onClick={() => fillDemo('owner')}
                className="cursor-pointer rounded border border-border px-2 py-1 text-slate-400 hover:border-primary hover:text-primary"
              >
                bladewasworthit / socblade
              </button>
              <button
                type="button"
                onClick={() => fillDemo('analyst')}
                className="cursor-pointer rounded border border-border px-2 py-1 text-slate-400 hover:border-primary hover:text-primary"
              >
                analyst / analyst123
              </button>
            </div>
          </div>
        </form>
      </div>
    </div>
  )
}
