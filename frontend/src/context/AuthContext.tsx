import { createContext, useContext, useEffect, useState, type ReactNode } from 'react'
import { authApi } from '../services/api'
import type { User } from '../types'

interface AuthContextValue {
  user: User | null
  loading: boolean
  login: (username: string, password: string) => Promise<void>
  logout: () => void
}

const AuthContext = createContext<AuthContextValue | undefined>(undefined)

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    const stored = localStorage.getItem('socshield_user')
    const token = localStorage.getItem('socshield_token')
    if (stored && token) {
      setUser(JSON.parse(stored))
      authApi
        .me()
        .then((u) => {
          setUser(u)
          localStorage.setItem('socshield_user', JSON.stringify(u))
        })
        .catch(() => {
          localStorage.removeItem('socshield_token')
          localStorage.removeItem('socshield_user')
          setUser(null)
        })
        .finally(() => setLoading(false))
    } else {
      setLoading(false)
    }
  }, [])

  async function login(username: string, password: string) {
    const res = await authApi.login(username, password)
    localStorage.setItem('socshield_token', res.access_token)
    localStorage.setItem('socshield_user', JSON.stringify(res.user))
    setUser(res.user)
  }

  function logout() {
    localStorage.removeItem('socshield_token')
    localStorage.removeItem('socshield_user')
    setUser(null)
  }

  return <AuthContext.Provider value={{ user, loading, login, logout }}>{children}</AuthContext.Provider>
}

export function useAuth() {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth must be used within AuthProvider')
  return ctx
}
