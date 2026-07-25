import type { ReactNode } from 'react'
import { Navigate } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'
import { ShieldHalf } from 'lucide-react'

export default function ProtectedRoute({ children }: { children: ReactNode }) {
  const { user, loading } = useAuth()

  if (loading) {
    return (
      <div className="flex h-screen items-center justify-center bg-bg text-slate-400">
        <ShieldHalf className="animate-pulse text-primary" size={28} />
      </div>
    )
  }

  if (!user) {
    return <Navigate to="/login" replace />
  }

  return <>{children}</>
}
