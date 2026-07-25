import type { ReactNode } from 'react'
import { BrowserRouter, Routes, Route } from 'react-router-dom'
import { AuthProvider } from './context/AuthContext'
import ProtectedRoute from './components/ProtectedRoute'
import Layout from './components/Layout'
import Login from './pages/Login'
import Dashboard from './pages/Dashboard'
import Alerts from './pages/Alerts'
import Incident from './pages/Incident'
import LogViewerPage from './pages/LogViewerPage'
import ThreatIntel from './pages/ThreatIntel'
import Scan from './pages/Scan'

function withLayout(title: string, node: ReactNode) {
  return (
    <ProtectedRoute>
      <Layout title={title}>{node}</Layout>
    </ProtectedRoute>
  )
}

export default function App() {
  return (
    <AuthProvider>
      <BrowserRouter>
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route path="/" element={withLayout('Dashboard', <Dashboard />)} />
          <Route path="/alerts" element={withLayout('Alerts', <Alerts />)} />
          <Route path="/incidents" element={withLayout('Incidents', <Incident />)} />
          <Route path="/logs" element={withLayout('Log Viewer', <LogViewerPage />)} />
          <Route path="/threat-intel" element={withLayout('Threat Intelligence', <ThreatIntel />)} />
          <Route path="/scan" element={withLayout('Malware Scan', <Scan />)} />
        </Routes>
      </BrowserRouter>
    </AuthProvider>
  )
}
