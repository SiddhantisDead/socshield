import axios from 'axios'
import type {
  AlertItem,
  AlertListResponse,
  AlertStatus,
  DashboardStats,
  FileScanResult,
  Incident,
  IncidentListResponse,
  IncidentStatus,
  IpReputationResult,
  LogListResponse,
  LogType,
  LogUploadResult,
  Severity,
  User,
} from '../types'

// In local dev / Docker, '/api' is proxied to the backend (see vite.config.ts
// / docker/nginx.conf). When the frontend and backend are deployed to
// separate hosts (e.g. Vercel + Heroku), set VITE_API_BASE_URL to the
// backend's full URL (e.g. https://api.yourdomain.com/api) at build time.
const api = axios.create({ baseURL: import.meta.env.VITE_API_BASE_URL || '/api' })

api.interceptors.request.use((config) => {
  const token = localStorage.getItem('socshield_token')
  if (token) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

api.interceptors.response.use(
  (res) => res,
  (error) => {
    if (error.response?.status === 401) {
      localStorage.removeItem('socshield_token')
      localStorage.removeItem('socshield_user')
      if (window.location.pathname !== '/login') {
        window.location.href = '/login'
      }
    }
    return Promise.reject(error)
  },
)

export interface LoginResponse {
  access_token: string
  token_type: string
  user: User
}

export const authApi = {
  login: (username: string, password: string) =>
    api.post<LoginResponse>('/auth/login', { username, password }).then((r) => r.data),
  me: () => api.get<User>('/auth/me').then((r) => r.data),
}

export interface LogFilters {
  search?: string
  severity?: Severity
  hostname?: string
  source_ip?: string
  log_type?: LogType
  limit?: number
  offset?: number
}

export const logsApi = {
  list: (filters: LogFilters = {}) => api.get<LogListResponse>('/logs', { params: filters }).then((r) => r.data),
  upload: (file: File, logType: LogType) => {
    const form = new FormData()
    form.append('file', file)
    form.append('log_type', logType)
    return api
      .post<LogUploadResult>('/upload-log', form, { headers: { 'Content-Type': 'multipart/form-data' } })
      .then((r) => r.data)
  },
  exportUrl: (format: 'csv' | 'json', filters: LogFilters = {}) => {
    const params = new URLSearchParams({ format })
    Object.entries(filters).forEach(([key, value]) => {
      if (value !== undefined && value !== '') params.set(key, String(value))
    })
    return `/api/logs/export?${params.toString()}`
  },
}

export interface AlertFilters {
  severity?: Severity
  status?: AlertStatus
  mitre_id?: string
  search?: string
  limit?: number
  offset?: number
}

export const alertsApi = {
  list: (filters: AlertFilters = {}) => api.get<AlertListResponse>('/alerts', { params: filters }).then((r) => r.data),
  get: (id: number) => api.get<AlertItem>(`/alerts/${id}`).then((r) => r.data),
  updateStatus: (id: number, status: AlertStatus) =>
    api.put<AlertItem>(`/alerts/${id}/status`, { status }).then((r) => r.data),
  rescan: () => api.post('/alerts/rescan').then((r) => r.data),
}

export const incidentsApi = {
  list: (filters: { status?: IncidentStatus; limit?: number; offset?: number } = {}) =>
    api.get<IncidentListResponse>('/incidents', { params: filters }).then((r) => r.data),
  get: (id: number) => api.get<Incident>(`/incidents/${id}`).then((r) => r.data),
  create: (alertId: number, title?: string) =>
    api.post<Incident>('/incidents', { alert_id: alertId, title }).then((r) => r.data),
  update: (
    id: number,
    payload: Partial<{ status: IncidentStatus; assigned_to_id: number | null; resolution: string; title: string }>,
  ) => api.put<Incident>(`/incidents/${id}`, payload).then((r) => r.data),
  addNote: (id: number, comment: string, nextAction: string) =>
    api.post(`/incidents/${id}/notes`, { comment, next_action: nextAction }).then((r) => r.data),
}

export const dashboardApi = {
  get: () => api.get<DashboardStats>('/dashboard').then((r) => r.data),
}

export const threatIntelApi = {
  lookup: (ip: string) => api.get<IpReputationResult>('/threat-intel', { params: { ip } }).then((r) => r.data),
}

export const scanApi = {
  scanFile: (file: File) => {
    const form = new FormData()
    form.append('file', file)
    return api
      .post<FileScanResult>('/scan', form, { headers: { 'Content-Type': 'multipart/form-data' } })
      .then((r) => r.data)
  },
}

export const usersApi = {
  list: () => api.get<User[]>('/users').then((r) => r.data),
}

export default api
