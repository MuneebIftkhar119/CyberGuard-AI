import axios from 'axios'

// In production set VITE_API_URL to your backend origin, e.g. https://cyberguard-api.onrender.com
// Locally leave it empty: Vite proxies /api to Django.
const baseURL = `${(import.meta.env.VITE_API_URL || '').replace(/\/$/, '')}/api`

const ACCESS = 'cg_access'
const REFRESH = 'cg_refresh'

function read(key) {
  try { return localStorage.getItem(key) } catch { return null }
}
function write(key, value) {
  try { value ? localStorage.setItem(key, value) : localStorage.removeItem(key) } catch { /* storage blocked */ }
}

export const tokens = {
  get access() { return read(ACCESS) },
  get refresh() { return read(REFRESH) },
  set({ access, refresh }) {
    if (access) write(ACCESS, access)
    if (refresh) write(REFRESH, refresh)
  },
  clear() { write(ACCESS, null); write(REFRESH, null) },
}

export const api = axios.create({ baseURL, timeout: 60000 })

api.interceptors.request.use((config) => {
  const access = tokens.access
  if (access) config.headers.Authorization = `Bearer ${access}`
  return config
})

// On a 401, refresh the access token once (shared across parallel requests) and retry.
let refreshing = null
let onSessionExpired = () => {}
export function setSessionExpiredHandler(fn) { onSessionExpired = fn }

api.interceptors.response.use(
  (res) => res,
  async (error) => {
    const original = error.config
    const status = error.response?.status
    const isAuthCall = original?.url?.startsWith('/auth/')
    if (status !== 401 || original._retried || isAuthCall || !tokens.refresh) {
      return Promise.reject(error)
    }
    original._retried = true
    try {
      refreshing ||= axios
        .post(`${baseURL}/auth/refresh/`, { refresh: tokens.refresh })
        .then(({ data }) => tokens.set(data))
        .finally(() => { refreshing = null })
      await refreshing
      return api(original)
    } catch (e) {
      tokens.clear()
      onSessionExpired()
      return Promise.reject(error)
    }
  },
)

/** Turn any API error into one readable sentence for the UI. */
export function errorMessage(error, fallback = 'Something went wrong. Try again.') {
  if (!error?.response) {
    return error?.code === 'ECONNABORTED'
      ? 'The server took too long to respond. If it was asleep, try again in a few seconds.'
      : 'Can’t reach the server. Check your connection — a free-tier server may take ~30 seconds to wake up.'
  }
  const { status, data } = error.response
  if (status === 429) return data?.detail || 'Too many requests. Wait a minute and try again.'
  if (typeof data === 'string') return fallback
  if (data?.detail) return data.detail
  if (data && typeof data === 'object') {
    const first = Object.entries(data)[0]
    if (first) {
      const [field, msgs] = first
      const msg = Array.isArray(msgs) ? msgs[0] : msgs
      return field === 'non_field_errors' ? msg : `${field.replace('_', ' ')}: ${msg}`
    }
  }
  return fallback
}
