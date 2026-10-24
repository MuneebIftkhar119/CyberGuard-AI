import { defineStore } from 'pinia'
import { api, tokens } from '../api'

export const useAuth = defineStore('auth', {
  state: () => ({ user: null, ready: false }),
  getters: {
    isAuthenticated: (s) => !!s.user,
  },
  actions: {
    async init() {
      if (this.ready) return
      if (tokens.access || tokens.refresh) {
        try {
          const { data } = await api.get('/auth/me/')
          this.user = data
        } catch {
          tokens.clear()
        }
      }
      this.ready = true
    },
    async login(username, password) {
      const { data } = await api.post('/auth/login/', { username, password })
      tokens.set(data)
      const me = await api.get('/auth/me/')
      this.user = me.data
    },
    async register(payload) {
      const { data } = await api.post('/auth/register/', payload)
      tokens.set(data)
      this.user = data.user
    },
    async logout() {
      const refresh = tokens.refresh
      tokens.clear()
      this.user = null
      if (refresh) api.post('/auth/logout/', { refresh }).catch(() => {})
    },
    expire() {
      tokens.clear()
      this.user = null
    },
  },
})
