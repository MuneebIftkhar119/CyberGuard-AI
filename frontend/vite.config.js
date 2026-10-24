import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

export default defineConfig({
  plugins: [vue()],
  server: {
    port: 5173,
    // In dev, /api calls are proxied to Django so no CORS setup is needed locally.
    proxy: {
      '/api': { target: process.env.VITE_DEV_API_TARGET || 'http://127.0.0.1:8000', changeOrigin: true },
    },
  },
})
