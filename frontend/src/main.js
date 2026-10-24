import { createApp } from 'vue'
import { createPinia } from 'pinia'
import App from './App.vue'
import router from './router'
import { setSessionExpiredHandler } from './api'
import { useAuth } from './stores/auth'
import './styles.css'

const app = createApp(App)
app.use(createPinia())
app.use(router)

setSessionExpiredHandler(() => {
  useAuth().expire()
  const current = router.currentRoute.value
  if (!current.meta.guest) router.push({ name: 'login', query: { next: current.fullPath, expired: '1' } })
})

app.mount('#app')
