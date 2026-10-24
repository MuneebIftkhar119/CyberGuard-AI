import { createRouter, createWebHistory } from 'vue-router'
import { useAuth } from './stores/auth'

const routes = [
  { path: '/login', name: 'login', component: () => import('./views/LoginView.vue'), meta: { guest: true, title: 'Log in' } },
  { path: '/register', name: 'register', component: () => import('./views/RegisterView.vue'), meta: { guest: true, title: 'Create account' } },
  { path: '/', name: 'dashboard', component: () => import('./views/DashboardView.vue'), meta: { title: 'Overview' } },
  { path: '/password', name: 'password', component: () => import('./views/PasswordView.vue'), meta: { title: 'Password check' } },
  { path: '/url', name: 'url', component: () => import('./views/UrlView.vue'), meta: { title: 'Link scanner' } },
  { path: '/phishing', name: 'phishing', component: () => import('./views/PhishingView.vue'), meta: { title: 'Message check' } },
  { path: '/chat', name: 'chat', component: () => import('./views/ChatView.vue'), meta: { title: 'Ask the tutor' } },
  { path: '/history', name: 'history', component: () => import('./views/HistoryView.vue'), meta: { title: 'History' } },
  { path: '/history/:id', name: 'scan', component: () => import('./views/ScanDetailView.vue'), meta: { title: 'Report' } },
  { path: '/:pathMatch(.*)*', name: 'notfound', component: () => import('./views/NotFoundView.vue'), meta: { public: true, title: 'Not found' } },
]

const router = createRouter({
  history: createWebHistory(),
  routes,
  scrollBehavior: () => ({ top: 0 }),
})

router.beforeEach(async (to) => {
  const auth = useAuth()
  await auth.init()
  if (to.meta.public) return true
  if (to.meta.guest) return auth.isAuthenticated ? { name: 'dashboard' } : true
  if (!auth.isAuthenticated) return { name: 'login', query: to.fullPath !== '/' ? { next: to.fullPath } : {} }
  return true
})

router.afterEach((to) => {
  document.title = to.meta.title ? `${to.meta.title} · CyberGuard AI` : 'CyberGuard AI'
})

export default router
