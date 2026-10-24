<script setup>
import { useRouter } from 'vue-router'
import { useAuth } from '../stores/auth'
import BrandMark from './BrandMark.vue'
import NavIcon from './NavIcon.vue'

const auth = useAuth()
const router = useRouter()

const nav = [
  { to: '/', label: 'Overview', icon: 'home' },
  { to: '/password', label: 'Password check', short: 'Password', icon: 'key' },
  { to: '/url', label: 'Link scanner', short: 'Links', icon: 'link' },
  { to: '/phishing', label: 'Message check', short: 'Messages', icon: 'mail' },
  { to: '/chat', label: 'Ask the tutor', short: 'Tutor', icon: 'chat' },
  { to: '/history', label: 'History', icon: 'clock' },
]

async function logout() {
  await auth.logout()
  router.push({ name: 'login' })
}
</script>

<template>
  <div class="shell">
    <a class="skip" href="#main">Skip to content</a>
    <aside class="side">
      <RouterLink to="/" class="brand"><BrandMark /></RouterLink>
      <nav aria-label="Main">
        <RouterLink v-for="item in nav" :key="item.to" :to="item.to" class="nav-item"
                    :class="{ exact: item.to === '/' }">
          <NavIcon :name="item.icon" />
          <span>{{ item.label }}</span>
        </RouterLink>
      </nav>
      <div class="me">
        <div class="who">
          <strong>{{ auth.user?.username }}</strong>
          <span class="muted small">{{ auth.user?.email }}</span>
        </div>
        <button class="btn-link small" @click="logout">Log out</button>
      </div>
    </aside>

    <header class="topbar">
      <RouterLink to="/" class="brand"><BrandMark compact /></RouterLink>
      <button class="btn-link small" @click="logout">Log out</button>
    </header>

    <main id="main" class="main"><slot /></main>

    <nav class="tabs" aria-label="Main">
      <RouterLink v-for="item in nav.filter(i => i.to !== '/history')" :key="item.to" :to="item.to"
                  class="tab" :class="{ exact: item.to === '/' }">
        <NavIcon :name="item.icon" />
        <span>{{ item.short || item.label }}</span>
      </RouterLink>
    </nav>
  </div>
</template>

<style scoped>
.shell { min-height: 100vh; }
.skip { position: absolute; left: -999px; top: 8px; background: var(--ink); color: var(--paper); padding: 8px 12px; z-index: 10; }
.skip:focus { left: 8px; }

.side {
  position: fixed; inset: 0 auto 0 0; width: var(--sidebar);
  display: flex; flex-direction: column;
  padding: 24px 16px;
  border-right: 1px solid var(--line);
  background: var(--sheet);
}
.brand { display: block; padding: 0 10px 24px; color: var(--ink); text-decoration: none; }
nav { display: flex; flex-direction: column; gap: 2px; }
.nav-item {
  display: flex; align-items: center; gap: 12px;
  padding: 10px 12px; border-radius: var(--radius-s);
  color: var(--ink-2); text-decoration: none; font-weight: 700; font-size: var(--t-sm);
}
.nav-item:hover { background: var(--paper); color: var(--ink); }
.nav-item.router-link-active:not(.exact),
.nav-item.exact.router-link-exact-active { background: var(--ink); color: var(--paper); }
.me { margin-top: auto; padding: 16px 10px 0; border-top: 1px solid var(--line); }
.who { display: flex; flex-direction: column; margin-bottom: 6px; overflow: hidden; }
.who span { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }

.main { margin-left: var(--sidebar); }
.topbar, .tabs { display: none; }

@media (max-width: 760px) {
  .side { display: none; }
  .main { margin-left: 0; }
  .topbar {
    display: flex; justify-content: space-between; align-items: center;
    padding: 12px 16px; border-bottom: 1px solid var(--line); background: var(--sheet);
    position: sticky; top: 0; z-index: 5;
  }
  .topbar .brand { padding: 0; }
  .tabs {
    display: grid; grid-template-columns: repeat(5, 1fr);
    position: fixed; left: 0; right: 0; bottom: 0; z-index: 5;
    background: var(--sheet); border-top: 1px solid var(--line);
    padding: 6px 4px calc(6px + env(safe-area-inset-bottom));
  }
  .tab {
    display: flex; flex-direction: column; align-items: center; gap: 2px;
    padding: 6px 2px; font-size: 0.7rem; font-weight: 700;
    color: var(--steel); text-decoration: none; border-radius: var(--radius-s);
  }
  .tab.router-link-active:not(.exact), .tab.exact.router-link-exact-active { color: var(--ink); background: var(--paper); }
}
</style>
