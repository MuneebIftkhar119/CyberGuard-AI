<script setup>
import { computed, onMounted, ref } from 'vue'
import { api, errorMessage } from '../api'
import { useAuth } from '../stores/auth'
import NavIcon from '../components/NavIcon.vue'
import ScanRow from '../components/ScanRow.vue'

const auth = useAuth()
const stats = ref(null)
const error = ref('')

onMounted(async () => {
  try {
    stats.value = (await api.get('/stats/')).data
  } catch (e) {
    error.value = errorMessage(e, 'Your overview couldn’t be loaded.')
  }
})

const tools = [
  { to: '/url', icon: 'link', title: 'Scan a link', text: 'Check where a link really goes before you tap it.' },
  { to: '/phishing', icon: 'mail', title: 'Check a message', text: 'Paste an email or SMS that feels off.' },
  { to: '/password', icon: 'key', title: 'Test a password', text: 'See how long it would survive an attack.' },
  { to: '/chat', icon: 'chat', title: 'Ask the tutor', text: 'Learn how an attack works and how to stop it.' },
]

const levels = computed(() => {
  const by = stats.value?.by_level || {}
  const total = Object.values(by).reduce((a, b) => a + b, 0)
  return ['low', 'medium', 'high', 'critical'].map((k) => ({ k, n: by[k] || 0, pct: total ? ((by[k] || 0) / total) * 100 : 0 }))
})
</script>

<template>
  <div class="page">
    <header class="page-head">
      <h1>Hi {{ auth.user?.username }}.</h1>
      <p>What do you want to check?</p>
    </header>

    <div class="tools">
      <RouterLink v-for="t in tools" :key="t.to" :to="t.to" class="tool">
        <NavIcon :name="t.icon" />
        <div>
          <strong>{{ t.title }}</strong>
          <span>{{ t.text }}</span>
        </div>
      </RouterLink>
    </div>

    <p v-if="error" class="notice" role="alert">{{ error }}</p>

    <section v-if="stats" class="summary">
      <h2>Your checks so far</h2>
      <div v-if="stats.total" class="sheet">
        <dl class="numbers">
          <div><dt>Checks run</dt><dd>{{ stats.total }}</dd></div>
          <div><dt>High or critical risk found</dt><dd class="hot">{{ stats.threats_caught }}</dd></div>
          <div><dt>Average password strength</dt><dd>{{ stats.avg_password_strength ?? '—' }}<small v-if="stats.avg_password_strength != null">/100</small></dd></div>
          <div><dt>Questions asked</dt><dd>{{ stats.chat_messages }}</dd></div>
        </dl>
        <div class="dist" role="img"
             :aria-label="levels.map(l => `${l.n} ${l.k}`).join(', ')">
          <span v-for="l in levels" :key="l.k" :class="'lv-' + l.k" :style="{ width: l.pct + '%' }" />
        </div>
        <ul class="legend">
          <li v-for="l in levels" :key="l.k" :class="'lv-' + l.k"><i />{{ l.n }} {{ l.k }}</li>
        </ul>

        <div class="recent">
          <div class="recent-head">
            <h3>Recent</h3>
            <RouterLink to="/history" class="small">See all history</RouterLink>
          </div>
          <ScanRow v-for="s in stats.recent" :key="s.id" :scan="s" />
        </div>
      </div>
      <p v-else class="muted">Nothing checked yet. Your results will collect here — start with a link or message you received recently.</p>
    </section>
  </div>
</template>

<style scoped>
.tools { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 12px; }
.tool {
  display: flex; gap: 14px; align-items: flex-start;
  padding: 18px; border: 1px solid var(--line); border-radius: var(--radius-m);
  background: var(--sheet); color: var(--ink); text-decoration: none;
}
.tool:hover { border-color: var(--ink-2); }
.tool :deep(.icon) { width: 24px; height: 24px; color: var(--signal); margin-top: 1px; }
.tool strong { display: block; font: 700 var(--t-lg)/1.2 var(--font-display); }
.tool span { display: block; color: var(--ink-2); font-size: var(--t-sm); margin-top: 3px; }

.summary { margin-top: 44px; }
.summary h2 { margin-bottom: 14px; }
.numbers { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 16px; margin: 0 0 22px; }
.numbers dt { font-size: var(--t-xs); color: var(--steel); font-weight: 700; }
.numbers dd { margin: 4px 0 0; font: 800 var(--t-2xl)/1 var(--font-display); font-variant-numeric: tabular-nums; }
.numbers dd small { font-size: var(--t-sm); color: var(--steel); font-weight: 500; }
.numbers .hot { color: var(--critical); }
.dist { display: flex; height: 10px; border-radius: 3px; overflow: hidden; background: var(--paper); }
.dist span { background: var(--c); }
.legend { display: flex; flex-wrap: wrap; gap: 6px 18px; list-style: none; padding: 0; margin: 10px 0 0; font-size: var(--t-sm); color: var(--ink-2); text-transform: capitalize; }
.legend i { display: inline-block; width: 9px; height: 9px; border-radius: 2px; background: var(--c); margin-right: 6px; }
.recent { margin-top: 28px; }
.recent-head { display: flex; justify-content: space-between; align-items: baseline; margin-bottom: 4px; }
.recent h3 { font-size: var(--t-md); }
.notice { margin-top: 20px; }
@media (max-width: 760px) {
  .tools { grid-template-columns: 1fr; }
  .numbers { grid-template-columns: 1fr 1fr; }
}
</style>
