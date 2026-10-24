<script setup>
import { ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { api, errorMessage } from '../api'
import ScanRow from '../components/ScanRow.vue'

const route = useRoute()
const router = useRouter()
const filters = [
  { value: '', label: 'All' },
  { value: 'url', label: 'Links' },
  { value: 'phishing', label: 'Messages' },
  { value: 'password', label: 'Passwords' },
]

const kind = ref(typeof route.query.kind === 'string' ? route.query.kind : '')
const page = ref(1)
const scans = ref([])
const count = ref(0)
const hasNext = ref(false)
const loading = ref(false)
const error = ref('')

async function load(reset = true) {
  loading.value = true
  error.value = ''
  if (reset) page.value = 1
  try {
    const { data } = await api.get('/scans/', { params: { kind: kind.value || undefined, page: page.value } })
    scans.value = reset ? data.results : [...scans.value, ...data.results]
    count.value = data.count
    hasNext.value = !!data.next
  } catch (e) {
    error.value = errorMessage(e, 'History couldn’t be loaded.')
  } finally {
    loading.value = false
  }
}

watch(kind, (k) => {
  router.replace({ query: k ? { kind: k } : {} })
  load()
}, { immediate: true })

function more() { page.value += 1; load(false) }

async function clearAll() {
  if (!confirm('Delete every saved check? This can’t be undone.')) return
  try {
    await api.delete('/scans/clear/')
    load()
  } catch (e) {
    error.value = errorMessage(e)
  }
}
</script>

<template>
  <div class="page">
    <header class="page-head head">
      <div>
        <h1>History</h1>
        <p>Every check you saved, newest first. Open one to see the full report.</p>
      </div>
      <button v-if="count" class="btn btn-danger" @click="clearAll">Delete all</button>
    </header>

    <div class="filters" role="group" aria-label="Filter by type">
      <button v-for="f in filters" :key="f.value" class="btn btn-ghost" :aria-pressed="kind === f.value"
              @click="kind = f.value">{{ f.label }}</button>
    </div>

    <p v-if="error" class="notice" role="alert">{{ error }}</p>

    <div class="sheet list">
      <ScanRow v-for="s in scans" :key="s.id" :scan="s" />
      <p v-if="!loading && !scans.length" class="muted empty">
        {{ kind ? 'No checks of this type yet.' : 'No saved checks yet. Results from the tools will appear here.' }}
      </p>
      <div class="foot">
        <span class="muted small">{{ scans.length }} of {{ count }}</span>
        <button v-if="hasNext" class="btn btn-ghost" :disabled="loading" @click="more">Load more</button>
        <span v-if="loading" class="spinner" />
      </div>
    </div>
  </div>
</template>

<style scoped>
.head { display: flex; justify-content: space-between; align-items: flex-start; gap: 16px; max-width: none; }
.filters { display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 16px; }
.filters .btn[aria-pressed='true'] { background: var(--ink); color: var(--paper); border-color: var(--ink); }
.list { padding-top: 8px; }
.empty { padding: 20px 4px; }
.foot { display: flex; align-items: center; gap: 14px; justify-content: space-between; padding-top: 14px; }
.notice { margin-bottom: 16px; }
</style>
