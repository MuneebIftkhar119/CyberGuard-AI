<script setup>
import { onBeforeUnmount, ref, watch } from 'vue'
import { api, errorMessage } from '../api'
import ScanReport from '../components/ScanReport.vue'

const password = ref('')
const visible = ref(false)
const result = ref(null)
const scanId = ref(null)
const error = ref('')
const checking = ref(false)
const saving = ref(false)
let timer = null
let seq = 0

// Live preview while typing: analyzed with save=false so nothing is recorded.
watch(password, (value) => {
  clearTimeout(timer)
  scanId.value = null
  error.value = ''
  if (!value) { result.value = null; return }
  timer = setTimeout(() => run(value, false), 350)
})

async function run(value, save) {
  const mine = ++seq
  save ? (saving.value = true) : (checking.value = true)
  try {
    const { data } = await api.post('/analyze/password/', { password: value, save })
    if (mine !== seq) return
    result.value = data.result
    scanId.value = data.scan_id
  } catch (e) {
    if (mine === seq) error.value = errorMessage(e)
  } finally {
    if (mine === seq) { checking.value = false; saving.value = false }
  }
}

function saveCheck() { if (password.value) run(password.value, true) }
onBeforeUnmount(() => { clearTimeout(timer); password.value = '' })
</script>

<template>
  <div class="page">
    <header class="page-head">
      <h1>Password check</h1>
      <p>Type a password to see how quickly it could be cracked and why. Results update as you type.
        The password is checked on the server and never saved — history only keeps its length.</p>
    </header>

    <div class="sheet">
      <label class="field">
        <span>Password to check</span>
        <div class="pw">
          <input v-model="password" class="input" :type="visible ? 'text' : 'password'"
                 autocomplete="off" autocapitalize="off" spellcheck="false" maxlength="256"
                 placeholder="Try something like Muneeb2004!" />
          <button type="button" class="btn btn-ghost" @click="visible = !visible"
                  :aria-pressed="visible">{{ visible ? 'Hide' : 'Show' }}</button>
        </div>
        <small>Tip: don’t paste a password you actually use. Test a pattern you’re thinking about instead.</small>
      </label>
      <div class="row actions">
        <button class="btn btn-primary" :disabled="!result || saving || !!scanId" @click="saveCheck">
          <span v-if="saving" class="spinner" />
          {{ scanId ? 'Saved to history' : 'Save to history' }}
        </button>
        <span v-if="checking" class="muted small">Checking…</span>
      </div>
      <p v-if="error" class="notice" role="alert">{{ error }}</p>
    </div>

    <ScanReport v-if="result" class="report" kind="password" :result="result" :scan-id="scanId" />
  </div>
</template>

<style scoped>
.pw { display: flex; gap: 8px; }
.pw .input { font-family: var(--font-mono); }
.actions { margin-top: 18px; }
.notice { margin-top: 14px; }
.report { margin-top: 24px; }
</style>
