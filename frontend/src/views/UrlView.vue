<script setup>
import { ref } from 'vue'
import { api, errorMessage } from '../api'
import ScanReport from '../components/ScanReport.vue'

const url = ref('')
const result = ref(null)
const scanId = ref(null)
const loading = ref(false)
const error = ref('')

const examples = [
  'http://paypa1.com/login',
  'https://secure-hbl.account-verify.xyz/signin',
  'https://www.amazon.com@evil.ru/login',
  'https://github.com',
]

async function scan(value = url.value) {
  url.value = value
  if (!value.trim()) return
  loading.value = true
  error.value = ''
  try {
    const { data } = await api.post('/analyze/url/', { url: value })
    result.value = data.result
    scanId.value = data.scan_id
  } catch (e) {
    error.value = errorMessage(e)
  } finally {
    loading.value = false
  }
}
</script>

<template>
  <div class="page">
    <header class="page-head">
      <h1>Link scanner</h1>
      <p>Paste a link from a message, QR code or ad. It’s checked with offline rules — the link is never
        opened — so it’s safe to scan even if it’s malicious.</p>
    </header>

    <form class="sheet" @submit.prevent="scan()">
      <label class="field">
        <span>Link</span>
        <div class="row nowrap">
          <input v-model="url" class="input mono" inputmode="url" autocomplete="off" spellcheck="false"
                 placeholder="https://example.com/login" maxlength="2048" />
          <button class="btn btn-primary" :disabled="loading || !url.trim()">
            <span v-if="loading" class="spinner" /> Scan link
          </button>
        </div>
        <small>Defanged links like hxxp://site[.]com work too.</small>
      </label>
      <div class="examples">
        <span class="muted small">Try:</span>
        <button v-for="e in examples" :key="e" type="button" class="btn-link small mono" @click="scan(e)">{{ e }}</button>
      </div>
      <p v-if="error" class="notice" role="alert">{{ error }}</p>
    </form>

    <ScanReport v-if="result" :key="scanId" class="report" kind="url" :result="result" :scan-id="scanId" />
  </div>
</template>

<style scoped>
.nowrap { flex-wrap: nowrap; }
.nowrap .input { flex: 1; min-width: 0; }
.examples { display: flex; flex-wrap: wrap; gap: 4px 14px; align-items: baseline; margin-top: 16px; }
.notice { margin-top: 14px; }
.report { margin-top: 24px; }
@media (max-width: 560px) { .nowrap { flex-wrap: wrap; } .nowrap .btn { width: 100%; } }
</style>
