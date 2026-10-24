<script setup>
import { reactive, ref } from 'vue'
import { api, errorMessage } from '../api'
import ScanReport from '../components/ScanReport.vue'

const form = reactive({ sender: '', reply_to: '', subject: '', body: '' })
const showHeaders = ref(false)
const result = ref(null)
const scanId = ref(null)
const loading = ref(false)
const error = ref('')

const samples = {
  'Bank email': {
    sender: 'HBL Security <alerts.hbl@gmail.com>', subject: 'Urgent: account suspended',
    body: 'Dear Customer,\n\nWe noticed unusual sign-in activity and your account has been suspended. Verify your account within 24 hours or it will be permanently closed.\n\nVerify now: http://hbl-secure.login-check.top/verify\n\nPlease confirm your password and OTP to restore access.\n\nHBL Security Team',
  },
  'Prize SMS': {
    sender: '', subject: '',
    body: 'Mubarak ho! Aap ne Rs 50,000 inaam jeeta hai. Apna OTP code bhejein aur 500 rupay processing fee JazzCash pe send karein fori. Offer aaj khatam!',
  },
  'Normal email': {
    sender: 'Ali Raza <ali@tylextech.com>', subject: 'Standup moved',
    body: 'Hi Muneeb,\n\nTomorrow’s standup is moved to 11am. Agenda is in the usual doc: https://docs.google.com/document/d/abc\n\nThanks,\nAli',
  },
}

function useSample(name) {
  Object.assign(form, { reply_to: '', ...samples[name] })
  showHeaders.value = !!form.sender
  result.value = null
}

async function analyze() {
  loading.value = true
  error.value = ''
  try {
    const { data } = await api.post('/analyze/phishing/', form)
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
      <h1>Message check</h1>
      <p>Paste an email, SMS or WhatsApp message you’re unsure about. CyberGuard looks for pressure
        tactics, requests for codes or money, fake senders and risky links.</p>
    </header>

    <form class="sheet" @submit.prevent="analyze">
      <div class="samples">
        <span class="muted small">Load an example:</span>
        <button v-for="(_, name) in samples" :key="name" type="button" class="btn-link small" @click="useSample(name)">{{ name }}</button>
      </div>

      <label class="field">
        <span>Message</span>
        <textarea v-model="form.body" class="textarea" maxlength="20000" required
                  placeholder="Paste the full message here, including any links."></textarea>
      </label>

      <button type="button" class="btn-link small toggle" :aria-expanded="showHeaders" @click="showHeaders = !showHeaders">
        {{ showHeaders ? 'Hide email details' : 'Add sender and subject (for emails)' }}
      </button>

      <div v-if="showHeaders" class="headers">
        <div class="grid-2">
          <label class="field"><span>From</span>
            <input v-model="form.sender" class="input" placeholder="PayPal <service@paypal.com>" />
          </label>
          <label class="field"><span>Reply-To <em class="muted">(optional)</em></span>
            <input v-model="form.reply_to" class="input" placeholder="Only if it differs" />
          </label>
        </div>
        <label class="field"><span>Subject</span>
          <input v-model="form.subject" class="input" />
        </label>
      </div>

      <div class="row actions">
        <button class="btn btn-primary" :disabled="loading || !form.body.trim()">
          <span v-if="loading" class="spinner" /> Check message
        </button>
      </div>
      <p v-if="error" class="notice" role="alert">{{ error }}</p>
    </form>

    <ScanReport v-if="result" :key="scanId" class="report" kind="phishing" :result="result" :scan-id="scanId" />
  </div>
</template>

<style scoped>
.samples { display: flex; flex-wrap: wrap; gap: 4px 14px; align-items: baseline; margin-bottom: 16px; }
.toggle { margin-top: 10px; }
.headers { margin-top: 14px; padding-top: 16px; border-top: 1px solid var(--line); }
.headers .grid-2 { margin-bottom: 16px; }
.field em { font-style: normal; font-weight: 400; }
.actions { margin-top: 20px; }
.notice { margin-top: 14px; }
.report { margin-top: 24px; }
</style>
