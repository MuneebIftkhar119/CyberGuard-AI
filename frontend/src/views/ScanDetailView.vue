<script setup>
import { onMounted, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { api, errorMessage } from '../api'
import ScanReport from '../components/ScanReport.vue'

const route = useRoute()
const router = useRouter()
const scan = ref(null)
const error = ref('')
const kindLabel = { password: 'Password check', url: 'Link scan', phishing: 'Message check' }
const fmt = new Intl.DateTimeFormat(undefined, { dateStyle: 'long', timeStyle: 'short' })

onMounted(async () => {
  try {
    scan.value = (await api.get(`/scans/${route.params.id}/`)).data
  } catch (e) {
    error.value = e.response?.status === 404 ? 'This report doesn’t exist or was deleted.' : errorMessage(e)
  }
})

async function remove() {
  if (!confirm('Delete this report?')) return
  try {
    await api.delete(`/scans/${scan.value.id}/`)
    router.push('/history')
  } catch (e) {
    error.value = errorMessage(e)
  }
}
</script>

<template>
  <div class="page">
    <RouterLink to="/history" class="small">Back to history</RouterLink>
    <p v-if="error" class="notice" role="alert">{{ error }}</p>
    <template v-if="scan">
      <header class="page-head head">
        <div>
          <h1>{{ kindLabel[scan.kind] }}</h1>
          <p class="target" :class="{ mono: scan.kind === 'url' }">{{ scan.target }}</p>
          <p class="muted small">{{ fmt.format(new Date(scan.created_at)) }}</p>
        </div>
        <button class="btn btn-danger" @click="remove">Delete</button>
      </header>
      <ScanReport :kind="scan.kind" :result="scan.result" :scan-id="scan.id"
                  :explanation="scan.ai_explanation" :explanation-source="scan.ai_source" />
    </template>
  </div>
</template>

<style scoped>
.head { display: flex; justify-content: space-between; align-items: flex-start; gap: 16px; margin-top: 16px; max-width: none; }
.target { overflow-wrap: anywhere; }
.notice { margin-top: 16px; }
</style>
