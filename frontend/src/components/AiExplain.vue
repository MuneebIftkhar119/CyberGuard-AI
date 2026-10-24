<script setup>
import { ref, watch } from 'vue'
import { api, errorMessage } from '../api'
import MarkdownBlock from './MarkdownBlock.vue'

const props = defineProps({
  scanId: { type: Number, default: null },
  initial: { type: String, default: '' },
  initialSource: { type: String, default: '' },
})

const text = ref(props.initial)
const source = ref(props.initialSource)
const loading = ref(false)
const error = ref('')

watch(() => props.scanId, () => {
  text.value = props.initial
  source.value = props.initialSource
  error.value = ''
})

async function explain(refresh = false) {
  if (!props.scanId) return
  loading.value = true
  error.value = ''
  try {
    const { data } = await api.post(`/scans/${props.scanId}/explain/`, { refresh })
    text.value = data.explanation
    source.value = data.source
  } catch (e) {
    error.value = errorMessage(e, 'The explanation could not be generated.')
  } finally {
    loading.value = false
  }
}
</script>

<template>
  <section class="explain" aria-live="polite">
    <div class="bar">
      <div>
        <h3>What this means</h3>
        <p class="muted small">The score above comes from local rules. The tutor only explains it.</p>
      </div>
      <button v-if="!text" class="btn btn-primary" :disabled="loading || !scanId" @click="explain()">
        <span v-if="loading" class="spinner" /> {{ loading ? 'Explaining…' : 'Explain with AI' }}
      </button>
      <button v-else-if="source === 'fallback'" class="btn btn-ghost" :disabled="loading" @click="explain(true)">
        <span v-if="loading" class="spinner" /> Try the AI again
      </button>
    </div>
    <p v-if="!scanId" class="muted small">Save this check to history to get an AI explanation.</p>
    <p v-if="error" class="notice">{{ error }}</p>
    <MarkdownBlock v-if="text" :source="text" class="body" />
  </section>
</template>

<style scoped>
.explain { border-top: 1px solid var(--line); padding-top: 20px; }
.bar { display: flex; justify-content: space-between; align-items: center; gap: 16px; flex-wrap: wrap; }
.bar p { margin-top: 2px; }
.body { margin-top: 16px; }
.notice { margin-top: 12px; }
</style>
