<script setup>
import { computed } from 'vue'
import { marked } from 'marked'
import DOMPurify from 'dompurify'

const props = defineProps({ source: { type: String, default: '' } })
// AI output is untrusted: render Markdown, then sanitize before injecting.
const html = computed(() => {
  const raw = marked.parse(props.source || '', { breaks: true, gfm: true })
  const clean = DOMPurify.sanitize(raw, { USE_PROFILES: { html: true } })
  return clean.replace(/<a /g, '<a target="_blank" rel="noopener noreferrer" ')
})
</script>

<template>
  <div class="prose" v-html="html" />
</template>
