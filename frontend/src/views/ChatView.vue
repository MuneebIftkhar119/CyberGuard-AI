<script setup>
import { nextTick, onMounted, ref } from 'vue'
import { api, errorMessage } from '../api'
import MarkdownBlock from '../components/MarkdownBlock.vue'

const messages = ref([])
const draft = ref('')
const loading = ref(true)
const sending = ref(false)
const error = ref('')
const log = ref(null)
const input = ref(null)

const starters = [
  'How do I recognise a phishing email?',
  'What is two-factor authentication and should I use it?',
  'Mera WhatsApp hack ho gaya, ab kya karun?',
  'Explain SQL injection and how Django prevents it.',
]

async function scrollDown() {
  await nextTick()
  if (log.value) log.value.scrollTop = log.value.scrollHeight
}

onMounted(async () => {
  try {
    const { data } = await api.get('/chat/')
    messages.value = data
  } catch (e) {
    error.value = errorMessage(e, 'Your chat history couldn’t be loaded.')
  } finally {
    loading.value = false
    scrollDown()
  }
})

async function send(text = draft.value) {
  const message = text.trim()
  if (!message || sending.value) return
  draft.value = ''
  error.value = ''
  sending.value = true
  const pending = { id: `p${Date.now()}`, role: 'user', content: message, pending: true }
  messages.value.push(pending)
  scrollDown()
  try {
    const { data } = await api.post('/chat/', { message })
    messages.value.splice(messages.value.indexOf(pending), 1, data.user_message, data.reply)
  } catch (e) {
    messages.value.splice(messages.value.indexOf(pending), 1)
    draft.value = message
    error.value = errorMessage(e, 'The message wasn’t sent.')
  } finally {
    sending.value = false
    scrollDown()
    input.value?.focus()
  }
}

async function clearChat() {
  if (!confirm('Delete the whole conversation? This can’t be undone.')) return
  try {
    await api.delete('/chat/')
    messages.value = []
  } catch (e) {
    error.value = errorMessage(e)
  }
}

function onKey(e) {
  if (e.key === 'Enter' && !e.shiftKey && !e.isComposing) {
    e.preventDefault()
    send()
  }
}
</script>

<template>
  <div class="chat-page">
    <header class="head">
      <div>
        <h1>Ask the tutor</h1>
        <p class="muted small">Questions about staying safe online, how attacks work, or security in your code. English, Urdu or Roman Urdu.</p>
      </div>
      <button v-if="messages.length" class="btn btn-ghost" @click="clearChat">Clear conversation</button>
    </header>

    <div ref="log" class="log" aria-live="polite">
      <p v-if="loading" class="muted center">Loading conversation…</p>
      <div v-else-if="!messages.length" class="empty">
        <p>Start with a question, or pick one of these:</p>
        <div class="starters">
          <button v-for="s in starters" :key="s" class="btn btn-ghost" @click="send(s)">{{ s }}</button>
        </div>
      </div>
      <div v-for="m in messages" :key="m.id" class="msg" :class="[m.role, { pending: m.pending, fallback: m.source === 'fallback' }]">
        <MarkdownBlock v-if="m.role === 'assistant'" :source="m.content" />
        <p v-else class="user-text">{{ m.content }}</p>
      </div>
      <div v-if="sending" class="msg assistant typing" aria-label="The tutor is writing">
        <span /><span /><span />
      </div>
    </div>

    <form class="composer" @submit.prevent="send()">
      <p v-if="error" class="notice" role="alert">{{ error }}</p>
      <div class="row nowrap">
        <textarea ref="input" v-model="draft" class="textarea" rows="1" maxlength="4000"
                  placeholder="Ask a security question…" @keydown="onKey" aria-label="Message"></textarea>
        <button class="btn btn-primary" :disabled="sending || !draft.trim()">Send</button>
      </div>
      <p class="muted hint">Enter to send, Shift+Enter for a new line. Never paste real passwords or OTP codes.</p>
    </form>
  </div>
</template>

<style scoped>
.chat-page { display: flex; flex-direction: column; height: 100vh; max-width: 880px; padding: 28px 32px 20px; }
.head { display: flex; justify-content: space-between; align-items: flex-start; gap: 16px; padding-bottom: 16px; border-bottom: 1px solid var(--line); }
.head p { margin-top: 6px; max-width: 60ch; }
.log { flex: 1; overflow-y: auto; padding: 20px 2px; display: flex; flex-direction: column; gap: 14px; }
.center { text-align: center; margin-top: 40px; }
.empty { margin: auto 0; display: grid; gap: 14px; justify-items: start; }
.starters { display: flex; flex-wrap: wrap; gap: 8px; }
.starters .btn { font-weight: 400; text-align: left; }

.msg { max-width: 78%; padding: 12px 16px; border-radius: var(--radius-m); }
.msg.user { align-self: flex-end; background: var(--ink); color: var(--paper); border-bottom-right-radius: 3px; }
.msg.assistant { align-self: flex-start; background: var(--sheet); border: 1px solid var(--line); border-bottom-left-radius: 3px; }
.msg.fallback { border-style: dashed; color: var(--ink-2); }
.msg.pending { opacity: .7; }
.user-text { white-space: pre-wrap; overflow-wrap: anywhere; }

.typing { display: flex; gap: 5px; padding: 16px; }
.typing span { width: 7px; height: 7px; border-radius: 50%; background: var(--steel); animation: blink 1.2s infinite ease-in-out; }
.typing span:nth-child(2) { animation-delay: .15s; }
.typing span:nth-child(3) { animation-delay: .3s; }
@keyframes blink { 0%, 80%, 100% { opacity: .25 } 40% { opacity: 1 } }

.composer { border-top: 1px solid var(--line); padding-top: 14px; }
.composer .notice { margin-bottom: 10px; }
.nowrap { flex-wrap: nowrap; align-items: flex-end; }
.composer .textarea { min-height: 48px; max-height: 180px; resize: none; field-sizing: content; }
.hint { font-size: var(--t-xs); margin-top: 8px; }

@media (max-width: 760px) {
  .chat-page { height: calc(100dvh - 57px - 64px); padding: 16px 16px 10px; }
  .head .btn { padding: 8px 10px; }
  .head p { display: none; }
  .msg { max-width: 92%; }
}
</style>
