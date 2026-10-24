<script setup>
import { reactive, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import AuthLayout from '../components/AuthLayout.vue'
import { errorMessage } from '../api'
import { useAuth } from '../stores/auth'

const auth = useAuth()
const route = useRoute()
const router = useRouter()
const form = reactive({ username: '', password: '' })
const loading = ref(false)
const error = ref('')

async function submit() {
  loading.value = true
  error.value = ''
  try {
    await auth.login(form.username.trim(), form.password)
    const next = typeof route.query.next === 'string' && route.query.next.startsWith('/') ? route.query.next : '/'
    router.replace(next)
  } catch (e) {
    error.value = e.response?.status === 401
      ? 'That username and password don’t match. Check both and try again.'
      : errorMessage(e)
  } finally {
    loading.value = false
  }
}
</script>

<template>
  <AuthLayout>
    <h2>Log in</h2>
    <p class="muted small sub">Welcome back.</p>
    <p v-if="route.query.expired" class="notice calm">Your session ended. Log in again to continue.</p>
    <form @submit.prevent="submit" novalidate>
      <label class="field"><span>Username</span>
        <input v-model="form.username" class="input" autocomplete="username" required autofocus />
      </label>
      <label class="field"><span>Password</span>
        <input v-model="form.password" class="input" type="password" autocomplete="current-password" required />
      </label>
      <p v-if="error" class="notice" role="alert">{{ error }}</p>
      <button class="btn btn-primary full" :disabled="loading || !form.username || !form.password">
        <span v-if="loading" class="spinner" /> Log in
      </button>
    </form>
    <p class="small switch">New here? <RouterLink to="/register">Create an account</RouterLink></p>
  </AuthLayout>
</template>

<style scoped>
.sub { margin: 4px 0 22px; }
form { display: grid; gap: 0; }
.notice { margin: 16px 0 0; }
.full { width: 100%; margin-top: 22px; padding: 14px; }
.switch { margin-top: 18px; color: var(--ink-2); }
</style>
