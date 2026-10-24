<script setup>
import { reactive, ref } from 'vue'
import { useRouter } from 'vue-router'
import AuthLayout from '../components/AuthLayout.vue'
import { errorMessage } from '../api'
import { useAuth } from '../stores/auth'

const auth = useAuth()
const router = useRouter()
const form = reactive({ username: '', email: '', password: '' })
const loading = ref(false)
const error = ref('')

async function submit() {
  loading.value = true
  error.value = ''
  try {
    await auth.register({ username: form.username.trim(), email: form.email.trim(), password: form.password })
    router.replace('/')
  } catch (e) {
    error.value = errorMessage(e, 'The account could not be created.')
  } finally {
    loading.value = false
  }
}
</script>

<template>
  <AuthLayout>
    <h2>Create an account</h2>
    <p class="muted small sub">Your checks and tutor chats are saved to your account.</p>
    <form @submit.prevent="submit" novalidate>
      <label class="field"><span>Username</span>
        <input v-model="form.username" class="input" autocomplete="username" required autofocus />
      </label>
      <label class="field"><span>Email</span>
        <input v-model="form.email" class="input" type="email" autocomplete="email" required />
      </label>
      <label class="field"><span>Password</span>
        <input v-model="form.password" class="input" type="password" autocomplete="new-password" required minlength="8" />
        <small>At least 8 characters, not a common password, not only numbers.</small>
      </label>
      <p v-if="error" class="notice" role="alert">{{ error }}</p>
      <button class="btn btn-primary full" :disabled="loading || !form.username || !form.email || !form.password">
        <span v-if="loading" class="spinner" /> Create account
      </button>
    </form>
    <p class="small switch">Already have an account? <RouterLink to="/login">Log in</RouterLink></p>
  </AuthLayout>
</template>

<style scoped>
.sub { margin: 4px 0 22px; }
.notice { margin: 16px 0 0; }
.full { width: 100%; margin-top: 22px; padding: 14px; }
.switch { margin-top: 18px; color: var(--ink-2); }
</style>
