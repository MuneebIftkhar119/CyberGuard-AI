<script setup>
import BrandMark from './BrandMark.vue'
</script>

<template>
  <div class="auth">
    <section class="intro">
      <BrandMark />
      <h1>Check it before you trust it.</h1>
      <p>Paste a link, a suspicious message or a password idea. CyberGuard scores the risk with
        transparent rules, then an AI tutor explains what it found and what to do next.</p>
      <ul>
        <li><strong>Link scanner</strong> spots look-alike domains, hidden redirects and @ tricks without opening the link.</li>
        <li><strong>Message check</strong> flags pressure tactics, OTP requests and fake senders — in English or Roman Urdu.</li>
        <li><strong>Password check</strong> estimates crack time and never stores what you type.</li>
      </ul>
    </section>
    <section class="panel">
      <div class="sheet card"><slot /></div>
    </section>
  </div>
</template>

<style scoped>
.auth { min-height: 100vh; display: grid; grid-template-columns: 1.1fr 1fr; }
/* Always the navy panel, in both themes; tokens are flipped locally so BrandMark reads on it. */
.intro {
  --ink: #e8edf6; --steel: #9aa8c2; --paper: #14213d;
  background: #14213d; color: #e8edf6;
  padding: 56px clamp(24px, 6vw, 80px);
  display: flex; flex-direction: column; justify-content: center; gap: 22px;
}
.intro h1 { font-size: clamp(2rem, 4vw, var(--t-3xl)); max-width: 14ch; }
.intro p { color: #b9c4d8; max-width: 52ch; }
.intro ul { list-style: none; padding: 0; margin: 8px 0 0; display: grid; gap: 14px; max-width: 52ch; }
.intro li { padding-left: 16px; border-left: 2px solid #34456a; color: #b9c4d8; font-size: var(--t-sm); }
.intro li strong { color: #e8edf6; }
.panel { display: flex; align-items: center; justify-content: center; padding: 40px 24px; }
.card { width: 100%; max-width: 420px; padding: 32px; }
@media (max-width: 860px) {
  .auth { grid-template-columns: 1fr; }
  .intro { padding: 32px 20px; gap: 14px; }
  .intro ul { display: none; }
  .panel { padding: 24px 16px 48px; align-items: flex-start; }
  .card { padding: 22px; }
}
</style>
