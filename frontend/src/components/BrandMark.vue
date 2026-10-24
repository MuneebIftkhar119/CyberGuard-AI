<script setup>
defineProps({ compact: Boolean })
</script>

<template>
  <span class="mark" :class="{ compact }">
    <svg viewBox="0 0 32 32" aria-hidden="true">
      <path d="M16 2 4 6.5v8.2c0 7.3 5 13.4 12 15.3 7-1.9 12-8 12-15.3V6.5L16 2Z" fill="var(--ink)" />
      <path d="M9 17.5h3.2l2.2-5 3.2 9 2.2-4h3.2" fill="none" stroke="var(--paper)" stroke-width="2.2"
            stroke-linecap="round" stroke-linejoin="round" />
    </svg>
    <span class="word">CyberGuard<span class="ai">AI</span></span>
  </span>
</template>

<style scoped>
.mark { display: inline-flex; align-items: center; gap: 10px; }
svg { width: 30px; height: 30px; flex: none; }
.word { font: 800 1.2rem/1 var(--font-display); letter-spacing: -0.02em; }
.ai { font-weight: 500; color: var(--steel); margin-left: 3px; }
.compact svg { width: 26px; height: 26px; }
.compact .word { font-size: 1.05rem; }
</style>
