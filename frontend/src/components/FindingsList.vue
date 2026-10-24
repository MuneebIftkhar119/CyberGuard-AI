<script setup>
defineProps({
  findings: { type: Array, default: () => [] },
  emptyText: { type: String, default: 'No warning signs found.' },
})
</script>

<template>
  <ul v-if="findings.length" class="findings">
    <li v-for="f in findings" :key="f.code + f.title" :class="'lv-' + f.severity">
      <div class="head">
        <strong>{{ f.title }}</strong>
        <span class="level">{{ f.severity }}</span>
      </div>
      <p>{{ f.detail }}</p>
    </li>
  </ul>
  <p v-else class="empty">{{ emptyText }}</p>
</template>

<style scoped>
.findings { list-style: none; padding: 0; margin: 0; }
.findings li {
  border-left: 3px solid var(--c);
  padding: 10px 0 10px 14px;
}
.findings li + li { border-top: 1px solid var(--line); }
.head { display: flex; justify-content: space-between; gap: 12px; align-items: flex-start; }
.head strong { font-size: var(--t-md); }
.findings p { color: var(--ink-2); font-size: var(--t-sm); margin-top: 3px; max-width: 70ch; }
.empty { color: var(--steel); padding: 8px 0; }
</style>
