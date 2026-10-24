<script setup>
defineProps({ scan: { type: Object, required: true } })
const kindLabel = { password: 'Password', url: 'Link', phishing: 'Message' }
const fmt = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' })
</script>

<template>
  <RouterLink :to="`/history/${scan.id}`" class="scan-row">
    <span class="level" :class="'lv-' + scan.risk_level">{{ scan.risk_level }}</span>
    <span class="target" :class="{ mono: scan.kind === 'url' }">{{ scan.target }}</span>
    <span class="kind">{{ kindLabel[scan.kind] }}</span>
    <time class="when" :datetime="scan.created_at">{{ fmt.format(new Date(scan.created_at)) }}</time>
  </RouterLink>
</template>

<style scoped>
.scan-row {
  display: grid; grid-template-columns: 80px minmax(0, 1fr) 80px 150px; gap: 14px; align-items: center;
  padding: 12px 4px; border-bottom: 1px solid var(--line); color: var(--ink); text-decoration: none;
}
.scan-row:hover .target { text-decoration: underline; text-underline-offset: 3px; }
.level { text-align: center; }
.target { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.kind, .when { color: var(--steel); font-size: var(--t-sm); }
.when { text-align: right; }
@media (max-width: 640px) {
  .scan-row { grid-template-columns: 72px minmax(0, 1fr); row-gap: 2px; }
  .kind { grid-column: 2; font-size: var(--t-xs); }
  .when { display: none; }
}
</style>
