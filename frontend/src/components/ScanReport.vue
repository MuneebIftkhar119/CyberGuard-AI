<script setup>
import { computed } from 'vue'
import RiskRuler from './RiskRuler.vue'
import FindingsList from './FindingsList.vue'
import AiExplain from './AiExplain.vue'

const props = defineProps({
  kind: { type: String, required: true },          // password | url | phishing
  result: { type: Object, required: true },
  scanId: { type: Number, default: null },
  explanation: { type: String, default: '' },
  explanationSource: { type: String, default: '' },
})

const isPassword = computed(() => props.kind === 'password')
const findings = computed(() => props.result.findings || [])
const warnings = computed(() => findings.value.filter((f) => f.severity !== 'info'))
const crack = computed(() => {
  const c = props.result.crack_times || {}
  return [
    ['Online, rate-limited login', c.online_throttled],
    ['Offline, slow hash (bcrypt)', c.offline_slow_hash],
    ['Offline, fast hash (MD5)', c.offline_fast_hash],
  ].filter(([, v]) => v)
})
</script>

<template>
  <article class="sheet report">
    <RiskRuler v-if="isPassword" mode="strength" :score="result.strength_score"
               :label="result.strength_label" />
    <RiskRuler v-else :score="result.risk_score" />

    <p v-if="result.verdict" class="verdict">{{ result.verdict }}</p>

    <dl v-if="kind === 'url'" class="facts">
      <div><dt>Opens</dt><dd class="mono">{{ result.registered_domain || result.host || '—' }}</dd></div>
      <div><dt>Full address</dt><dd class="mono wrap">{{ result.normalized_url }}</dd></div>
    </dl>

    <dl v-if="isPassword" class="facts">
      <div><dt>Length</dt><dd>{{ result.length }} characters</dd></div>
      <div><dt>Estimated entropy</dt><dd>{{ result.entropy_bits }} bits</dd></div>
    </dl>

    <section v-if="isPassword && crack.length">
      <h3>Time to crack</h3>
      <table class="crack">
        <tbody>
          <tr v-for="[label, v] in crack" :key="label"><th scope="row">{{ label }}</th><td>{{ v.display }}</td></tr>
        </tbody>
      </table>
    </section>

    <section>
      <h3>{{ warnings.length ? `Warning signs (${warnings.length})` : 'Warning signs' }}</h3>
      <FindingsList :findings="findings" />
    </section>

    <section v-if="kind === 'phishing' && result.links?.length">
      <h3>Links in the message</h3>
      <ul class="links">
        <li v-for="l in result.links" :key="l.url">
          <span class="level" :class="'lv-' + l.risk_level">{{ l.risk_level }}</span>
          <div>
            <span class="mono wrap">{{ l.url }}</span>
            <span v-if="l.top_findings.length" class="muted small">{{ l.top_findings.join('; ') }}</span>
          </div>
        </li>
      </ul>
    </section>

    <section v-if="isPassword && result.suggestions?.length">
      <h3>How to improve it</h3>
      <ul class="tips"><li v-for="t in result.suggestions" :key="t">{{ t }}</li></ul>
    </section>

    <AiExplain :scan-id="scanId" :initial="explanation" :initial-source="explanationSource" />
  </article>
</template>

<style scoped>
.report > * + * { margin-top: 26px; }
.report h3 { font-size: var(--t-md); margin-bottom: 10px; }
.verdict { font: 700 var(--t-lg)/1.35 var(--font-display); max-width: 48ch; }
.facts { display: grid; grid-template-columns: minmax(0, 1fr) minmax(0, 2fr); gap: 16px; margin: 0; }
.facts dt { font-size: var(--t-xs); color: var(--steel); font-weight: 700; }
.facts dd { margin: 2px 0 0; }
.wrap { overflow-wrap: anywhere; }
.crack { border-collapse: collapse; width: 100%; max-width: 520px; }
.crack th, .crack td { text-align: left; padding: 8px 0; border-bottom: 1px solid var(--line); font-size: var(--t-sm); }
.crack th { font-weight: 400; color: var(--ink-2); }
.crack td { font-weight: 700; text-align: right; }
.links { list-style: none; padding: 0; margin: 0; }
.links li { display: flex; gap: 12px; align-items: flex-start; padding: 10px 0; border-bottom: 1px solid var(--line); }
.links li > div { display: flex; flex-direction: column; min-width: 0; }
.links .level { flex: none; margin-top: 2px; min-width: 64px; text-align: center; }
.tips { margin: 0; padding-left: 1.2em; }
.tips li + li { margin-top: 4px; }
@media (max-width: 760px) { .facts { grid-template-columns: 1fr; } }
</style>
