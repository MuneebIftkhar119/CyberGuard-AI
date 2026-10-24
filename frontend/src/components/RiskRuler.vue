<script setup>
import { computed, onMounted, ref, watch } from 'vue'

/**
 * A measuring ruler from 0 to 100 with the score marked on it.
 * mode="risk": higher is worse.  mode="strength": higher is better (password).
 */
const props = defineProps({
  score: { type: Number, required: true },
  mode: { type: String, default: 'risk' },
  label: { type: String, default: '' },
})

const zones = computed(() =>
  props.mode === 'strength'
    ? [
        { from: 0, to: 30, cls: 'lv-critical', name: 'Very weak' },
        { from: 30, to: 45, cls: 'lv-high', name: 'Weak' },
        { from: 45, to: 65, cls: 'lv-medium', name: 'Fair' },
        { from: 65, to: 100, cls: 'lv-low', name: 'Strong' },
      ]
    : [
        { from: 0, to: 20, cls: 'lv-low', name: 'Low' },
        { from: 20, to: 45, cls: 'lv-medium', name: 'Medium' },
        { from: 45, to: 70, cls: 'lv-high', name: 'High' },
        { from: 70, to: 100, cls: 'lv-critical', name: 'Critical' },
      ],
)
const current = computed(() => zones.value.find((z) => props.score >= z.from && props.score <= z.to) || zones.value[0])
const ticks = Array.from({ length: 21 }, (_, i) => i * 5)

// The marker travels from 0 to the score once — the page's one piece of motion.
const shown = ref(0)
function settle() { requestAnimationFrame(() => { shown.value = props.score }) }
onMounted(settle)
watch(() => props.score, settle)
</script>

<template>
  <figure class="ruler" :class="current.cls" role="img"
          :aria-label="`${label || (mode === 'strength' ? 'Strength' : 'Risk')} ${score} out of 100: ${current.name}`">
    <div class="readout">
      <span class="num">{{ score }}</span>
      <span class="of">/100</span>
      <span class="level">{{ label || current.name }}</span>
    </div>
    <div class="scale">
      <div class="zones">
        <div v-for="z in zones" :key="z.from" class="zone" :class="z.cls"
             :style="{ left: z.from + '%', width: (z.to - z.from) + '%' }" />
      </div>
      <div class="ticks" aria-hidden="true">
        <span v-for="t in ticks" :key="t" class="tick" :class="{ major: t % 25 === 0 }" :style="{ left: t + '%' }" />
      </div>
      <div class="marker" :style="{ left: shown + '%' }" aria-hidden="true"><span /></div>
      <div class="labels" aria-hidden="true">
        <span v-for="t in [0, 25, 50, 75, 100]" :key="t" :style="{ left: t + '%' }">{{ t }}</span>
      </div>
    </div>
  </figure>
</template>

<style scoped>
.ruler { margin: 0; }
.readout { display: flex; align-items: baseline; gap: 4px; margin-bottom: 14px; }
.num { font: 800 3.4rem/0.9 var(--font-display); color: var(--c); letter-spacing: -0.04em; font-variant-numeric: tabular-nums; }
.of { font: 500 var(--t-lg)/1 var(--font-display); color: var(--steel); }
.readout .level { margin-left: 12px; align-self: center; }

.scale { position: relative; height: 54px; }
.zones { position: absolute; left: 0; right: 0; top: 0; height: 14px; border-radius: 3px; overflow: hidden; background: var(--paper); }
.zone { position: absolute; top: 0; bottom: 0; background: var(--c-soft); border-right: 1px solid var(--sheet); }
.ruler .zone { opacity: .9; }
.ticks { position: absolute; left: 0; right: 0; top: 14px; height: 12px; border-top: 1px solid var(--line-strong); }
.tick { position: absolute; top: 0; width: 1px; height: 5px; background: var(--line-strong); transform: translateX(-0.5px); }
.tick.major { height: 10px; background: var(--steel); }
.labels { position: absolute; left: 0; right: 0; top: 30px; font: 500 var(--t-xs)/1 var(--font-mono); color: var(--steel); }
.labels span { position: absolute; transform: translateX(-50%); }
.labels span:first-child { transform: none; }
.labels span:last-child { transform: translateX(-100%); }

.marker {
  position: absolute; top: -6px; width: 0; height: 32px;
  transition: left 900ms cubic-bezier(.2, .8, .2, 1);
}
.marker span {
  position: absolute; left: -1.5px; top: 0; width: 3px; height: 26px; background: var(--c); border-radius: 2px;
}
.marker span::after {
  content: ''; position: absolute; left: 50%; top: -7px; transform: translateX(-50%);
  border: 6px solid transparent; border-top: 7px solid var(--c); border-bottom: 0;
}
</style>
