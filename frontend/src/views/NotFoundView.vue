<template>
  <div class="nf">
    <h1>This page doesn’t exist.</h1>
    <p class="muted">The address may be mistyped, or the page was moved.</p>
    <RouterLink to="/" class="btn btn-primary">Go to overview</RouterLink>
  </div>
</template>

<style scoped>
.nf { min-height: 100vh; display: grid; place-content: center; gap: 14px; padding: 24px; text-align: center; justify-items: center; }
</style>
