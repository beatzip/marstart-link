<script setup lang="ts">
import { ref, onMounted, onUnmounted } from 'vue';
import { invoke } from '@tauri-apps/api/core';

const totalTx = ref(0);
const totalRx = ref(0);
const isActive = ref(false);
let pollInterval: number | null = null;

async function pollStats() {
  try {
    const stats = await invoke<{ is_active: boolean, total_tx: number, total_rx: number }>('tunnel_get_stats');
    isActive.value = stats.is_active;
    if (stats.is_active) {
      totalTx.value = stats.total_tx;
      totalRx.value = stats.total_rx;
    }
  } catch (e) {
    console.warn("Stats not available", e);
  }
}

onMounted(() => {
  pollInterval = window.setInterval(pollStats, 1000);
});

onUnmounted(() => {
  if (pollInterval !== null) {
    clearInterval(pollInterval); // ✅ Защита от утечки памяти
  }
});
</script>

<template>
  <div v-if="isActive">
    <p>⬆️ TX: {{ (totalTx / 1024 / 1024).toFixed(2) }} MB</p>
    <p>⬇️ RX: {{ (totalRx / 1024 / 1024).toFixed(2) }} MB</p>
  </div>
  <div v-else>
    <p>Туннель отключен</p>
  </div>
</template>