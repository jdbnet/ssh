<script setup lang="ts">
import { ref } from "vue";
import { api } from "@/api";

const emit = defineEmits<{ loggedIn: [] }>();

const username = ref("");
const password = ref("");
const err = ref("");
const busy = ref(false);

async function submit() {
  err.value = "";
  busy.value = true;
  try {
    await api.login(username.value.trim(), password.value);
    emit("loggedIn");
  } catch (e) {
    err.value = e instanceof Error ? e.message : "Login failed";
  } finally {
    busy.value = false;
  }
}
</script>

<template>
  <div
    class="flex min-h-screen items-center justify-center bg-surface p-6"
  >
    <div
      class="w-full max-w-md rounded-xl border border-slate-800 bg-surface-raised p-8 shadow-xl"
    >
      <h1 class="font-sans text-2xl font-semibold tracking-tight text-white">
        SSH
      </h1>
      <p class="mt-1 text-sm text-slate-400">
        Sign in to manage connections and open terminals.
      </p>
      <form class="mt-8 space-y-4" @submit.prevent="submit">
        <div>
          <label class="mb-1 block text-xs font-medium uppercase tracking-wide text-slate-500">Username</label>
          <input
            v-model="username"
            type="text"
            autocomplete="username"
            class="w-full rounded-lg border border-slate-700 bg-surface-overlay px-3 py-2 text-sm text-white outline-none ring-accent focus:border-accent focus:ring-1"
            required
          />
        </div>
        <div>
          <label class="mb-1 block text-xs font-medium uppercase tracking-wide text-slate-500">Password</label>
          <input
            v-model="password"
            type="password"
            autocomplete="current-password"
            class="w-full rounded-lg border border-slate-700 bg-surface-overlay px-3 py-2 text-sm text-white outline-none ring-accent focus:border-accent focus:ring-1"
            required
          />
        </div>
        <p v-if="err" class="text-sm text-red-400">{{ err }}</p>
        <button
          type="submit"
          :disabled="busy"
          class="w-full rounded-lg bg-accent px-4 py-2.5 text-sm font-medium text-slate-950 transition hover:bg-sky-400 disabled:opacity-50"
        >
          {{ busy ? "Signing in…" : "Sign in" }}
        </button>
      </form>
    </div>
  </div>
</template>
