<script setup lang="ts">
import {
  onMounted,
  onUnmounted,
  ref,
  watch,
  nextTick,
} from "vue";
import { Terminal } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import "@xterm/xterm/css/xterm.css";
import SftpPanel from "./SftpPanel.vue";

const props = defineProps<{
  hostId: number;
  visible: boolean;
}>();

const termEl = ref<HTMLElement | null>(null);
const status = ref("Connecting…");
const connId = ref<string | null>(null);

let ws: WebSocket | null = null;
let term: Terminal | null = null;
let fit: FitAddon | null = null;
let ro: ResizeObserver | null = null;

function wsUrl(hostId: number): string {
  const proto = location.protocol === "https:" ? "wss:" : "ws:";
  return `${proto}//${location.host}/ws/terminal?host_id=${hostId}`;
}

function sendResize() {
  if (!ws || ws.readyState !== WebSocket.OPEN || !term) return;
  const dims = { cols: term.cols, rows: term.rows };
  ws.send(JSON.stringify({ type: "resize", ...dims }));
}

function fitAndResize() {
  if (!fit || !term || !props.visible) return;
  try {
    fit.fit();
    sendResize();
  } catch {
    /* ignore */
  }
}

onMounted(async () => {
  await nextTick();
  if (!termEl.value) return;

  term = new Terminal({
    cursorBlink: true,
    fontFamily: "IBM Plex Mono, monospace",
    fontSize: 14,
    theme: {
      background: "#0a0e12",
      foreground: "#e2e8f0",
      cursor: "#3d9aed",
    },
  });
  fit = new FitAddon();
  term.loadAddon(fit);
  term.open(termEl.value);
  fit.fit();

  term.onData((data) => {
    if (ws && ws.readyState === WebSocket.OPEN) {
      ws.send(new TextEncoder().encode(data));
    }
  });

  term.onResize(({ cols, rows }) => {
    if (ws && ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify({ type: "resize", cols, rows }));
    }
  });

  ro = new ResizeObserver(() => fitAndResize());
  ro.observe(termEl.value);

  ws = new WebSocket(wsUrl(props.hostId));
  ws.binaryType = "arraybuffer";

  ws.onopen = () => {
    status.value = "Handshaking…";
    sendResize();
  };

  ws.onmessage = (ev) => {
    if (!term) return;
    if (typeof ev.data === "string") {
      try {
        const o = JSON.parse(ev.data) as { type?: string; conn_id?: string };
        if (o.type === "ready" && o.conn_id) {
          connId.value = o.conn_id;
          status.value = "";
          fitAndResize();
          term.focus();
          return;
        }
      } catch {
        /* fall through */
      }
      term.write(ev.data);
      return;
    }
    const u8 = new Uint8Array(ev.data as ArrayBuffer);
    term.write(new TextDecoder().decode(u8));
  };

  ws.onerror = () => {
    status.value = "WebSocket error";
  };

  ws.onclose = () => {
    if (!connId.value) {
      status.value = "Disconnected";
    } else {
      status.value = "Session ended";
    }
  };
});

onUnmounted(() => {
  ro?.disconnect();
  ro = null;
  ws?.close();
  ws = null;
  term?.dispose();
  term = null;
  fit = null;
});

watch(
  () => props.visible,
  async (v) => {
    if (v) {
      await nextTick();
      fitAndResize();
      term?.focus();
    }
  },
);
</script>

<template>
  <div class="flex h-full min-h-0 gap-0">
    <div class="relative min-h-0 min-w-0 flex-1 flex-col">
      <div
        v-if="status"
        class="absolute left-3 top-2 z-10 rounded bg-black/70 px-2 py-1 font-mono text-xs text-amber-200"
      >
        {{ status }}
      </div>
      <div
        ref="termEl"
        class="h-full min-h-[320px] rounded-lg border border-slate-800 bg-[#0a0e12] p-1"
      />
    </div>
    <div
      v-if="connId"
      class="hidden w-80 shrink-0 flex-col border-l border-slate-800 md:flex"
    >
      <SftpPanel :conn-id="connId" />
    </div>
    <div
      v-else
      class="hidden w-72 shrink-0 items-center justify-center border-l border-slate-800 bg-surface-raised text-xs text-slate-500 md:flex"
    >
      SFTP unlocks when the shell session is ready.
    </div>
  </div>
</template>
