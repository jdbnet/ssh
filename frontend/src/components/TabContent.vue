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
  showSftp: boolean;
}>();

const termEl = ref<HTMLElement | null>(null);
const status = ref("Connecting…");
const connId = ref<string | null>(null);

let ws: WebSocket | null = null;
let term: Terminal | null = null;
let fit: FitAddon | null = null;
let ro: ResizeObserver | null = null;
let visibilityHandler: (() => void) | null = null;

function wsUrl(hostId: number): string {
  const proto = location.protocol === "https:" ? "wss:" : "ws:";
  return `${proto}//${location.host}/ws/terminal?host_id=${hostId}`;
}

function sendResize() {
  if (!ws || ws.readyState !== WebSocket.OPEN || !term) return;
  const dims = { cols: term.cols, rows: term.rows };
  ws.send(JSON.stringify({ type: "resize", ...dims }));
}

function sendPing() {
  if (ws && ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify({ type: "ping" }));
  }
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

function isControlMessage(raw: string): boolean {
  try {
    const o = JSON.parse(raw) as { type?: string; conn_id?: string };
    if (o.type === "ready" && o.conn_id) {
      connId.value = o.conn_id;
      status.value = "";
      fitAndResize();
      term?.focus();
      return true;
    }
    if (o.type === "keepalive" || o.type === "pong") {
      return true;
    }
  } catch {
    /* not JSON control traffic */
  }
  return false;
}

onMounted(async () => {
  await nextTick();
  if (!termEl.value) return;

  term = new Terminal({
    cursorBlink: true,
    fontFamily: "DM Mono, ui-monospace, monospace",
    fontSize: 14,
    theme: {
      background: "#0d1117",
      foreground: "#e6edf3",
      cursor: "#1ebe8a",
      selectionBackground: "rgba(30, 190, 138, 0.3)",
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
      if (isControlMessage(ev.data)) return;
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

  visibilityHandler = () => {
    if (document.visibilityState === "visible") {
      sendPing();
      fitAndResize();
    }
  };
  document.addEventListener("visibilitychange", visibilityHandler);
});

onUnmounted(() => {
  if (visibilityHandler) {
    document.removeEventListener("visibilitychange", visibilityHandler);
    visibilityHandler = null;
  }
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
      sendPing();
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
        class="h-full min-h-[320px] rounded-lg border border-slate-800 bg-[#0d1117] p-1"
      />
    </div>
    <template v-if="showSftp">
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
    </template>
  </div>
</template>
