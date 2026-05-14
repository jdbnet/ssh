<script setup lang="ts">
import { onMounted, ref } from "vue";
import { Folder } from "lucide-vue-next";
import {
  api,
  type HostRow,
  type IdentityRow,
  type FolderRow,
  type ConnectionAuditRow,
} from "@/api";
import LoginForm from "@/components/LoginForm.vue";
import TabContent from "@/components/TabContent.vue";

interface TabItem {
  id: string;
  hostId: number;
  label: string;
}

const loggedIn = ref(false);
const checking = ref(true);
const identities = ref<IdentityRow[]>([]);
const allHosts = ref<HostRow[]>([]);
const allFolders = ref<FolderRow[]>([]);
const browseFolders = ref<FolderRow[]>([]);
const browseHosts = ref<HostRow[]>([]);
const breadcrumb = ref<{ id: number; label: string }[]>([]);
const searchActive = ref(false);
const currentFolderId = ref<number | null>(null);
const searchQuery = ref("");
const tabs = ref<TabItem[]>([]);
const activeTabId = ref<string | null>(null);
const loadErr = ref("");
/** Narrow viewports: slide-over hosts panel; md+ sidebar stays visible */
const sidebarOpen = ref(true);

let searchDebounceTimer = 0;

const showIdentityForm = ref(false);
const showEditIdentity = ref(false);
const showHostForm = ref(false);
const showFolderForm = ref(false);
const showEditHost = ref(false);
const showAuditLog = ref(false);
const auditLoading = ref(false);
const auditErr = ref("");
const auditRows = ref<ConnectionAuditRow[]>([]);
const deleteIdentityErr = ref("");
const deleteIdentityErrId = ref<number | null>(null);
const newFolderLabel = ref("");
const identityForm = ref({
  label: "",
  auth_type: "password" as "password" | "publickey",
  ssh_username: "",
  password: "",
  private_key: "",
  key_passphrase: "",
});
const editIdentityForm = ref({
  id: 0,
  label: "",
  auth_type: "password" as "password" | "publickey",
  ssh_username: "",
  password: "",
  private_key: "",
  key_passphrase: "",
});
const hostForm = ref({
  label: "",
  hostname: "",
  port: 22,
  identity_id: 0 as number,
  jump_host_id: null as number | null,
});
const editHostForm = ref({
  id: 0,
  label: "",
  hostname: "",
  port: 22,
  identity_id: 0,
  folder_id: null as number | null,
  jump_host_id: null as number | null,
});

function folderOptionLabel(id: number | null): string {
  if (id == null) return "(root)";
  const byId = new Map(allFolders.value.map((f) => [f.id, f]));
  const parts: string[] = [];
  let cur: number | null | undefined = id;
  const guard = new Set<number>();
  while (cur != null && !guard.has(cur)) {
    guard.add(cur);
    const f = byId.get(cur);
    if (!f) break;
    parts.unshift(f.label);
    cur = f.parent_id;
  }
  return parts.join(" / ") || `#${id}`;
}

async function refreshBrowse() {
  try {
    const d = await api.browse(currentFolderId.value, searchQuery.value);
    browseFolders.value = d.folders;
    browseHosts.value = d.hosts;
    breadcrumb.value = d.breadcrumb;
    searchActive.value = d.search_active;
  } catch (e) {
    loadErr.value = e instanceof Error ? e.message : "Browse failed";
  }
}

function onSearchInput() {
  window.clearTimeout(searchDebounceTimer);
  searchDebounceTimer = window.setTimeout(() => {
    void refreshBrowse();
  }, 300);
}

function goToFolder(id: number | null) {
  currentFolderId.value = id;
  searchQuery.value = "";
  void refreshBrowse();
}

async function refreshData() {
  loadErr.value = "";
  try {
    identities.value = await api.listIdentities();
    allHosts.value = await api.listHosts();
    allFolders.value = await api.listFoldersFlat();
    if (!hostForm.value.identity_id && identities.value.length) {
      hostForm.value.identity_id = identities.value[0].id;
    }
    await refreshBrowse();
  } catch (e) {
    loadErr.value = e instanceof Error ? e.message : "Failed to load data";
  }
}

onMounted(async () => {
  try {
    const m = await api.me();
    loggedIn.value = m.logged_in;
    if (loggedIn.value) await refreshData();
  } catch {
    loggedIn.value = false;
  } finally {
    checking.value = false;
  }
});

async function onLoggedIn() {
  loggedIn.value = true;
  await refreshData();
}

async function logout() {
  await api.logout();
  tabs.value = [];
  activeTabId.value = null;
  loggedIn.value = false;
}

function fmtDate(ts: string | null): string {
  if (!ts) return "In progress";
  const d = new Date(ts);
  return Number.isNaN(d.getTime()) ? ts : d.toLocaleString();
}

function fmtDuration(totalSeconds: number | null): string {
  if (totalSeconds == null) return "In progress";
  const s = Math.max(0, Math.floor(totalSeconds));
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const sec = s % 60;
  if (h > 0) return `${h}h ${m}m ${sec}s`;
  if (m > 0) return `${m}m ${sec}s`;
  return `${sec}s`;
}

async function openAuditLog() {
  showAuditLog.value = true;
  auditLoading.value = true;
  auditErr.value = "";
  try {
    auditRows.value = await api.listConnectionAudit(250);
  } catch (e) {
    auditErr.value = e instanceof Error ? e.message : "Failed to load audit log";
  } finally {
    auditLoading.value = false;
  }
}

function openTab(h: HostRow) {
  const id = crypto.randomUUID();
  tabs.value.push({ id, hostId: h.id, label: h.label });
  activeTabId.value = id;
  if (window.matchMedia("(max-width: 767px)").matches) {
    sidebarOpen.value = false;
  }
}

function toggleSidebar() {
  sidebarOpen.value = !sidebarOpen.value;
}

function closeTab(id: string) {
  tabs.value = tabs.value.filter((t) => t.id !== id);
  if (activeTabId.value === id) {
    activeTabId.value = tabs.value.length ? tabs.value[tabs.value.length - 1].id : null;
  }
}

async function submitIdentity() {
  const f = identityForm.value;
  const body: Record<string, unknown> = {
    label: f.label.trim(),
    auth_type: f.auth_type,
    ssh_username: f.ssh_username.trim(),
  };
  if (f.auth_type === "password") body.password = f.password;
  else {
    body.private_key = f.private_key;
    if (f.key_passphrase) body.key_passphrase = f.key_passphrase;
  }
  await api.createIdentity(body);
  showIdentityForm.value = false;
  identityForm.value = {
    label: "",
    auth_type: "password",
    ssh_username: "",
    password: "",
    private_key: "",
    key_passphrase: "",
  };
  await refreshData();
}

async function openEditIdentity(i: IdentityRow) {
  editIdentityForm.value = {
    id: i.id,
    label: i.label,
    auth_type: i.auth_type,
    ssh_username: "",
    password: "",
    private_key: "",
    key_passphrase: "",
  };
  showEditIdentity.value = true;
}

async function submitEditIdentity() {
  const f = editIdentityForm.value;
  const body: Partial<{
    label: string;
    ssh_username: string;
    password: string;
    private_key: string;
    key_passphrase: string;
  }> = {
    label: f.label.trim(),
  };
  if (f.ssh_username.trim()) body.ssh_username = f.ssh_username.trim();
  if (f.auth_type === "password" && f.password) body.password = f.password;
  else if (f.auth_type === "publickey") {
    if (f.private_key) body.private_key = f.private_key;
    if (f.key_passphrase !== undefined) body.key_passphrase = f.key_passphrase;
  }
  await api.updateIdentity(f.id, body);
  showEditIdentity.value = false;
  editIdentityForm.value = {
    id: 0,
    label: "",
    auth_type: "password",
    ssh_username: "",
    password: "",
    private_key: "",
    key_passphrase: "",
  };
  await refreshData();
}

async function submitHost() {
  const f = hostForm.value;
  await api.createHost({
    label: f.label.trim(),
    hostname: f.hostname.trim(),
    port: Number(f.port) || 22,
    identity_id: f.identity_id,
    folder_id: currentFolderId.value,
    jump_host_id: f.jump_host_id,
  });
  showHostForm.value = false;
  hostForm.value = {
    label: "",
    hostname: "",
    port: 22,
    identity_id: hostForm.value.identity_id,
    jump_host_id: null,
  };
  await refreshData();
}

async function submitFolder() {
  const l = newFolderLabel.value.trim();
  if (!l) return;
  await api.createFolder({ label: l, parent_id: currentFolderId.value });
  newFolderLabel.value = "";
  showFolderForm.value = false;
  await refreshBrowse();
}

function openEditHost(h: HostRow) {
  editHostForm.value = {
    id: h.id,
    label: h.label,
    hostname: h.hostname,
    port: h.port,
    identity_id: h.identity_id,
    folder_id: h.folder_id,
    jump_host_id: h.jump_host_id,
  };
  showEditHost.value = true;
}

async function submitEditHost() {
  const f = editHostForm.value;
  await api.patchHost(f.id, {
    label: f.label.trim(),
    hostname: f.hostname.trim(),
    port: Number(f.port) || 22,
    identity_id: f.identity_id,
    folder_id: f.folder_id,
    jump_host_id: f.jump_host_id,
  });
  showEditHost.value = false;
  allHosts.value = await api.listHosts();
  await refreshBrowse();
}

async function deleteFolderRow(id: number) {
  if (
    !confirm(
      "Delete this folder and all subfolders? Hosts in those folders become unfiled (root).",
    )
  )
    return;
  await api.deleteFolder(id);
  if (currentFolderId.value === id) {
    currentFolderId.value = null;
  }
  await refreshData();
}

async function deleteHostRow(id: number) {
  if (!confirm("Remove this host entry?")) return;
  await api.deleteHost(id);
  allHosts.value = allHosts.value.filter((h) => h.id !== id);
  tabs.value = tabs.value.filter((t) => t.hostId !== id);
  if (!tabs.value.some((t) => t.id === activeTabId.value)) {
    activeTabId.value = tabs.value.length
      ? tabs.value[tabs.value.length - 1].id
      : null;
  }
  await refreshBrowse();
}

async function deleteIdentityRow(id: number) {
  if (!confirm("Remove this identity?")) return;
  deleteIdentityErr.value = "";
  try {
    await api.deleteIdentity(id);
    await refreshData();
  } catch (e) {
    deleteIdentityErr.value = e instanceof Error ? e.message : "Failed to delete identity";
    deleteIdentityErrId.value = id;
  }
}
</script>

<template>
  <div v-if="checking" class="flex min-h-screen items-center justify-center text-slate-500">
    Loading…
  </div>
  <LoginForm v-else-if="!loggedIn" @logged-in="onLoggedIn" />
  <div v-else class="flex h-screen min-h-0 flex-col bg-surface font-sans">
    <header
      class="flex shrink-0 items-center justify-between border-b border-slate-800 bg-surface-raised px-3 py-2 md:px-4"
    >
      <div class="flex min-w-0 items-center gap-2">
        <button
          type="button"
          class="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg text-slate-300 hover:bg-slate-800 hover:text-white"
          aria-controls="hosts-sidebar"
          :aria-expanded="sidebarOpen"
          aria-label="Toggle hosts menu"
          @click="toggleSidebar"
        >
          <span class="sr-only">Menu</span>
          <svg
            class="h-5 w-5"
            fill="none"
            stroke="currentColor"
            stroke-width="2"
            viewBox="0 0 24 24"
            aria-hidden="true"
          >
            <path
              stroke-linecap="round"
              stroke-linejoin="round"
              d="M4 6h16M4 12h16M4 18h16"
            />
          </svg>
        </button>
        <span class="truncate text-sm font-semibold text-white">JDB-NET SSH</span>
      </div>
      <div class="flex items-center gap-2">
        <button
          type="button"
          class="rounded-lg px-3 py-1.5 text-xs text-slate-400 hover:bg-slate-800 hover:text-white"
          @click="openAuditLog"
        >
          Connection audit
        </button>
        <button
          type="button"
          class="rounded-lg px-3 py-1.5 text-xs text-slate-400 hover:bg-slate-800 hover:text-white"
          @click="logout"
        >
          Sign out
        </button>
      </div>
    </header>
    <div class="relative flex min-h-0 flex-1">
      <div
        v-show="sidebarOpen"
        class="fixed inset-0 top-14 z-30 bg-black/50 md:hidden"
        aria-hidden="true"
        @click="sidebarOpen = false"
      />
      <aside
        id="hosts-sidebar"
        class="flex w-72 shrink-0 flex-col border-r border-slate-800 bg-surface-raised transition-all duration-200 ease-out max-md:fixed max-md:bottom-0 max-md:left-0 max-md:top-14 max-md:z-40 max-md:max-h-[calc(100dvh-3.5rem)] max-md:shadow-2xl md:relative"
        :class="
          sidebarOpen
            ? 'max-md:translate-x-0 md:translate-x-0 md:w-72 md:opacity-100'
            : 'max-md:-translate-x-full md:-translate-x-full md:w-0 md:opacity-0 md:border-r-0 md:overflow-hidden'
        "
      >
        <div class="border-b border-slate-800 p-3">
          <div class="text-xs font-medium uppercase tracking-wide text-slate-500">
            Hosts
          </div>
          <input
            v-model="searchQuery"
            type="search"
            placeholder="Search in this folder…"
            class="mt-2 w-full rounded-lg border border-slate-700 bg-surface-overlay px-2 py-1.5 text-xs text-white placeholder:text-slate-500 focus:border-accent focus:outline-none focus:ring-1 focus:ring-accent"
            @input="onSearchInput"
          >
          <p
            v-if="searchActive && searchQuery.trim()"
            class="mt-1 text-[10px] text-slate-500"
          >
            Matches in
            {{
              currentFolderId == null
                ? "all folders"
                : "this folder and below"
            }}
          </p>
          <nav class="mt-2 flex flex-wrap items-center gap-1 text-[11px] text-slate-400">
            <button
              type="button"
              class="rounded px-1.5 py-0.5 hover:bg-slate-800 hover:text-white"
              @click="goToFolder(null)"
            >
              Home
            </button>
            <template v-for="c in breadcrumb" :key="c.id">
              <span class="text-slate-600">/</span>
              <button
                type="button"
                class="rounded px-1.5 py-0.5 hover:bg-slate-800 hover:text-white"
                @click="goToFolder(c.id)"
              >
                {{ c.label }}
              </button>
            </template>
          </nav>
          <div class="mt-2 flex flex-wrap gap-2">
            <button
              type="button"
              class="rounded bg-accent/20 px-2 py-1 text-xs text-accent hover:bg-accent/30"
              @click="showHostForm = true"
            >
              Add host
            </button>
            <button
              type="button"
              class="rounded bg-slate-800 px-2 py-1 text-xs hover:bg-slate-700"
              @click="showFolderForm = true"
            >
              New folder
            </button>
            <button
              type="button"
              class="rounded bg-slate-800 px-2 py-1 text-xs hover:bg-slate-700"
              @click="showIdentityForm = true"
            >
              Identities
            </button>
          </div>
        </div>
        <div class="min-h-0 flex-1 overflow-auto p-2">
          <p v-if="loadErr" class="mb-2 text-xs text-red-400">{{ loadErr }}</p>
          <ul v-if="!searchActive" class="mb-3 space-y-1">
            <li
              v-for="f in browseFolders"
              :key="'f' + f.id"
              class="flex items-center justify-between gap-1 rounded-lg border border-slate-800 bg-surface-overlay px-2 py-1.5"
            >
              <button
                type="button"
                class="min-w-0 flex-1 truncate text-left text-sm text-accent hover:underline"
                @click="goToFolder(f.id)"
              >
                <span class="inline-flex items-center gap-1.5">
                  <Folder class="h-4 w-4 shrink-0" aria-hidden="true" />
                  <span>{{ f.label }}</span>
                </span>
              </button>
              <button
                type="button"
                class="shrink-0 text-[10px] text-red-400/80 hover:underline"
                @click="deleteFolderRow(f.id)"
              >
                Del
              </button>
            </li>
          </ul>
          <ul class="space-y-1">
            <li
              v-for="h in browseHosts"
              :key="'h' + h.id"
              class="rounded-lg border border-slate-800 bg-surface-overlay p-2"
            >
              <button
                type="button"
                class="w-full text-left text-sm font-medium text-white hover:text-accent"
                @click="openTab(h)"
              >
                {{ h.label }}
              </button>
              <div class="mt-0.5 truncate font-mono text-[10px] text-slate-500">
                {{ h.hostname }}:{{ h.port }} · {{ h.identity_label }}
              </div>
              <p
                v-if="h.jump_host_id"
                class="mt-0.5 truncate text-[10px] text-slate-500"
              >
                via {{ h.jump_host_label || `#${h.jump_host_id}` }}
              </p>
              <p
                v-if="searchActive"
                class="mt-0.5 truncate text-[10px] text-slate-600"
              >
                {{ folderOptionLabel(h.folder_id) }}
              </p>
              <div class="mt-1 flex gap-2">
                <button
                  type="button"
                  class="text-[10px] text-slate-400 hover:text-white hover:underline"
                  @click="openEditHost(h)"
                >
                  Edit
                </button>
                <button
                  type="button"
                  class="text-[10px] text-red-400/80 hover:underline"
                  @click="deleteHostRow(h.id)"
                >
                  Remove
                </button>
              </div>
            </li>
          </ul>
          <p
            v-if="!browseFolders.length && !browseHosts.length && !loadErr"
            class="py-4 text-center text-xs text-slate-500"
          >
            {{
              searchActive
                ? "No hosts match."
                : "Empty folder — add a host or subfolder."
            }}
          </p>
        </div>
        <div class="border-t border-slate-800 p-2">
          <div class="text-xs font-medium uppercase tracking-wide text-slate-500">
            Saved identities
          </div>
          <p v-if="deleteIdentityErr" class="mt-2 text-[11px] text-red-400">
            {{ deleteIdentityErr }}
            <button
              type="button"
              class="ml-2 underline hover:text-red-300"
              @click="deleteIdentityErr = ''"
            >
              Dismiss
            </button>
          </p>
          <ul class="mt-1 max-h-32 overflow-auto text-xs text-slate-400">
            <li
              v-for="i in identities"
              :key="i.id"
              class="flex items-center justify-between gap-1 py-0.5"
            >
              <span class="truncate">{{ i.label }} ({{ i.auth_type }})</span>
              <div class="flex gap-1">
                <button
                  type="button"
                  class="shrink-0 text-slate-400/70 hover:text-slate-300 hover:underline"
                  @click="openEditIdentity(i)"
                >
                  Edit
                </button>
                <button
                  type="button"
                  class="shrink-0 text-red-400/70 hover:underline"
                  @click="deleteIdentityRow(i.id)"
                >
                  ×
                </button>
              </div>
            </li>
          </ul>
        </div>
      </aside>
      <main class="flex min-h-0 min-w-0 flex-1 flex-col">
        <div
          v-if="!tabs.length"
          class="flex flex-1 items-center justify-center text-sm text-slate-500"
        >
          Select a host to open a tab, or add one from the sidebar.
        </div>
        <template v-else>
          <div
            class="flex shrink-0 gap-1 overflow-x-auto border-b border-slate-800 bg-surface-raised px-2 pt-2"
          >
            <button
              v-for="t in tabs"
              :key="t.id"
              type="button"
              class="flex items-center gap-2 rounded-t-lg border border-b-0 px-3 py-2 text-sm"
              :class="
                t.id === activeTabId
                  ? 'border-slate-700 bg-surface text-white'
                  : 'border-transparent bg-transparent text-slate-400 hover:text-white'
              "
              @click="activeTabId = t.id"
            >
              {{ t.label }}
              <span
                class="rounded px-1 text-slate-500 hover:bg-slate-800 hover:text-white"
                @click.stop="closeTab(t.id)"
              >×</span>
            </button>
          </div>
          <div class="min-h-0 flex-1 p-2 md:p-3">
            <div
              v-for="t in tabs"
              v-show="t.id === activeTabId"
              :key="t.id"
              class="h-full min-h-0"
            >
              <TabContent
                :host-id="t.hostId"
                :visible="t.id === activeTabId"
              />
            </div>
          </div>
        </template>
      </main>
    </div>

    <div
      v-if="showAuditLog"
      class="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4"
      @click.self="showAuditLog = false"
    >
      <div
        class="max-h-[90vh] w-full max-w-4xl overflow-auto rounded-xl border border-slate-800 bg-surface-raised p-6 shadow-xl"
      >
        <div class="flex items-center justify-between gap-3">
          <h2 class="text-lg font-semibold text-white">Connection audit</h2>
          <button
            type="button"
            class="rounded-lg px-3 py-1.5 text-xs text-slate-400 hover:bg-slate-800 hover:text-white"
            @click="showAuditLog = false"
          >
            Close
          </button>
        </div>
        <p class="mt-1 text-xs text-slate-500">
          Recent SSH sessions and how long they lasted.
        </p>
        <p v-if="auditErr" class="mt-3 text-xs text-red-400">{{ auditErr }}</p>
        <p v-else-if="auditLoading" class="mt-3 text-xs text-slate-400">
          Loading…
        </p>
        <div v-else class="mt-4 overflow-x-auto">
          <table class="min-w-full text-left text-xs">
            <thead class="text-slate-500">
              <tr class="border-b border-slate-800">
                <th class="px-2 py-2 font-medium">Host</th>
                <th class="px-2 py-2 font-medium">Address</th>
                <th class="px-2 py-2 font-medium">Started</th>
                <th class="px-2 py-2 font-medium">Ended</th>
                <th class="px-2 py-2 font-medium">Duration</th>
              </tr>
            </thead>
            <tbody>
              <tr
                v-for="r in auditRows"
                :key="r.id"
                class="border-b border-slate-900/80 text-slate-300"
              >
                <td class="px-2 py-2">
                  <div class="truncate">{{ r.host_label }}</div>
                  <div
                    v-if="r.jump_host_id"
                    class="truncate text-[10px] text-slate-500"
                  >
                    via #{{ r.jump_host_id }}
                  </div>
                </td>
                <td class="px-2 py-2 font-mono text-[11px]">
                  {{ r.hostname }}:{{ r.port }}
                </td>
                <td class="px-2 py-2">{{ fmtDate(r.started_at) }}</td>
                <td class="px-2 py-2">{{ fmtDate(r.ended_at) }}</td>
                <td class="px-2 py-2">{{ fmtDuration(r.duration_seconds) }}</td>
              </tr>
              <tr v-if="!auditRows.length">
                <td class="px-2 py-4 text-center text-slate-500" colspan="5">
                  No connection sessions yet.
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>

    <div
      v-if="showIdentityForm"
      class="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4"
      @click.self="showIdentityForm = false"
    >
      <form
        class="max-h-[90vh] w-full max-w-lg overflow-auto rounded-xl border border-slate-800 bg-surface-raised p-6 shadow-xl"
        @submit.prevent="submitIdentity"
      >
        <h2 class="text-lg font-semibold text-white">New identity</h2>
        <label class="mt-4 block text-xs uppercase text-slate-500">Label</label>
        <input
          v-model="identityForm.label"
          required
          class="mt-1 w-full rounded border border-slate-700 bg-surface-overlay px-2 py-1.5 text-sm"
        />
        <label class="mt-3 block text-xs uppercase text-slate-500">Auth</label>
        <select
          v-model="identityForm.auth_type"
          class="mt-1 w-full rounded border border-slate-700 bg-surface-overlay px-2 py-1.5 text-sm"
        >
          <option value="password">Password</option>
          <option value="publickey">SSH private key</option>
        </select>
        <label class="mt-3 block text-xs uppercase text-slate-500">SSH username</label>
        <input
          v-model="identityForm.ssh_username"
          required
          autocomplete="off"
          class="mt-1 w-full rounded border border-slate-700 bg-surface-overlay px-2 py-1.5 text-sm"
        />
        <template v-if="identityForm.auth_type === 'password'">
          <label class="mt-3 block text-xs uppercase text-slate-500">Password</label>
          <input
            v-model="identityForm.password"
            type="password"
            required
            class="mt-1 w-full rounded border border-slate-700 bg-surface-overlay px-2 py-1.5 text-sm"
          />
        </template>
        <template v-else>
          <label class="mt-3 block text-xs uppercase text-slate-500">Private key (PEM)</label>
          <textarea
            v-model="identityForm.private_key"
            required
            rows="6"
            class="mt-1 w-full rounded border border-slate-700 bg-surface-overlay px-2 py-1.5 font-mono text-xs"
          />
          <label class="mt-3 block text-xs uppercase text-slate-500">Key passphrase (optional)</label>
          <input
            v-model="identityForm.key_passphrase"
            type="password"
            class="mt-1 w-full rounded border border-slate-700 bg-surface-overlay px-2 py-1.5 text-sm"
          />
        </template>
        <div class="mt-6 flex justify-end gap-2">
          <button
            type="button"
            class="rounded-lg px-4 py-2 text-sm text-slate-400 hover:bg-slate-800"
            @click="showIdentityForm = false"
          >
            Cancel
          </button>
          <button
            type="submit"
            class="rounded-lg bg-accent px-4 py-2 text-sm font-medium text-slate-950"
          >
            Save
          </button>
        </div>
      </form>
    </div>

    <div
      v-if="showEditIdentity"
      class="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4"
      @click.self="showEditIdentity = false"
    >
      <form
        class="max-h-[90vh] w-full max-w-lg overflow-auto rounded-xl border border-slate-800 bg-surface-raised p-6 shadow-xl"
        @submit.prevent="submitEditIdentity"
      >
        <h2 class="text-lg font-semibold text-white">Edit identity</h2>
        <label class="mt-4 block text-xs uppercase text-slate-500">Label</label>
        <input
          v-model="editIdentityForm.label"
          required
          class="mt-1 w-full rounded border border-slate-700 bg-surface-overlay px-2 py-1.5 text-sm"
        />
        <label class="mt-3 block text-xs uppercase text-slate-500">Auth type</label>
        <div class="mt-1 rounded border border-slate-700 bg-surface-overlay px-2 py-1.5 text-sm text-slate-400">
          {{ editIdentityForm.auth_type }}
        </div>
        <p class="mt-1 text-[10px] text-slate-500">Auth type cannot be changed</p>
        <label class="mt-3 block text-xs uppercase text-slate-500">SSH username</label>
        <input
          v-model="editIdentityForm.ssh_username"
          placeholder="Leave empty to keep unchanged"
          autocomplete="off"
          class="mt-1 w-full rounded border border-slate-700 bg-surface-overlay px-2 py-1.5 text-sm"
        />
        <template v-if="editIdentityForm.auth_type === 'password'">
          <label class="mt-3 block text-xs uppercase text-slate-500">Password (optional)</label>
          <input
            v-model="editIdentityForm.password"
            type="password"
            placeholder="Leave empty to keep current password"
            class="mt-1 w-full rounded border border-slate-700 bg-surface-overlay px-2 py-1.5 text-sm"
          />
        </template>
        <template v-else>
          <label class="mt-3 block text-xs uppercase text-slate-500">Private key (PEM, optional)</label>
          <textarea
            v-model="editIdentityForm.private_key"
            placeholder="Leave empty to keep current key"
            rows="6"
            class="mt-1 w-full rounded border border-slate-700 bg-surface-overlay px-2 py-1.5 font-mono text-xs"
          />
          <label class="mt-3 block text-xs uppercase text-slate-500">Key passphrase (optional)</label>
          <input
            v-model="editIdentityForm.key_passphrase"
            type="password"
            placeholder="Leave empty to remove passphrase"
            class="mt-1 w-full rounded border border-slate-700 bg-surface-overlay px-2 py-1.5 text-sm"
          />
        </template>
        <div class="mt-6 flex justify-end gap-2">
          <button
            type="button"
            class="rounded-lg px-4 py-2 text-sm text-slate-400 hover:bg-slate-800"
            @click="showEditIdentity = false"
          >
            Cancel
          </button>
          <button
            type="submit"
            class="rounded-lg bg-accent px-4 py-2 text-sm font-medium text-slate-950"
          >
            Save
          </button>
        </div>
      </form>
    </div>

    <div
      v-if="showHostForm"
      class="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4"
      @click.self="showHostForm = false"
    >
      <form
        class="w-full max-w-md rounded-xl border border-slate-800 bg-surface-raised p-6 shadow-xl"
        @submit.prevent="submitHost"
      >
        <h2 class="text-lg font-semibold text-white">New host</h2>
        <p class="mt-1 text-xs text-slate-500">
          Folder: {{ folderOptionLabel(currentFolderId) }}
        </p>
        <label class="mt-4 block text-xs uppercase text-slate-500">Label</label>
        <input
          v-model="hostForm.label"
          required
          class="mt-1 w-full rounded border border-slate-700 bg-surface-overlay px-2 py-1.5 text-sm"
        />
        <label class="mt-3 block text-xs uppercase text-slate-500">Hostname or IP</label>
        <input
          v-model="hostForm.hostname"
          required
          class="mt-1 w-full rounded border border-slate-700 bg-surface-overlay px-2 py-1.5 text-sm"
        />
        <label class="mt-3 block text-xs uppercase text-slate-500">Port</label>
        <input
          v-model.number="hostForm.port"
          type="number"
          min="1"
          max="65535"
          class="mt-1 w-full rounded border border-slate-700 bg-surface-overlay px-2 py-1.5 text-sm"
        />
        <label class="mt-3 block text-xs uppercase text-slate-500">Identity</label>
        <select
          v-model.number="hostForm.identity_id"
          required
          class="mt-1 w-full rounded border border-slate-700 bg-surface-overlay px-2 py-1.5 text-sm"
        >
          <option v-for="i in identities" :key="i.id" :value="i.id">
            {{ i.label }} ({{ i.auth_type }})
          </option>
        </select>
        <label class="mt-3 block text-xs uppercase text-slate-500">Jump host (optional)</label>
        <select
          class="mt-1 w-full rounded border border-slate-700 bg-surface-overlay px-2 py-1.5 text-sm"
          :value="hostForm.jump_host_id === null ? '' : String(hostForm.jump_host_id)"
          @change="
            hostForm.jump_host_id =
              ($event.target as HTMLSelectElement).value === ''
                ? null
                : Number(($event.target as HTMLSelectElement).value)
          "
        >
          <option value="">None (direct)</option>
          <option v-for="h in allHosts" :key="h.id" :value="String(h.id)">
            {{ h.label }} ({{ h.hostname }}:{{ h.port }})
          </option>
        </select>
        <div class="mt-6 flex justify-end gap-2">
          <button
            type="button"
            class="rounded-lg px-4 py-2 text-sm text-slate-400 hover:bg-slate-800"
            @click="showHostForm = false"
          >
            Cancel
          </button>
          <button
            type="submit"
            class="rounded-lg bg-accent px-4 py-2 text-sm font-medium text-slate-950"
            :disabled="!identities.length"
          >
            Save
          </button>
        </div>
      </form>
    </div>

    <div
      v-if="showFolderForm"
      class="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4"
      @click.self="showFolderForm = false"
    >
      <form
        class="w-full max-w-sm rounded-xl border border-slate-800 bg-surface-raised p-6 shadow-xl"
        @submit.prevent="submitFolder"
      >
        <h2 class="text-lg font-semibold text-white">New folder</h2>
        <p class="mt-1 text-xs text-slate-500">
          Inside: {{ folderOptionLabel(currentFolderId) }}
        </p>
        <label class="mt-4 block text-xs uppercase text-slate-500">Name</label>
        <input
          v-model="newFolderLabel"
          required
          class="mt-1 w-full rounded border border-slate-700 bg-surface-overlay px-2 py-1.5 text-sm"
        >
        <div class="mt-6 flex justify-end gap-2">
          <button
            type="button"
            class="rounded-lg px-4 py-2 text-sm text-slate-400 hover:bg-slate-800"
            @click="showFolderForm = false"
          >
            Cancel
          </button>
          <button
            type="submit"
            class="rounded-lg bg-accent px-4 py-2 text-sm font-medium text-slate-950"
          >
            Create
          </button>
        </div>
      </form>
    </div>

    <div
      v-if="showEditHost"
      class="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4"
      @click.self="showEditHost = false"
    >
      <form
        class="max-h-[90vh] w-full max-w-md overflow-auto rounded-xl border border-slate-800 bg-surface-raised p-6 shadow-xl"
        @submit.prevent="submitEditHost"
      >
        <h2 class="text-lg font-semibold text-white">Edit host</h2>
        <label class="mt-4 block text-xs uppercase text-slate-500">Label</label>
        <input
          v-model="editHostForm.label"
          required
          class="mt-1 w-full rounded border border-slate-700 bg-surface-overlay px-2 py-1.5 text-sm"
        >
        <label class="mt-3 block text-xs uppercase text-slate-500">Hostname or IP</label>
        <input
          v-model="editHostForm.hostname"
          required
          class="mt-1 w-full rounded border border-slate-700 bg-surface-overlay px-2 py-1.5 text-sm"
        >
        <label class="mt-3 block text-xs uppercase text-slate-500">Port</label>
        <input
          v-model.number="editHostForm.port"
          type="number"
          min="1"
          max="65535"
          class="mt-1 w-full rounded border border-slate-700 bg-surface-overlay px-2 py-1.5 text-sm"
        >
        <label class="mt-3 block text-xs uppercase text-slate-500">Folder</label>
        <select
          class="mt-1 w-full rounded border border-slate-700 bg-surface-overlay px-2 py-1.5 text-sm"
          :value="editHostForm.folder_id === null ? '' : String(editHostForm.folder_id)"
          @change="
            editHostForm.folder_id =
              ($event.target as HTMLSelectElement).value === ''
                ? null
                : Number(($event.target as HTMLSelectElement).value)
          "
        >
          <option value="">(root)</option>
          <option
            v-for="f in allFolders"
            :key="f.id"
            :value="String(f.id)"
          >
            {{ folderOptionLabel(f.id) }}
          </option>
        </select>
        <label class="mt-3 block text-xs uppercase text-slate-500">Identity</label>
        <select
          v-model.number="editHostForm.identity_id"
          required
          class="mt-1 w-full rounded border border-slate-700 bg-surface-overlay px-2 py-1.5 text-sm"
        >
          <option v-for="i in identities" :key="i.id" :value="i.id">
            {{ i.label }} ({{ i.auth_type }})
          </option>
        </select>
        <label class="mt-3 block text-xs uppercase text-slate-500">Jump host (optional)</label>
        <select
          class="mt-1 w-full rounded border border-slate-700 bg-surface-overlay px-2 py-1.5 text-sm"
          :value="editHostForm.jump_host_id === null ? '' : String(editHostForm.jump_host_id)"
          @change="
            editHostForm.jump_host_id =
              ($event.target as HTMLSelectElement).value === ''
                ? null
                : Number(($event.target as HTMLSelectElement).value)
          "
        >
          <option value="">None (direct)</option>
          <option
            v-for="h in allHosts.filter((x) => x.id !== editHostForm.id)"
            :key="h.id"
            :value="String(h.id)"
          >
            {{ h.label }} ({{ h.hostname }}:{{ h.port }})
          </option>
        </select>
        <div class="mt-6 flex justify-end gap-2">
          <button
            type="button"
            class="rounded-lg px-4 py-2 text-sm text-slate-400 hover:bg-slate-800"
            @click="showEditHost = false"
          >
            Cancel
          </button>
          <button
            type="submit"
            class="rounded-lg bg-accent px-4 py-2 text-sm font-medium text-slate-950"
          >
            Save
          </button>
        </div>
      </form>
    </div>
  </div>
</template>
