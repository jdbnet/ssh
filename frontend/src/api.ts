const jsonHeaders = { "Content-Type": "application/json" };

async function handle<T>(res: Response): Promise<T> {
  if (res.status === 401) {
    throw new Error("unauthorized");
  }
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw new Error((data as { error?: string }).error || res.statusText);
  }
  return data as T;
}

function browseParams(folderId: number | null, q: string): string {
  const p = new URLSearchParams();
  if (folderId != null) p.set("folder_id", String(folderId));
  else p.set("folder_id", "root");
  const t = q.trim();
  if (t) p.set("q", t);
  return p.toString();
}

export const api = {
  async me(): Promise<{ logged_in: boolean; app_version?: string }> {
    const res = await fetch("/api/me", { credentials: "include" });
    return handle(res);
  },

  async login(username: string, password: string): Promise<void> {
    const res = await fetch("/api/login", {
      method: "POST",
      credentials: "include",
      headers: jsonHeaders,
      body: JSON.stringify({ username, password }),
    });
    await handle(res);
  },

  async logout(): Promise<void> {
    const res = await fetch("/api/logout", {
      method: "POST",
      credentials: "include",
    });
    await handle(res);
  },

  async browse(
    folderId: number | null,
    q: string,
  ): Promise<{
    breadcrumb: { id: number; label: string }[];
    folders: FolderRow[];
    hosts: HostRow[];
    search_active: boolean;
  }> {
    const res = await fetch(`/api/browse?${browseParams(folderId, q)}`, {
      credentials: "include",
    });
    return handle(res);
  },

  async listHosts(): Promise<HostRow[]> {
    const res = await fetch("/api/hosts", { credentials: "include" });
    const d = await handle<{ items: HostRow[] }>(res);
    return d.items;
  },

  async listTags(): Promise<string[]> {
    const res = await fetch("/api/tags", { credentials: "include" });
    const d = await handle<{ items: string[] }>(res);
    return d.items;
  },

  async listFoldersFlat(): Promise<FolderRow[]> {
    const res = await fetch("/api/folders", { credentials: "include" });
    const d = await handle<{ items: FolderRow[] }>(res);
    return d.items;
  },

  async createFolder(body: {
    label: string;
    parent_id?: number | null;
  }): Promise<{ id: number }> {
    const res = await fetch("/api/folders", {
      method: "POST",
      credentials: "include",
      headers: jsonHeaders,
      body: JSON.stringify(body),
    });
    return handle(res);
  },

  async deleteFolder(id: number): Promise<void> {
    const res = await fetch(`/api/folders/${id}`, {
      method: "DELETE",
      credentials: "include",
    });
    await handle(res);
  },

  async updateFolder(
    id: number,
    body: {
      label?: string;
      parent_id?: number | null;
    },
  ): Promise<void> {
    const res = await fetch(`/api/folders/${id}`, {
      method: "PATCH",
      credentials: "include",
      headers: jsonHeaders,
      body: JSON.stringify(body),
    });
    await handle(res);
  },

  async listIdentities(): Promise<IdentityRow[]> {
    const res = await fetch("/api/identities", { credentials: "include" });
    const d = await handle<{ items: IdentityRow[] }>(res);
    return d.items;
  },

  async createHost(body: Record<string, unknown>): Promise<{ id: number }> {
    const res = await fetch("/api/hosts", {
      method: "POST",
      credentials: "include",
      headers: jsonHeaders,
      body: JSON.stringify(body),
    });
    return handle(res);
  },

  async patchHost(
    id: number,
    body: Record<string, unknown>,
  ): Promise<void> {
    const res = await fetch(`/api/hosts/${id}`, {
      method: "PATCH",
      credentials: "include",
      headers: jsonHeaders,
      body: JSON.stringify(body),
    });
    await handle(res);
  },

  async deleteHost(id: number): Promise<void> {
    const res = await fetch(`/api/hosts/${id}`, {
      method: "DELETE",
      credentials: "include",
    });
    await handle(res);
  },

  async createIdentity(body: Record<string, unknown>): Promise<{ id: number }> {
    const res = await fetch("/api/identities", {
      method: "POST",
      credentials: "include",
      headers: jsonHeaders,
      body: JSON.stringify(body),
    });
    return handle(res);
  },

  async updateIdentity(
    id: number,
    body: Partial<{
      label: string;
      ssh_username: string;
      password: string;
      private_key: string;
      key_passphrase: string;
    }>,
  ): Promise<void> {
    const res = await fetch(`/api/identities/${id}`, {
      method: "PATCH",
      credentials: "include",
      headers: jsonHeaders,
      body: JSON.stringify(body),
    });
    await handle(res);
  },

  async deleteIdentity(id: number): Promise<void> {
    const res = await fetch(`/api/identities/${id}`, {
      method: "DELETE",
      credentials: "include",
    });
    await handle(res);
  },

  async listSnippets(): Promise<SnippetRow[]> {
    const res = await fetch("/api/snippets", { credentials: "include" });
    const d = await handle<{ items: SnippetRow[] }>(res);
    return d.items;
  },

  async createSnippet(body: Record<string, unknown>): Promise<{ id: number }> {
    const res = await fetch("/api/snippets", {
      method: "POST",
      credentials: "include",
      headers: jsonHeaders,
      body: JSON.stringify(body),
    });
    return handle(res);
  },

  async updateSnippet(
    id: number,
    body: Partial<{ label: string; command: string }>,
  ): Promise<void> {
    const res = await fetch(`/api/snippets/${id}`, {
      method: "PATCH",
      credentials: "include",
      headers: jsonHeaders,
      body: JSON.stringify(body),
    });
    await handle(res);
  },

  async deleteSnippet(id: number): Promise<void> {
    const res = await fetch(`/api/snippets/${id}`, {
      method: "DELETE",
      credentials: "include",
    });
    await handle(res);
  },

  async listConnectionAudit(limit = 200, daysBack?: number): Promise<ConnectionAuditRow[]> {
    const q = new URLSearchParams({ limit: String(limit) });
    if (daysBack !== undefined) {
      q.set("days_back", String(daysBack));
    }
    const res = await fetch(`/api/audit/connections?${q.toString()}`, {
      credentials: "include",
    });
    const d = await handle<{ items: ConnectionAuditRow[] }>(res);
    return d.items;
  },

  async listApiKeyScopes(): Promise<ApiKeyScopeDef[]> {
    const res = await fetch("/api/api-keys/scopes", { credentials: "include" });
    const d = await handle<{ items: ApiKeyScopeDef[] }>(res);
    return d.items;
  },

  async listApiKeys(): Promise<ApiKeyRow[]> {
    const res = await fetch("/api/api-keys", { credentials: "include" });
    const d = await handle<{ items: ApiKeyRow[] }>(res);
    return d.items;
  },

  async createApiKey(body: {
    label: string;
    scopes: string[];
    expires_at?: string | null;
  }): Promise<CreateApiKeyResponse> {
    const res = await fetch("/api/api-keys", {
      method: "POST",
      credentials: "include",
      headers: jsonHeaders,
      body: JSON.stringify(body),
    });
    return handle(res);
  },

  async deleteApiKey(id: number): Promise<void> {
    const res = await fetch(`/api/api-keys/${id}`, {
      method: "DELETE",
      credentials: "include",
    });
    await handle(res);
  },

  async sftpList(
    connId: string,
    path: string,
  ): Promise<{ path: string; entries: SftpEntry[] }> {
    const res = await fetch(`/api/sftp/${connId}/list`, {
      method: "POST",
      credentials: "include",
      headers: jsonHeaders,
      body: JSON.stringify({ path }),
    });
    return handle(res);
  },

  async sftpMkdir(connId: string, path: string): Promise<void> {
    const res = await fetch(`/api/sftp/${connId}/mkdir`, {
      method: "POST",
      credentials: "include",
      headers: jsonHeaders,
      body: JSON.stringify({ path }),
    });
    await handle(res);
  },

  async sftpRemove(connId: string, path: string): Promise<void> {
    const res = await fetch(`/api/sftp/${connId}/remove`, {
      method: "POST",
      credentials: "include",
      headers: jsonHeaders,
      body: JSON.stringify({ path }),
    });
    await handle(res);
  },

  async sftpRename(
    connId: string,
    oldPath: string,
    newPath: string,
  ): Promise<void> {
    const res = await fetch(`/api/sftp/${connId}/rename`, {
      method: "POST",
      credentials: "include",
      headers: jsonHeaders,
      body: JSON.stringify({ old_path: oldPath, new_path: newPath }),
    });
    await handle(res);
  },

  async sftpUpload(connId: string, path: string, file: File): Promise<void> {
    const fd = new FormData();
    fd.set("path", path);
    fd.set("file", file);
    const res = await fetch(`/api/sftp/${connId}/upload`, {
      method: "POST",
      credentials: "include",
      body: fd,
    });
    await handle(res);
  },

  sftpDownloadUrl(connId: string, path: string): string {
    const q = new URLSearchParams({ path });
    return `/api/sftp/${connId}/download?${q}`;
  },
};

export interface FolderRow {
  id: number;
  label: string;
  parent_id: number | null;
}

export interface HostRow {
  id: number;
  folder_id: number | null;
  label: string;
  hostname: string;
  port: number;
  identity_id: number;
  jump_host_id: number | null;
  jump_host_label?: string | null;
  identity_label: string;
  identity_auth_type: string;
  folder_label?: string | null;
  last_connected_at?: string | null;
  tags?: string[];
}

export interface IdentityRow {
  id: number;
  label: string;
  auth_type: string;
}

export interface SnippetRow {
  id: number;
  label: string;
  command: string;
}

export interface SftpEntry {
  filename: string;
  st_mode: number;
  st_size: number;
  st_mtime: number;
}

export interface ConnectionAuditRow {
  id: number;
  host_id: number | null;
  host_label: string;
  hostname: string;
  port: number;
  jump_host_id: number | null;
  started_at: string;
  ended_at: string | null;
  duration_seconds: number | null;
}

export interface ApiKeyScopeDef {
  id: string;
  label: string;
  description: string;
}

export interface ApiKeyRow {
  id: number;
  label: string;
  key_prefix: string;
  scopes: string[];
  expires_at: string | null;
  last_used_at: string | null;
  revoked_at: string | null;
  created_at: string;
  expired: boolean;
  active: boolean;
}

export interface CreateApiKeyResponse {
  id: number;
  label: string;
  key_prefix: string;
  scopes: string[];
  expires_at: string | null;
  key: string;
}
