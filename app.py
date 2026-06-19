"""
SSH web client — Flask backend: auth, MariaDB, encrypted identities, WebSocket terminal, SFTP REST.
"""
from __future__ import annotations

import os

if os.getenv("GEVENT_MONKEY_PATCH", "").lower() in ("1", "true", "yes"):
    from gevent import monkey

    monkey.patch_all(thread=False, subprocess=False)

import base64
import hashlib
import hmac
import io
import json
import secrets
import logging
import posixpath
import queue
import re
import threading
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from functools import wraps
from typing import Any

import mysql.connector
from mysql.connector import pooling
import paramiko
from cryptography.fernet import Fernet, InvalidToken
from dotenv import load_dotenv
from flask import Flask, jsonify, request, session, send_from_directory, send_file, abort, Response
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import safe_join, secure_filename
from simple_websocket import ConnectionClosed, Server

load_dotenv()

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
log = logging.getLogger("ssh_web")

app = Flask(__name__, static_folder=None)
app.secret_key = os.getenv("SECRET_KEY", "dev-change-me")
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(
    days=int(os.getenv("SESSION_DAYS", "14"))
)
app.config["VERSION"] = os.getenv("VERSION", "unknown")
if os.getenv("SESSION_COOKIE_SECURE", "").lower() in ("1", "true", "yes"):
    app.config["SESSION_COOKIE_SECURE"] = True

_db_pool: pooling.MySQLConnectionPool | None = None


def get_pool() -> pooling.MySQLConnectionPool:
    global _db_pool
    if _db_pool is None:
        _db_pool = pooling.MySQLConnectionPool(
            pool_name="ssh_web_pool",
            pool_size=int(os.getenv("MYSQL_POOL_SIZE", "5")),
            host=os.getenv("MYSQL_HOST", "127.0.0.1"),
            port=int(os.getenv("MYSQL_PORT", "3306")),
            user=os.getenv("MYSQL_USER", "root"),
            password=os.getenv("MYSQL_PASSWORD", ""),
            database=os.getenv("MYSQL_DATABASE", "ssh_web"),
        )
    return _db_pool


@contextmanager
def db_cursor(dict_cursor: bool = True):
    pool = get_pool()
    conn = pool.get_connection()
    try:
        cur = conn.cursor(dictionary=dict_cursor)
        yield conn, cur
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        cur.close()
        conn.close()


def init_db():
    ddl = """
    CREATE TABLE IF NOT EXISTS ssh_identities (
      id INT AUTO_INCREMENT PRIMARY KEY,
      label VARCHAR(255) NOT NULL,
      auth_type ENUM('password','publickey') NOT NULL,
      encrypted_blob TEXT NOT NULL,
      encrypted_key_passphrase TEXT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS ssh_folders (
      id INT AUTO_INCREMENT PRIMARY KEY,
      parent_id INT NULL,
      label VARCHAR(255) NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      CONSTRAINT fk_folder_parent FOREIGN KEY (parent_id)
        REFERENCES ssh_folders(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS ssh_hosts (
      id INT AUTO_INCREMENT PRIMARY KEY,
      folder_id INT NULL,
      label VARCHAR(255) NOT NULL,
      hostname VARCHAR(512) NOT NULL,
      port INT NOT NULL DEFAULT 22,
      identity_id INT NULL,
      inline_identity_auth_type ENUM('password','publickey') NULL,
      inline_identity_encrypted_blob TEXT NULL,
      inline_identity_encrypted_key_passphrase TEXT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      CONSTRAINT fk_host_identity FOREIGN KEY (identity_id)
        REFERENCES ssh_identities(id) ON DELETE SET NULL,
      CONSTRAINT fk_host_folder FOREIGN KEY (folder_id)
        REFERENCES ssh_folders(id) ON DELETE SET NULL
    );
    CREATE TABLE IF NOT EXISTS ssh_connection_audit (
      id BIGINT AUTO_INCREMENT PRIMARY KEY,
      host_id INT NULL,
      host_label VARCHAR(255) NOT NULL,
      hostname VARCHAR(512) NOT NULL,
      port INT NOT NULL,
      jump_host_id INT NULL,
      started_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
      ended_at TIMESTAMP NULL,
      duration_seconds INT NULL,
      CONSTRAINT fk_audit_host FOREIGN KEY (host_id)
        REFERENCES ssh_hosts(id) ON DELETE SET NULL
    );
    CREATE TABLE IF NOT EXISTS api_keys (
      id INT AUTO_INCREMENT PRIMARY KEY,
      label VARCHAR(255) NOT NULL,
      key_prefix VARCHAR(24) NOT NULL,
      key_hash VARCHAR(255) NOT NULL,
      scopes JSON NOT NULL,
      expires_at TIMESTAMP NULL,
      last_used_at TIMESTAMP NULL,
      revoked_at TIMESTAMP NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      UNIQUE KEY uq_api_keys_prefix (key_prefix)
    );
    CREATE TABLE IF NOT EXISTS ssh_tags (
      id INT AUTO_INCREMENT PRIMARY KEY,
      name VARCHAR(64) NOT NULL,
      UNIQUE KEY uq_ssh_tags_name (name)
    );
    CREATE TABLE IF NOT EXISTS ssh_host_tags (
      host_id INT NOT NULL,
      tag_id INT NOT NULL,
      PRIMARY KEY (host_id, tag_id),
      CONSTRAINT fk_host_tags_host FOREIGN KEY (host_id)
        REFERENCES ssh_hosts(id) ON DELETE CASCADE,
      CONSTRAINT fk_host_tags_tag FOREIGN KEY (tag_id)
        REFERENCES ssh_tags(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS ssh_snippets (
      id INT AUTO_INCREMENT PRIMARY KEY,
      label VARCHAR(255) NOT NULL,
      command TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    );
    """
    with db_cursor() as (_, cur):
        for stmt in ddl.split(";"):
            s = stmt.strip()
            if s:
                cur.execute(s)
        _ensure_jump_host_schema(cur)
        _ensure_inline_identity_schema(cur)


def _ensure_jump_host_schema(cur) -> None:
    cur.execute(
        """
        SELECT 1
        FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = DATABASE()
          AND TABLE_NAME = 'ssh_hosts'
          AND COLUMN_NAME = 'jump_host_id'
        LIMIT 1
        """
    )
    has_col = cur.fetchone() is not None
    if not has_col:
        cur.execute("ALTER TABLE ssh_hosts ADD COLUMN jump_host_id INT NULL")
        cur.execute(
            """
            ALTER TABLE ssh_hosts
            ADD CONSTRAINT fk_host_jump_host
            FOREIGN KEY (jump_host_id) REFERENCES ssh_hosts(id) ON DELETE SET NULL
            """
        )


def _ensure_inline_identity_schema(cur) -> None:
    """Migrate existing databases to support inline (one-time) credentials."""
    # Check and modify identity_id to allow NULL
    cur.execute(
        """
        SELECT 1
        FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = DATABASE()
          AND TABLE_NAME = 'ssh_hosts'
          AND COLUMN_NAME = 'identity_id'
          AND IS_NULLABLE = 'NO'
        LIMIT 1
        """
    )
    if cur.fetchone() is not None:
        cur.execute("ALTER TABLE ssh_hosts MODIFY COLUMN identity_id INT NULL")
    
    # Check and add inline_identity_auth_type column
    cur.execute(
        """
        SELECT 1
        FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = DATABASE()
          AND TABLE_NAME = 'ssh_hosts'
          AND COLUMN_NAME = 'inline_identity_auth_type'
        LIMIT 1
        """
    )
    if cur.fetchone() is None:
        cur.execute(
            "ALTER TABLE ssh_hosts ADD COLUMN inline_identity_auth_type ENUM('password','publickey') NULL"
        )
    
    # Check and add inline_identity_encrypted_blob column
    cur.execute(
        """
        SELECT 1
        FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = DATABASE()
          AND TABLE_NAME = 'ssh_hosts'
          AND COLUMN_NAME = 'inline_identity_encrypted_blob'
        LIMIT 1
        """
    )
    if cur.fetchone() is None:
        cur.execute(
            "ALTER TABLE ssh_hosts ADD COLUMN inline_identity_encrypted_blob TEXT NULL"
        )
    
    # Check and add inline_identity_encrypted_key_passphrase column
    cur.execute(
        """
        SELECT 1
        FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = DATABASE()
          AND TABLE_NAME = 'ssh_hosts'
          AND COLUMN_NAME = 'inline_identity_encrypted_key_passphrase'
        LIMIT 1
        """
    )
    if cur.fetchone() is None:
        cur.execute(
            "ALTER TABLE ssh_hosts ADD COLUMN inline_identity_encrypted_key_passphrase TEXT NULL"
        )
    
    # Check and add last_connected_at column
    cur.execute(
        """
        SELECT 1
        FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = DATABASE()
          AND TABLE_NAME = 'ssh_hosts'
          AND COLUMN_NAME = 'last_connected_at'
        LIMIT 1
        """
    )
    if cur.fetchone() is None:
        cur.execute(
            "ALTER TABLE ssh_hosts ADD COLUMN last_connected_at TIMESTAMP NULL"
        )


def _like_escape(s: str) -> str:
    return (
        s.replace("\\", "\\\\")
        .replace("%", "\\%")
        .replace("_", "\\_")
    )


_TAG_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")


def _normalize_tag_name(raw: str) -> str | None:
    name = re.sub(r"\s+", "", raw.strip().lower())
    if not name or not _TAG_NAME_RE.match(name):
        return None
    return name


def _parse_host_tags(raw: Any) -> list[str] | None:
    if raw is None:
        return []
    if not isinstance(raw, list):
        return None
    tags: list[str] = []
    seen: set[str] = set()
    for item in raw:
        if not isinstance(item, str):
            return None
        norm = _normalize_tag_name(item)
        if norm is None:
            return None
        if norm not in seen:
            seen.add(norm)
            tags.append(norm)
    return sorted(tags)


def _parse_search_query(q: str) -> tuple[str, str]:
    if q.lower().startswith("tag:"):
        return "tag", q[4:].strip()
    return "text", q


def _host_tag_list_sql() -> str:
    return """
            (SELECT GROUP_CONCAT(t.name ORDER BY t.name SEPARATOR ',')
             FROM ssh_host_tags ht
             INNER JOIN ssh_tags t ON t.id = ht.tag_id
             WHERE ht.host_id = h.id) AS tag_list
            """


def _serialize_host_row(row: dict[str, Any]) -> dict[str, Any]:
    out = dict(row)
    tag_list = out.pop("tag_list", None)
    out["tags"] = tag_list.split(",") if tag_list else []
    return out


def _serialize_host_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [_serialize_host_row(r) for r in rows]


def _tag_id(cur, name: str) -> int:
    cur.execute(
        "INSERT INTO ssh_tags (name) VALUES (%s) ON DUPLICATE KEY UPDATE name = name",
        (name,),
    )
    cur.execute("SELECT id FROM ssh_tags WHERE name = %s", (name,))
    row = cur.fetchone()
    assert row is not None
    return int(row["id"])


def _set_host_tags(cur, host_id: int, tags: list[str]) -> None:
    cur.execute("DELETE FROM ssh_host_tags WHERE host_id = %s", (host_id,))
    for name in tags:
        cur.execute(
            "INSERT INTO ssh_host_tags (host_id, tag_id) VALUES (%s, %s)",
            (host_id, _tag_id(cur, name)),
        )


def _host_tag_filter_sql(tag_name: str) -> tuple[str, tuple[Any, ...]]:
    return (
        "h.id IN ("
        "SELECT ht.host_id FROM ssh_host_tags ht "
        "INNER JOIN ssh_tags t ON t.id = ht.tag_id "
        "WHERE t.name = %s"
        ")",
        (tag_name,),
    )


def _folder_subtree_ids(cur, root_id: int) -> list[int]:
    cur.execute(
        """
        WITH RECURSIVE sub AS (
          SELECT id FROM ssh_folders WHERE id = %s
          UNION ALL
          SELECT f.id FROM ssh_folders f INNER JOIN sub ON f.parent_id = sub.id
        )
        SELECT id FROM sub
        """,
        (root_id,),
    )
    return [r["id"] for r in cur.fetchall()]


def _folder_breadcrumb_rows(cur, folder_id: int) -> list[dict[str, Any]]:
    cur.execute(
        """
        WITH RECURSIVE up AS (
          SELECT id, parent_id, label FROM ssh_folders WHERE id = %s
          UNION ALL
          SELECT f.id, f.parent_id, f.label
          FROM ssh_folders f INNER JOIN up ON f.id = up.parent_id
        )
        SELECT id, label FROM up
        """,
        (folder_id,),
    )
    rows = cur.fetchall()
    return list(reversed(rows))


def _fernet() -> Fernet:
    raw = os.getenv("CREDENTIALS_ENCRYPTION_KEY", "").encode("utf-8")
    if not raw:
        raise RuntimeError("CREDENTIALS_ENCRYPTION_KEY is not set")
    key = base64.urlsafe_b64encode(hashlib.sha256(raw).digest())
    return Fernet(key)


def encrypt_secret(plaintext: str) -> str:
    return _fernet().encrypt(plaintext.encode("utf-8")).decode("ascii")


def decrypt_secret(token: str) -> str:
    try:
        return _fernet().decrypt(token.encode("ascii")).decode("utf-8")
    except InvalidToken as e:
        raise ValueError("decryption failed") from e


def _web_login_ok(username: str, password: str) -> bool:
    u = os.getenv("WEBAPP_USERNAME", "")
    if not u or username != u:
        return False
    pw_hash = os.getenv("WEBAPP_PASSWORD_HASH", "").strip()
    if pw_hash:
        return check_password_hash(pw_hash, password)
    expected = os.getenv("WEBAPP_PASSWORD", "")
    if not expected:
        return False
    pa = password.encode("utf-8")
    pb = expected.encode("utf-8")
    if len(pa) != len(pb):
        return False
    return hmac.compare_digest(pa, pb)


def require_login(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if not session.get("logged_in"):
            return jsonify({"error": "unauthorized"}), 401
        return fn(*args, **kwargs)

    return wrapped


VALID_API_SCOPES = frozenset(
    {
        "read:hosts",
        "write:hosts",
        "read:audit",
        "terminal:connect",
        "sftp:manage",
    }
)


def _parse_api_key_scopes(raw: Any) -> set[str]:
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except json.JSONDecodeError:
            return set()
    if not isinstance(raw, list):
        return set()
    return {s for s in raw if isinstance(s, str) and s in VALID_API_SCOPES}


def _bearer_token_from_request() -> str | None:
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        token = auth[7:].strip()
        return token or None
    return None


def _authenticate_api_key(token: str) -> dict[str, Any] | None:
    if not token.startswith("ssh_k_"):
        return None
    parts = token.split("_")
    if len(parts) < 4 or parts[0] != "ssh" or parts[1] != "k" or len(parts[2]) != 8:
        return None
    key_prefix = f"ssh_k_{parts[2]}"
    with db_cursor() as (_, cur):
        cur.execute(
            """
            SELECT id, key_hash, scopes, expires_at, revoked_at
            FROM api_keys
            WHERE key_prefix = %s
            LIMIT 1
            """,
            (key_prefix,),
        )
        row = cur.fetchone()
    if not row or row.get("revoked_at"):
        return None
    expires_at = row.get("expires_at")
    if expires_at is not None and expires_at <= _utcnow():
        return None
    if not check_password_hash(row["key_hash"], token):
        return None
    scopes = _parse_api_key_scopes(row.get("scopes"))
    if not scopes:
        return None
    with db_cursor() as (_, cur):
        cur.execute(
            "UPDATE api_keys SET last_used_at = CURRENT_TIMESTAMP WHERE id = %s",
            (row["id"],),
        )
    return {"type": "api_key", "id": row["id"], "scopes": scopes}


def _utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def resolve_auth() -> dict[str, Any] | None:
    if session.get("logged_in"):
        return {"type": "session", "scopes": set(VALID_API_SCOPES)}
    token = _bearer_token_from_request()
    if token:
        return _authenticate_api_key(token)
    return None


def _ws_resolve_auth() -> dict[str, Any] | None:
    if session.get("logged_in"):
        return {"type": "session", "scopes": set(VALID_API_SCOPES)}
    token = (request.args.get("token") or "").strip()
    if not token:
        token = _bearer_token_from_request() or ""
    if token:
        return _authenticate_api_key(token)
    return None


def _auth_has_scopes(auth: dict[str, Any], required: tuple[str, ...]) -> bool:
    if not required:
        return True
    scopes = auth.get("scopes") or set()
    return all(scope in scopes for scope in required)


def require_auth(*required_scopes: str):
    def decorator(fn):
        @wraps(fn)
        def wrapped(*args, **kwargs):
            auth = resolve_auth()
            if not auth:
                return jsonify({"error": "unauthorized"}), 401
            if not _auth_has_scopes(auth, required_scopes):
                return jsonify({"error": "forbidden"}), 403
            return fn(*args, **kwargs)

        return wrapped

    return decorator


def _validate_api_key_scopes(raw: Any) -> list[str] | None:
    if not isinstance(raw, list):
        return None
    scopes = sorted(_parse_api_key_scopes(raw))
    if not scopes:
        return None
    return scopes


def _generate_api_key_material() -> tuple[str, str, str]:
    key_prefix = f"ssh_k_{secrets.token_hex(4)}"
    full_key = f"{key_prefix}_{secrets.token_urlsafe(32)}"
    return full_key, key_prefix, generate_password_hash(full_key)


def _parse_optional_expires_at(raw: Any) -> Any:
    if raw is None or raw == "":
        return None
    if not isinstance(raw, str):
        return "invalid"
    text = raw.strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return "invalid"
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


_registry_lock = threading.Lock()
_connections: dict[str, dict[str, Any]] = {}


def _conn_put(cid: str, data: dict[str, Any]) -> None:
    with _registry_lock:
        _connections[cid] = data


def _conn_get(cid: str) -> dict[str, Any] | None:
    with _registry_lock:
        return _connections.get(cid)


def _conn_pop(cid: str) -> dict[str, Any] | None:
    with _registry_lock:
        return _connections.pop(cid, None)


def _close_ssh_entry(entry: dict[str, Any]) -> None:
    ch = entry.get("channel")
    if ch is not None:
        try:
            ch.close()
        except Exception:
            pass
    sf = entry.get("sftp")
    if sf is not None:
        try:
            sf.close()
        except Exception:
            pass
    cl = entry.get("client")
    if cl is not None:
        try:
            cl.close()
        except Exception:
            pass
    for jump_client in entry.get("jump_clients") or []:
        try:
            jump_client.close()
        except Exception:
            pass


MAX_CONCURRENT_SSH = int(os.getenv("MAX_CONCURRENT_SSH", "32"))
SSH_KEEPALIVE_INTERVAL = int(os.getenv("SSH_KEEPALIVE_INTERVAL", "15"))
WS_KEEPALIVE_INTERVAL = int(os.getenv("WS_KEEPALIVE_INTERVAL", "25"))


def _apply_ssh_keepalive(client: paramiko.SSHClient) -> None:
    if SSH_KEEPALIVE_INTERVAL <= 0:
        return
    transport = client.get_transport()
    if transport is not None:
        transport.set_keepalive(SSH_KEEPALIVE_INTERVAL)


def _ssh_transports_alive(
    client: paramiko.SSHClient, jump_clients: list[paramiko.SSHClient] | None
) -> bool:
    for ssh_client in (client, *(jump_clients or [])):
        transport = ssh_client.get_transport()
        if transport is None or not transport.is_active():
            return False
    return True


class GeventWsAppResponse(Response):
    def __call__(self, environ, start_response):
        return []


class GeventTerminalSocket:
    def __init__(self, gw):
        self._gw = gw

    def send(self, data) -> None:
        from geventwebsocket import WebSocketError

        try:
            if isinstance(data, bytes):
                self._gw.send(data, binary=True)
            else:
                self._gw.send(str(data), binary=False)
        except WebSocketError:
            raise

    def receive(self, timeout=None):
        import gevent
        from geventwebsocket import WebSocketError

        if self._gw.closed:
            return None
        if timeout is None:
            try:
                return self._gw.receive()
            except WebSocketError:
                return None
        t = gevent.Timeout(timeout)
        t.start()
        try:
            return self._gw.receive()
        except gevent.Timeout:
            return None
        except WebSocketError:
            return None
        finally:
            try:
                t.close()
            except Exception:
                pass

    def close(self, reason=None, message=None) -> None:
        if self._gw.closed:
            return
        code = int(reason) if reason is not None else 1000
        msg = message or ""
        if isinstance(msg, str):
            msg = msg.encode("utf-8", errors="replace")
        try:
            self._gw.close(code, msg)
        except Exception:
            pass


def _open_terminal_socket():
    gw = request.environ.get("wsgi.websocket")
    if gw is not None:
        return GeventTerminalSocket(gw), True
    return Server(request.environ, **app.config.get("SOCK_SERVER_OPTIONS", {})), False


def _registry_count() -> int:
    with _registry_lock:
        return len(_connections)


def _connect_paramiko(host_row: dict, sock=None) -> tuple[paramiko.SSHClient, paramiko.Channel]:
    # Prefer inline identity if available, otherwise use saved identity
    if host_row.get("inline_identity_encrypted_blob"):
        # Use inline credentials
        auth_type = host_row["inline_identity_auth_type"]
        encrypted_blob = host_row["inline_identity_encrypted_blob"]
        encrypted_key_passphrase = host_row.get("inline_identity_encrypted_key_passphrase")
    else:
        # Use saved identity
        if not host_row.get("encrypted_blob"):
            raise ValueError("host has no identity configured")
        auth_type = host_row["auth_type"]
        encrypted_blob = host_row["encrypted_blob"]
        encrypted_key_passphrase = host_row.get("encrypted_key_passphrase")
    
    payload = decrypt_secret(encrypted_blob)
    data = json.loads(payload)
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    hostname = host_row["hostname"]
    port = int(host_row["port"] or 22)
    username_ssh = data.get("ssh_username") or data.get("username")
    if not username_ssh:
        raise ValueError("identity payload missing ssh_username")

    if auth_type == "password":
        pwd = data.get("password")
        if not pwd:
            raise ValueError("missing password in identity")
        client.connect(
            hostname,
            port=port,
            username=username_ssh,
            password=pwd,
            sock=sock,
            timeout=30,
            banner_timeout=30,
            auth_timeout=30,
        )
    else:
        key_str = data.get("private_key")
        if not key_str:
            raise ValueError("missing private_key in identity")
        pkey = None
        key_pass = None
        if encrypted_key_passphrase:
            key_pass = decrypt_secret(encrypted_key_passphrase) or None
        last_err: Exception | None = None
        key_classes: list[type] = [
            paramiko.RSAKey,
            paramiko.Ed25519Key,
            paramiko.ECDSAKey,
        ]
        _dss = getattr(paramiko, "DSSKey", None)
        if _dss is not None:
            key_classes.append(_dss)
        for KeyCls in key_classes:
            f = io.StringIO(key_str)
            try:
                pkey = KeyCls.from_private_key(f, password=key_pass)
                break
            except Exception as e:
                last_err = e
                continue
        if pkey is None:
            raise ValueError("could not load private key") from last_err
        client.connect(
            hostname,
            port=port,
            username=username_ssh,
            pkey=pkey,
            sock=sock,
            timeout=30,
            banner_timeout=30,
            auth_timeout=30,
        )

    if SSH_KEEPALIVE_INTERVAL > 0:
        _apply_ssh_keepalive(client)

    chan = client.invoke_shell(term="xterm-256color", width=120, height=40)
    chan.setblocking(True)
    return client, chan


def _load_host_connect_row(cur, host_id: int) -> dict[str, Any] | None:
    cur.execute(
        """
        SELECT h.id, h.label, h.hostname, h.port, h.identity_id, h.jump_host_id,
               h.inline_identity_auth_type, h.inline_identity_encrypted_blob, h.inline_identity_encrypted_key_passphrase,
               i.auth_type, i.encrypted_blob, i.encrypted_key_passphrase
        FROM ssh_hosts h
        LEFT JOIN ssh_identities i ON i.id = h.identity_id
        WHERE h.id = %s
        """,
        (host_id,),
    )
    return cur.fetchone()


def _connect_with_jump_chain(host_id: int) -> tuple[paramiko.SSHClient, paramiko.Channel, list[paramiko.SSHClient], dict[str, Any]]:
    with db_cursor() as (_, cur):
        cur.execute("SELECT id FROM ssh_hosts WHERE id = %s", (host_id,))
        if not cur.fetchone():
            raise ValueError("host not found")

        chain: list[dict[str, Any]] = []
        seen: set[int] = set()
        current = host_id
        while True:
            if current in seen:
                raise ValueError("jump host cycle detected")
            seen.add(current)
            row = _load_host_connect_row(cur, current)
            if not row:
                raise ValueError("host not found")
            chain.append(row)
            jump_id = row.get("jump_host_id")
            if jump_id is None:
                break
            current = int(jump_id)

    chain.reverse()
    jump_clients: list[paramiko.SSHClient] = []
    upstream_sock = None
    for idx, row in enumerate(chain):
        is_target = idx == len(chain) - 1
        client, shell_chan = _connect_paramiko(row, sock=upstream_sock)
        if is_target:
            return client, shell_chan, jump_clients, row
        jump_clients.append(client)
        upstream_sock = client.get_transport().open_channel(
            "direct-tcpip",
            (chain[idx + 1]["hostname"], int(chain[idx + 1]["port"] or 22)),
            ("127.0.0.1", 0),
        )

    raise RuntimeError("failed to build jump chain")


def _insert_connection_audit(host_row: dict[str, Any]) -> int | None:
    try:
        with db_cursor() as (_, cur):
            cur.execute(
                """
                INSERT INTO ssh_connection_audit (host_id, host_label, hostname, port, jump_host_id)
                VALUES (%s, %s, %s, %s, %s)
                """,
                (
                    int(host_row["id"]),
                    str(host_row["label"]),
                    str(host_row["hostname"]),
                    int(host_row["port"] or 22),
                    host_row.get("jump_host_id"),
                ),
            )
            audit_id = int(cur.lastrowid)
            # Update the host's last_connected_at timestamp
            cur.execute(
                "UPDATE ssh_hosts SET last_connected_at = CURRENT_TIMESTAMP WHERE id = %s",
                (int(host_row["id"]),),
            )
            return audit_id
    except Exception:
        log.exception("failed to insert connection audit row")
        return None


def _finish_connection_audit(audit_id: int, started_monotonic: float) -> None:
    duration = max(0, int(time.monotonic() - started_monotonic))
    try:
        with db_cursor() as (_, cur):
            cur.execute(
                """
                UPDATE ssh_connection_audit
                SET ended_at = CURRENT_TIMESTAMP, duration_seconds = %s
                WHERE id = %s
                """,
                (duration, audit_id),
            )
    except Exception:
        log.exception("failed to finalize connection audit row")


def validate_remote_path(path: str) -> str:
    if not path or not isinstance(path, str):
        raise ValueError("invalid path")
    norm = posixpath.normpath(path)
    if norm in ("..", ".") or norm.startswith("../"):
        raise ValueError("invalid path")
    return norm


def _get_sftp(entry: dict[str, Any]) -> paramiko.SFTPClient:
    with entry["lock"]:
        if entry.get("sftp") is None:
            entry["sftp"] = entry["client"].open_sftp()
        return entry["sftp"]


@app.route("/api/login", methods=["POST"])
def api_login():
    body = request.get_json(silent=True) or {}
    username = (body.get("username") or "").strip()
    password = body.get("password") or ""
    if _web_login_ok(username, password):
        session["logged_in"] = True
        session.permanent = bool(os.getenv("SESSION_PERMANENT", "1").lower() in ("1", "true", "yes"))
        return jsonify({"ok": True})
    return jsonify({"ok": False, "error": "invalid credentials"}), 401


@app.route("/api/logout", methods=["POST"])
def api_logout():
    session.pop("logged_in", None)
    return jsonify({"ok": True})


@app.route("/api/me", methods=["GET"])
def api_me():
    version = app.config.get("VERSION", "unknown")
    if session.get("logged_in"):
        return jsonify({"logged_in": True, "app_version": version})
    return jsonify({"logged_in": False, "app_version": version})


@app.route("/api/identities", methods=["GET"])
@require_auth("read:hosts")
def list_identities():
    with db_cursor() as (_, cur):
        cur.execute(
            "SELECT id, label, auth_type, created_at, updated_at FROM ssh_identities ORDER BY label"
        )
        rows = cur.fetchall()
    return jsonify({"items": rows})


@app.route("/api/identities", methods=["POST"])
@require_auth("write:hosts")
def create_identity():
    body = request.get_json(silent=True) or {}
    label = (body.get("label") or "").strip()
    auth_type = body.get("auth_type")
    ssh_username = (body.get("ssh_username") or "").strip()
    if not label or auth_type not in ("password", "publickey") or not ssh_username:
        return jsonify({"error": "label, auth_type, ssh_username required"}), 400

    key_pass_plain = body.get("key_passphrase")

    if auth_type == "password":
        password = body.get("password")
        if not password:
            return jsonify({"error": "password required"}), 400
        payload = json.dumps(
            {"ssh_username": ssh_username, "password": password}
        )
        enc_key_pass = None
    else:
        private_key = body.get("private_key")
        if not private_key or not isinstance(private_key, str):
            return jsonify({"error": "private_key required"}), 400
        inner = {"ssh_username": ssh_username, "private_key": private_key}
        payload = json.dumps(inner)
        enc_key_pass = (
            encrypt_secret(key_pass_plain) if key_pass_plain else None
        )

    blob = encrypt_secret(payload)
    with db_cursor() as (_, cur):
        cur.execute(
            """
            INSERT INTO ssh_identities (label, auth_type, encrypted_blob, encrypted_key_passphrase)
            VALUES (%s, %s, %s, %s)
            """,
            (label, auth_type, blob, enc_key_pass),
        )
        new_id = cur.lastrowid
    return jsonify({"id": new_id}), 201


@app.route("/api/identities/<int:iid>", methods=["PATCH"])
@require_auth("write:hosts")
def update_identity(iid: int):
    body = request.get_json(silent=True) or {}
    with db_cursor() as (_, cur):
        cur.execute(
            "SELECT id, label, auth_type, encrypted_blob, encrypted_key_passphrase FROM ssh_identities WHERE id = %s",
            (iid,),
        )
        row = cur.fetchone()
    if not row:
        return jsonify({"error": "not found"}), 404

    label = body.get("label")
    if label is not None:
        label = str(label).strip()
    ssh_username = body.get("ssh_username")
    if ssh_username is not None:
        ssh_username = str(ssh_username).strip()

    try:
        plain = decrypt_secret(row["encrypted_blob"])
        data = json.loads(plain)
    except Exception:
        return jsonify({"error": "cannot update corrupted identity"}), 500

    if ssh_username:
        data["ssh_username"] = ssh_username

    new_blob = row["encrypted_blob"]
    new_key_pass = row["encrypted_key_passphrase"]

    if row["auth_type"] == "password":
        if body.get("password"):
            data["password"] = body["password"]
            new_blob = encrypt_secret(json.dumps(data))
    else:
        if body.get("private_key"):
            data["private_key"] = body["private_key"]
            new_blob = encrypt_secret(json.dumps(data))
        if "key_passphrase" in body:
            kp = body.get("key_passphrase")
            new_key_pass = encrypt_secret(kp) if kp else None

    sets = []
    args: list[Any] = []
    if label:
        sets.append("label = %s")
        args.append(label)
    if new_blob != row["encrypted_blob"]:
        sets.append("encrypted_blob = %s")
        args.append(new_blob)
    if (new_key_pass or "") != (row["encrypted_key_passphrase"] or ""):
        sets.append("encrypted_key_passphrase = %s")
        args.append(new_key_pass)
    if not sets:
        return jsonify({"ok": True})
    args.append(iid)
    with db_cursor() as (_, cur):
        cur.execute(
            f"UPDATE ssh_identities SET {', '.join(sets)} WHERE id = %s",
            tuple(args),
        )
    return jsonify({"ok": True})


@app.route("/api/identities/<int:iid>", methods=["DELETE"])
@require_auth("write:hosts")
def delete_identity(iid: int):
    with db_cursor() as (_, cur):
        # Check if identity is being used by any hosts
        cur.execute(
            "SELECT COUNT(*) as count FROM ssh_hosts WHERE identity_id = %s",
            (iid,),
        )
        result = cur.fetchone()
        if result and result["count"] > 0:
            return jsonify({
                "error": f"Cannot delete identity: it is being used by {result['count']} host(s)"
            }), 409
        
        cur.execute("DELETE FROM ssh_identities WHERE id = %s", (iid,))
        if cur.rowcount == 0:
            return jsonify({"error": "not found"}), 404
    return jsonify({"ok": True})


@app.route("/api/snippets", methods=["GET"])
@require_auth("read:hosts")
def list_snippets():
    with db_cursor() as (_, cur):
        cur.execute("SELECT id, label, command, created_at, updated_at FROM ssh_snippets ORDER BY label ASC")
        rows = cur.fetchall()
    return jsonify({"items": rows})


@app.route("/api/snippets", methods=["POST"])
@require_auth("write:hosts")
def create_snippet():
    req = request.get_json()
    if not req:
        return jsonify({"error": "invalid json"}), 400
    label = (req.get("label") or "").strip()
    command = req.get("command") or ""
    if not label or not command:
        return jsonify({"error": "label and command required"}), 400
    with db_cursor() as (_, cur):
        cur.execute(
            "INSERT INTO ssh_snippets (label, command) VALUES (%s, %s)",
            (label, command),
        )
        sid = cur.lastrowid
    return jsonify({"id": sid}), 201


@app.route("/api/snippets/<int:sid>", methods=["PATCH"])
@require_auth("write:hosts")
def update_snippet(sid: int):
    req = request.get_json()
    if not req:
        return jsonify({"error": "invalid json"}), 400
    
    updates = []
    args = []
    if "label" in req:
        label = (req["label"] or "").strip()
        if not label:
            return jsonify({"error": "label cannot be empty"}), 400
        updates.append("label = %s")
        args.append(label)
    if "command" in req:
        cmd = req["command"] or ""
        if not cmd:
            return jsonify({"error": "command cannot be empty"}), 400
        updates.append("command = %s")
        args.append(cmd)
    
    if not updates:
        return jsonify({"ok": True})
    
    args.append(sid)
    with db_cursor() as (_, cur):
        cur.execute(
            f"UPDATE ssh_snippets SET {', '.join(updates)} WHERE id = %s",
            tuple(args),
        )
        if cur.rowcount == 0:
            return jsonify({"error": "not found"}), 404
    return jsonify({"ok": True})


@app.route("/api/snippets/<int:sid>", methods=["DELETE"])
@require_auth("write:hosts")
def delete_snippet(sid: int):
    with db_cursor() as (_, cur):
        cur.execute("DELETE FROM ssh_snippets WHERE id = %s", (sid,))
        if cur.rowcount == 0:
            return jsonify({"error": "not found"}), 404
    return jsonify({"ok": True})


def _host_select_sql(extra_where: str = "") -> str:
    return f"""
            SELECT h.id, h.folder_id, h.label, h.hostname, h.port, h.identity_id, h.jump_host_id,
                   h.created_at, h.updated_at, h.last_connected_at,
                   COALESCE(i.label, 'One-time') AS identity_label,
                   COALESCE(i.auth_type, h.inline_identity_auth_type) AS identity_auth_type,
                   pf.label AS folder_label,
                   jh.label AS jump_host_label,
                   {_host_tag_list_sql()}
            FROM ssh_hosts h
            LEFT JOIN ssh_identities i ON i.id = h.identity_id
            LEFT JOIN ssh_folders pf ON pf.id = h.folder_id
            LEFT JOIN ssh_hosts jh ON jh.id = h.jump_host_id
            {extra_where}
            """

@app.route("/api/folders", methods=["GET"])
@require_auth("read:hosts")
def list_all_folders():
    with db_cursor() as (_, cur):
        cur.execute(
            "SELECT id, label, parent_id FROM ssh_folders ORDER BY label"
        )
        rows = cur.fetchall()
    return jsonify({"items": rows})


@app.route("/api/folders", methods=["POST"])
@require_auth("write:hosts")
def create_folder():
    body = request.get_json(silent=True) or {}
    label = (body.get("label") or "").strip()
    if not label:
        return jsonify({"error": "label required"}), 400
    pid = body.get("parent_id")
    parent_id = int(pid) if pid is not None and pid != "" else None
    if parent_id is not None:
        with db_cursor() as (_, cur):
            cur.execute("SELECT id FROM ssh_folders WHERE id = %s", (parent_id,))
            if not cur.fetchone():
                return jsonify({"error": "parent not found"}), 400
    with db_cursor() as (_, cur):
        cur.execute(
            "INSERT INTO ssh_folders (label, parent_id) VALUES (%s, %s)",
            (label, parent_id),
        )
        fid = cur.lastrowid
    return jsonify({"id": fid}), 201


@app.route("/api/folders/<int:fid>", methods=["PATCH"])
@require_auth("write:hosts")
def update_folder(fid: int):
    body = request.get_json(silent=True) or {}
    with db_cursor() as (_, cur):
        cur.execute("SELECT id, parent_id, label FROM ssh_folders WHERE id = %s", (fid,))
        row = cur.fetchone()
    if not row:
        return jsonify({"error": "not found"}), 404
    sets = []
    args: list[Any] = []
    if "label" in body:
        sets.append("label = %s")
        args.append(str(body["label"]).strip())
    if "parent_id" in body:
        p = body["parent_id"]
        new_parent = int(p) if p is not None and p != "" else None
        if new_parent == fid:
            return jsonify({"error": "cannot set parent to self"}), 400
        with db_cursor() as (_, cur):
            if new_parent is not None:
                cur.execute("SELECT id FROM ssh_folders WHERE id = %s", (new_parent,))
                if not cur.fetchone():
                    return jsonify({"error": "parent not found"}), 400
            sub = _folder_subtree_ids(cur, fid)
        if new_parent is not None and new_parent in sub:
            return jsonify({"error": "cannot move folder into its descendant"}), 400
        sets.append("parent_id = %s")
        args.append(new_parent)
    if not sets:
        return jsonify({"ok": True})
    args.append(fid)
    with db_cursor() as (_, cur):
        cur.execute(
            f"UPDATE ssh_folders SET {', '.join(sets)} WHERE id = %s",
            tuple(args),
        )
    return jsonify({"ok": True})


@app.route("/api/folders/<int:fid>", methods=["DELETE"])
@require_auth("write:hosts")
def delete_folder(fid: int):
    with db_cursor() as (_, cur):
        cur.execute("DELETE FROM ssh_folders WHERE id = %s", (fid,))
        if cur.rowcount == 0:
            return jsonify({"error": "not found"}), 404
    return jsonify({"ok": True})


@app.route("/api/browse", methods=["GET"])
@require_auth("read:hosts")
def api_browse():
    raw_fid = request.args.get("folder_id")
    if raw_fid in (None, "", "root"):
        folder_id = None
    else:
        try:
            folder_id = int(raw_fid)
        except (TypeError, ValueError):
            return jsonify({"error": "invalid folder_id"}), 400
    q = (request.args.get("q") or "").strip()
    search_mode, search_term = _parse_search_query(q)

    with db_cursor() as (_, cur):
        breadcrumb: list[dict[str, Any]] = []
        if folder_id is not None:
            cur.execute("SELECT id FROM ssh_folders WHERE id = %s", (folder_id,))
            if not cur.fetchone():
                return jsonify({"error": "folder not found"}), 404
            breadcrumb = _folder_breadcrumb_rows(cur, folder_id)

        if q:
            if search_mode == "tag":
                tag_name = _normalize_tag_name(search_term)
                if tag_name is None:
                    hosts: list[dict[str, Any]] = []
                else:
                    tag_where, tag_args = _host_tag_filter_sql(tag_name)
                    cur.execute(
                        _host_select_sql(f"WHERE {tag_where}") + " ORDER BY h.label",
                        tag_args,
                    )
                    hosts = _serialize_host_rows(cur.fetchall())
                return jsonify(
                    {
                        "breadcrumb": breadcrumb,
                        "folders": [],
                        "hosts": hosts,
                        "search_active": True,
                        "search_mode": "tag",
                        "search_tag": tag_name,
                    }
                )

            esc = _like_escape(search_term)
            pat = f"%{esc}%"
            if folder_id is None:
                cur.execute(
                    _host_select_sql(
                        "WHERE (h.label LIKE %s ESCAPE '\\\\' OR h.hostname LIKE %s ESCAPE '\\\\')"
                    )
                    + " ORDER BY h.label",
                    (pat, pat),
                )
                hosts = _serialize_host_rows(cur.fetchall())
            else:
                ids = _folder_subtree_ids(cur, folder_id)
                if not ids:
                    hosts = []
                else:
                    ph = ",".join(["%s"] * len(ids))
                    cur.execute(
                        _host_select_sql(
                            f"WHERE h.folder_id IN ({ph}) AND "
                            "(h.label LIKE %s ESCAPE '\\\\' OR h.hostname LIKE %s ESCAPE '\\\\')"
                        )
                        + " ORDER BY h.label",
                        (*ids, pat, pat),
                    )
                    hosts = _serialize_host_rows(cur.fetchall())
            return jsonify(
                {
                    "breadcrumb": breadcrumb,
                    "folders": [],
                    "hosts": hosts,
                    "search_active": True,
                    "search_mode": "text",
                }
            )

        if folder_id is None:
            cur.execute(
                "SELECT id, label, parent_id FROM ssh_folders WHERE parent_id IS NULL ORDER BY label"
            )
            folders = cur.fetchall()
            cur.execute(
                _host_select_sql("WHERE h.folder_id IS NULL") + " ORDER BY h.label"
            )
        else:
            cur.execute(
                "SELECT id, label, parent_id FROM ssh_folders WHERE parent_id = %s ORDER BY label",
                (folder_id,),
            )
            folders = cur.fetchall()
            cur.execute(
                _host_select_sql("WHERE h.folder_id = %s") + " ORDER BY h.label",
                (folder_id,),
            )
        hosts = _serialize_host_rows(cur.fetchall())

    return jsonify(
        {
            "breadcrumb": breadcrumb,
            "folders": folders,
            "hosts": hosts,
            "search_active": False,
        }
    )


@app.route("/api/hosts", methods=["GET"])
@require_auth("read:hosts")
def list_hosts():
    with db_cursor() as (_, cur):
        cur.execute(_host_select_sql("") + " ORDER BY h.label")
        rows = _serialize_host_rows(cur.fetchall())
    return jsonify({"items": rows})


@app.route("/api/tags", methods=["GET"])
@require_auth("read:hosts")
def list_tags():
    with db_cursor() as (_, cur):
        cur.execute("SELECT name FROM ssh_tags ORDER BY name")
        rows = cur.fetchall()
    return jsonify({"items": [r["name"] for r in rows]})


@app.route("/api/hosts", methods=["POST"])
@require_auth("write:hosts")
def create_host():
    body = request.get_json(silent=True) or {}
    label = (body.get("label") or "").strip()
    hostname = (body.get("hostname") or "").strip()
    port = int(body.get("port") or 22)
    use_inline = body.get("use_inline_identity", False)
    identity_id = body.get("identity_id")
    jump_host_raw = body.get("jump_host_id")
    jump_host_id = int(jump_host_raw) if jump_host_raw is not None and jump_host_raw != "" else None
    
    if not label or not hostname:
        return jsonify({"error": "label, hostname required"}), 400

    tags = None
    if "tags" in body:
        tags = _parse_host_tags(body.get("tags"))
        if tags is None:
            return jsonify({"error": "invalid tags"}), 400
    
    # Validate identity or inline credentials
    inline_auth_type = None
    inline_blob = None
    inline_key_pass = None
    
    if use_inline:
        # Use inline credentials
        auth_type = body.get("auth_type")
        ssh_username = (body.get("ssh_username") or "").strip()
        if not auth_type or auth_type not in ("password", "publickey") or not ssh_username:
            return jsonify({"error": "auth_type and ssh_username required for inline identity"}), 400
        
        if auth_type == "password":
            password = body.get("password")
            if not password:
                return jsonify({"error": "password required"}), 400
            payload = json.dumps({"ssh_username": ssh_username, "password": password})
        else:
            private_key = body.get("private_key")
            if not private_key or not isinstance(private_key, str):
                return jsonify({"error": "private_key required"}), 400
            key_pass_plain = body.get("key_passphrase")
            payload = json.dumps({"ssh_username": ssh_username, "private_key": private_key})
            inline_key_pass = encrypt_secret(key_pass_plain) if key_pass_plain else None
        
        inline_auth_type = auth_type
        inline_blob = encrypt_secret(payload)
        identity_id = None
    else:
        # Use saved identity
        if not identity_id:
            return jsonify({"error": "identity_id required when not using inline identity"}), 400
    
    fid = body.get("folder_id")
    folder_id = int(fid) if fid is not None and fid != "" else None
    if folder_id is not None:
        with db_cursor() as (_, cur):
            cur.execute("SELECT id FROM ssh_folders WHERE id = %s", (folder_id,))
            if not cur.fetchone():
                return jsonify({"error": "folder not found"}), 400
    
    with db_cursor() as (_, cur):
        if jump_host_id is not None:
            cur.execute("SELECT id FROM ssh_hosts WHERE id = %s", (jump_host_id,))
            if not cur.fetchone():
                return jsonify({"error": "jump host not found"}), 400
        
        if identity_id:
            identity_id = int(identity_id)
        
        cur.execute(
            """
            INSERT INTO ssh_hosts (folder_id, label, hostname, port, identity_id, jump_host_id,
                                   inline_identity_auth_type, inline_identity_encrypted_blob, inline_identity_encrypted_key_passphrase)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (folder_id, label, hostname, port, identity_id, jump_host_id,
             inline_auth_type, inline_blob, inline_key_pass),
        )
        hid = cur.lastrowid
        if tags is not None:
            _set_host_tags(cur, int(hid), tags)
    return jsonify({"id": hid}), 201


@app.route("/api/hosts/<int:hid>", methods=["PATCH"])
@require_auth("write:hosts")
def update_host(hid: int):
    body = request.get_json(silent=True) or {}
    fields = []
    args: list[Any] = []
    
    # Handle inline identity switching
    if "use_inline_identity" in body:
        use_inline = body.get("use_inline_identity", False)
        if use_inline:
            # Switch to inline credentials
            auth_type = body.get("auth_type")
            ssh_username = (body.get("ssh_username") or "").strip()
            if not auth_type or auth_type not in ("password", "publickey") or not ssh_username:
                return jsonify({"error": "auth_type and ssh_username required for inline identity"}), 400
            
            if auth_type == "password":
                password = body.get("password")
                if not password:
                    return jsonify({"error": "password required"}), 400
                payload = json.dumps({"ssh_username": ssh_username, "password": password})
            else:
                private_key = body.get("private_key")
                if not private_key or not isinstance(private_key, str):
                    return jsonify({"error": "private_key required"}), 400
                key_pass_plain = body.get("key_passphrase")
                payload = json.dumps({"ssh_username": ssh_username, "private_key": private_key})
                inline_key_pass = encrypt_secret(key_pass_plain) if key_pass_plain else None
            
            # Clear identity_id and set inline fields
            fields.append("identity_id = %s")
            args.append(None)
            fields.append("inline_identity_auth_type = %s")
            args.append(auth_type)
            fields.append("inline_identity_encrypted_blob = %s")
            args.append(encrypt_secret(payload))
            fields.append("inline_identity_encrypted_key_passphrase = %s")
            if auth_type == "password":
                args.append(None)
            else:
                args.append(inline_key_pass)
        else:
            # Switch to saved identity - clear inline fields
            fields.append("identity_id = %s")
            args.append(body.get("identity_id"))
            fields.append("inline_identity_auth_type = %s")
            args.append(None)
            fields.append("inline_identity_encrypted_blob = %s")
            args.append(None)
            fields.append("inline_identity_encrypted_key_passphrase = %s")
            args.append(None)
    
    if "label" in body:
        fields.append("label = %s")
        args.append(str(body["label"]).strip())
    if "hostname" in body:
        fields.append("hostname = %s")
        args.append(str(body["hostname"]).strip())
    if "port" in body:
        fields.append("port = %s")
        args.append(int(body["port"]))
    if "identity_id" in body and "use_inline_identity" not in body:
        fields.append("identity_id = %s")
        args.append(int(body["identity_id"]))
    if "jump_host_id" in body:
        j = body["jump_host_id"]
        jump_host_id = int(j) if j is not None and j != "" else None
        if jump_host_id == hid:
            return jsonify({"error": "host cannot jump through itself"}), 400
        if jump_host_id is not None:
            with db_cursor() as (_, cur):
                cur.execute("SELECT id FROM ssh_hosts WHERE id = %s", (jump_host_id,))
                if not cur.fetchone():
                    return jsonify({"error": "jump host not found"}), 400
        fields.append("jump_host_id = %s")
        args.append(jump_host_id)
    if "folder_id" in body:
        p = body["folder_id"]
        folder_id = int(p) if p is not None and p != "" else None
        if folder_id is not None:
            with db_cursor() as (_, cur):
                cur.execute("SELECT id FROM ssh_folders WHERE id = %s", (folder_id,))
                if not cur.fetchone():
                    return jsonify({"error": "folder not found"}), 400
        fields.append("folder_id = %s")
        args.append(folder_id)

    tags = None
    if "tags" in body:
        tags = _parse_host_tags(body.get("tags"))
        if tags is None:
            return jsonify({"error": "invalid tags"}), 400

    if not fields and tags is None:
        return jsonify({"ok": True})

    with db_cursor() as (_, cur):
        cur.execute("SELECT id FROM ssh_hosts WHERE id = %s", (hid,))
        if not cur.fetchone():
            return jsonify({"error": "not found"}), 404
        if fields:
            update_args = list(args)
            update_args.append(hid)
            cur.execute(
                f"UPDATE ssh_hosts SET {', '.join(fields)} WHERE id = %s",
                tuple(update_args),
            )
        if tags is not None:
            _set_host_tags(cur, hid, tags)
    return jsonify({"ok": True})


@app.route("/api/hosts/<int:hid>", methods=["DELETE"])
@require_auth("write:hosts")
def delete_host(hid: int):
    with db_cursor() as (_, cur):
        cur.execute("DELETE FROM ssh_hosts WHERE id = %s", (hid,))
        if cur.rowcount == 0:
            return jsonify({"error": "not found"}), 404
    return jsonify({"ok": True})


@app.route("/api/audit/connections", methods=["GET"])
@require_auth("read:audit")
def list_connection_audit():
    raw_limit = request.args.get("limit") or "200"
    raw_days = request.args.get("days_back")
    try:
        limit = int(raw_limit)
    except (TypeError, ValueError):
        limit = 200
    limit = max(1, min(limit, 500))
    
    # Build the where clause for days filtering
    where_clause = ""
    params: list[Any] = []
    if raw_days is not None:
        try:
            days = int(raw_days)
            if days > 0:
                where_clause = "WHERE started_at >= DATE_SUB(NOW(), INTERVAL %s DAY)"
                params = [days]
        except (TypeError, ValueError):
            pass
    
    with db_cursor() as (_, cur):
        query = f"""
            SELECT id, host_id, host_label, hostname, port, jump_host_id,
                   started_at, ended_at, duration_seconds
            FROM ssh_connection_audit
            {where_clause}
            ORDER BY id DESC
            LIMIT %s
            """
        params.append(limit)
        cur.execute(query, tuple(params))
        rows = cur.fetchall()
    return jsonify({"items": rows})


@app.route("/api/api-keys/scopes", methods=["GET"])
@require_login
def list_api_key_scopes():
    return jsonify(
        {
            "items": [
                {
                    "id": "read:hosts",
                    "label": "Read hosts",
                    "description": "List hosts, folders, and identities",
                },
                {
                    "id": "write:hosts",
                    "label": "Write hosts",
                    "description": "Create, update, and delete hosts, folders, and identities",
                },
                {
                    "id": "read:audit",
                    "label": "Read audit",
                    "description": "View the connection audit log",
                },
                {
                    "id": "terminal:connect",
                    "label": "Terminal",
                    "description": "Open SSH terminal sessions (WebSocket)",
                },
                {
                    "id": "sftp:manage",
                    "label": "SFTP",
                    "description": "List, upload, download, and manage remote files",
                },
            ]
        }
    )


def _serialize_api_key_row(row: dict[str, Any]) -> dict[str, Any]:
    scopes = sorted(_parse_api_key_scopes(row.get("scopes")))

    def _fmt_ts(val: Any) -> str | None:
        if val is None:
            return None
        if hasattr(val, "isoformat"):
            return val.isoformat(sep=" ", timespec="seconds")
        return str(val)

    expires_at = row.get("expires_at")
    revoked_at = row.get("revoked_at")
    expired = bool(
        expires_at is not None and expires_at <= _utcnow() and revoked_at is None
    )
    return {
        "id": row["id"],
        "label": row["label"],
        "key_prefix": row["key_prefix"],
        "scopes": scopes,
        "expires_at": _fmt_ts(expires_at),
        "last_used_at": _fmt_ts(row.get("last_used_at")),
        "revoked_at": _fmt_ts(revoked_at),
        "created_at": _fmt_ts(row.get("created_at")),
        "expired": expired,
        "active": revoked_at is None and not expired,
    }


@app.route("/api/api-keys", methods=["GET"])
@require_login
def list_api_keys():
    with db_cursor() as (_, cur):
        cur.execute(
            """
            SELECT id, label, key_prefix, scopes, expires_at, last_used_at,
                   revoked_at, created_at
            FROM api_keys
            ORDER BY id DESC
            """
        )
        rows = cur.fetchall()
    return jsonify({"items": [_serialize_api_key_row(r) for r in rows]})


@app.route("/api/api-keys", methods=["POST"])
@require_login
def create_api_key():
    body = request.get_json(silent=True) or {}
    label = (body.get("label") or "").strip()
    if not label:
        return jsonify({"error": "label required"}), 400
    scopes = _validate_api_key_scopes(body.get("scopes"))
    if scopes is None:
        return jsonify({"error": "at least one valid scope required"}), 400
    expires_at = _parse_optional_expires_at(body.get("expires_at"))
    if expires_at == "invalid":
        return jsonify({"error": "invalid expires_at"}), 400
    if expires_at is not None and expires_at <= _utcnow():
        return jsonify({"error": "expires_at must be in the future"}), 400
    full_key, key_prefix, key_hash = _generate_api_key_material()
    with db_cursor() as (_, cur):
        cur.execute(
            """
            INSERT INTO api_keys (label, key_prefix, key_hash, scopes, expires_at)
            VALUES (%s, %s, %s, %s, %s)
            """,
            (label, key_prefix, key_hash, json.dumps(scopes), expires_at),
        )
        key_id = cur.lastrowid
    return (
        jsonify(
            {
                "id": key_id,
                "label": label,
                "key_prefix": key_prefix,
                "scopes": scopes,
                "expires_at": expires_at.isoformat(sep=" ", timespec="seconds")
                if expires_at
                else None,
                "key": full_key,
            }
        ),
        201,
    )


@app.route("/api/api-keys/<int:kid>", methods=["PATCH"])
@require_login
def update_api_key(kid: int):
    body = request.get_json(silent=True) or {}
    sets: list[str] = []
    params: list[Any] = []
    if "label" in body:
        label = (body.get("label") or "").strip()
        if not label:
            return jsonify({"error": "label required"}), 400
        sets.append("label = %s")
        params.append(label)
    if "scopes" in body:
        scopes = _validate_api_key_scopes(body.get("scopes"))
        if scopes is None:
            return jsonify({"error": "at least one valid scope required"}), 400
        sets.append("scopes = %s")
        params.append(json.dumps(scopes))
    if "expires_at" in body:
        expires_at = _parse_optional_expires_at(body.get("expires_at"))
        if expires_at == "invalid":
            return jsonify({"error": "invalid expires_at"}), 400
        if expires_at is not None and expires_at <= _utcnow():
            return jsonify({"error": "expires_at must be in the future"}), 400
        sets.append("expires_at = %s")
        params.append(expires_at)
    if not sets:
        return jsonify({"error": "no changes"}), 400
    params.append(kid)
    with db_cursor() as (_, cur):
        cur.execute(
            f"UPDATE api_keys SET {', '.join(sets)} WHERE id = %s AND revoked_at IS NULL",
            tuple(params),
        )
        if cur.rowcount == 0:
            return jsonify({"error": "not found"}), 404
    return jsonify({"ok": True})


@app.route("/api/api-keys/<int:kid>", methods=["DELETE"])
@require_login
def delete_api_key(kid: int):
    with db_cursor() as (_, cur):
        cur.execute(
            """
            DELETE FROM api_keys
            WHERE id = %s
            """,
            (kid,),
        )
        if cur.rowcount == 0:
            return jsonify({"error": "not found"}), 404
    return jsonify({"ok": True})


@app.route("/ws/terminal", websocket=True)
def ws_terminal():
    sock, use_gevent_wsgi = _open_terminal_socket()

    def bail_close(code: int, msg: str):
        try:
            sock.close(reason=code, message=msg)
        except Exception:
            pass
        return GeventWsAppResponse() if use_gevent_wsgi else Response(status=400)

    auth = _ws_resolve_auth()
    if not auth or not _auth_has_scopes(auth, ("terminal:connect",)):
        return bail_close(1008, "unauthorized")

    host_id_raw = request.args.get("host_id")
    if not host_id_raw:
        return bail_close(4000, "host_id required")
    try:
        host_id = int(host_id_raw)
    except ValueError:
        return bail_close(4000, "invalid host_id")

    if _registry_count() >= MAX_CONCURRENT_SSH:
        return bail_close(4002, "too many connections")

    ssh_result: queue.Queue = queue.Queue(maxsize=1)
    pending_inbound: list[Any] = []

    def ssh_connect_worker():
        try:
            c, ch, jump_clients, host_row = _connect_with_jump_chain(host_id)
            ssh_result.put(("ok", (c, ch, jump_clients, host_row)))
        except Exception as e:
            ssh_result.put(("err", e))

    t_ssh = threading.Thread(target=ssh_connect_worker, daemon=True)
    t_ssh.start()

    client_gone = False
    while t_ssh.is_alive():
        msg = sock.receive(timeout=0.25)
        if msg is not None:
            pending_inbound.append(msg)
            continue
        if use_gevent_wsgi and getattr(sock, "_gw", None) is not None and sock._gw.closed:
            client_gone = True
            break

    t_ssh.join(timeout=3600 if not client_gone else 5)

    if client_gone:
        return GeventWsAppResponse() if use_gevent_wsgi else Response(status=204)

    try:
        kind, payload = ssh_result.get_nowait()
    except queue.Empty:
        log.error("SSH worker finished without result")
        return GeventWsAppResponse() if use_gevent_wsgi else Response(status=500)

    if kind == "err":
        log.error("SSH connect failed: %s", payload, exc_info=payload)
        try:
            sock.close(reason=4500, message=str(payload)[:120])
        except Exception:
            pass
        return GeventWsAppResponse() if use_gevent_wsgi else Response(status=500)

    client, channel, jump_clients, host_row = payload

    conn_id = str(uuid.uuid4())
    session_started = time.monotonic()
    audit_id = _insert_connection_audit(host_row)
    entry = {
        "client": client,
        "channel": channel,
        "sftp": None,
        "lock": threading.Lock(),
        "host_id": host_id,
        "label": host_row["label"],
        "jump_clients": jump_clients,
        "audit_id": audit_id,
        "session_started": session_started,
    }
    _conn_put(conn_id, entry)

    def handle_ws_inbound(msg) -> bool:
        if msg is None:
            return False
        if isinstance(msg, str) and msg.startswith("{"):
            try:
                o = json.loads(msg)
                if o.get("type") == "resize":
                    channel.resize_pty(
                        width=int(o.get("cols", 120)),
                        height=int(o.get("rows", 40)),
                    )
                    return True
                if o.get("type") == "ping":
                    sock.send(json.dumps({"type": "pong"}))
                    return True
            except (json.JSONDecodeError, TypeError, ValueError):
                pass
            channel.send(msg.encode("utf-8"))
        elif isinstance(msg, str):
            channel.send(msg.encode("utf-8"))
        else:
            channel.send(msg)
        return True

    for msg in pending_inbound:
        if not handle_ws_inbound(msg):
            _conn_pop(conn_id)
            _close_ssh_entry(entry)
            return GeventWsAppResponse() if use_gevent_wsgi else Response(status=204)

    out_q: queue.Queue[bytes | None] = queue.Queue()
    stop = threading.Event()

    def channel_reader():
        try:
            while not stop.is_set():
                try:
                    data = channel.recv(65536)
                    if not data:
                        break
                    out_q.put(data)
                except Exception:
                    break
        finally:
            out_q.put(None)
            stop.set()

    t_ch = threading.Thread(target=channel_reader, daemon=True)
    t_ch.start()

    try:
        sock.send(
            json.dumps(
                {
                    "type": "ready",
                    "conn_id": conn_id,
                    "label": host_row["label"],
                },
                ensure_ascii=True,
            )
        )

        last_ws_keepalive = time.monotonic()
        while not stop.is_set():
            drained_eof = False
            try:
                while True:
                    item = out_q.get_nowait()
                    if item is None:
                        drained_eof = True
                        break
                    sock.send(item)
                    last_ws_keepalive = time.monotonic()
            except queue.Empty:
                pass
            if drained_eof:
                break

            now = time.monotonic()
            if (
                WS_KEEPALIVE_INTERVAL > 0
                and now - last_ws_keepalive >= WS_KEEPALIVE_INTERVAL
            ):
                if not _ssh_transports_alive(client, jump_clients):
                    break
                try:
                    sock.send(json.dumps({"type": "keepalive"}))
                except Exception:
                    break
                last_ws_keepalive = now

            msg = sock.receive(timeout=0.15)
            if msg is None:
                if use_gevent_wsgi and getattr(sock, "_gw", None) is not None and sock._gw.closed:
                    break
                continue
            last_ws_keepalive = time.monotonic()
            if not handle_ws_inbound(msg):
                break
    except ConnectionClosed:
        pass
    except Exception:
        log.exception("ws loop")
    finally:
        stop.set()
        try:
            channel.close()
        except Exception:
            pass
        t_ch.join(timeout=2)
        _close_ssh_entry(entry)
        _conn_pop(conn_id)
        if audit_id is not None:
            _finish_connection_audit(audit_id, session_started)

    try:
        sock.close()
    except Exception:
        pass

    return GeventWsAppResponse() if use_gevent_wsgi else Response(status=204)


@app.route("/api/sftp/<cid>/list", methods=["POST"])
@require_auth("sftp:manage")
def sftp_list(cid: str):
    entry = _conn_get(cid)
    if not entry:
        return jsonify({"error": "unknown connection"}), 404
    body = request.get_json(silent=True) or {}
    path = validate_remote_path(body.get("path") or "/")
    try:
        sf = _get_sftp(entry)
        attrs = []
        for attr in sf.listdir_attr(path):
            attrs.append(
                {
                    "filename": attr.filename,
                    "st_mode": int(attr.st_mode),
                    "st_size": int(attr.st_size) if attr.st_size else 0,
                    "st_mtime": int(attr.st_mtime) if attr.st_mtime else 0,
                }
            )
        attrs.sort(key=lambda x: (not _is_dir_mode(x["st_mode"]), x["filename"].lower()))
        return jsonify({"path": path, "entries": attrs})
    except Exception as e:
        log.exception("sftp list")
        return jsonify({"error": str(e)}), 400


def _is_dir_mode(mode: int) -> bool:
    import stat

    return stat.S_ISDIR(mode)


@app.route("/api/sftp/<cid>/mkdir", methods=["POST"])
@require_auth("sftp:manage")
def sftp_mkdir(cid: str):
    entry = _conn_get(cid)
    if not entry:
        return jsonify({"error": "unknown connection"}), 404
    body = request.get_json(silent=True) or {}
    path = validate_remote_path(body.get("path") or "")
    try:
        _get_sftp(entry).mkdir(path)
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route("/api/sftp/<cid>/remove", methods=["POST"])
@require_auth("sftp:manage")
def sftp_remove(cid: str):
    entry = _conn_get(cid)
    if not entry:
        return jsonify({"error": "unknown connection"}), 404
    body = request.get_json(silent=True) or {}
    path = validate_remote_path(body.get("path") or "")
    try:
        sf = _get_sftp(entry)
        st = sf.stat(path)
        import stat

        if stat.S_ISDIR(st.st_mode):
            sf.rmdir(path)
        else:
            sf.remove(path)
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route("/api/sftp/<cid>/rename", methods=["POST"])
@require_auth("sftp:manage")
def sftp_rename(cid: str):
    entry = _conn_get(cid)
    if not entry:
        return jsonify({"error": "unknown connection"}), 404
    body = request.get_json(silent=True) or {}
    old = validate_remote_path(body.get("old_path") or "")
    new = validate_remote_path(body.get("new_path") or "")
    try:
        _get_sftp(entry).rename(old, new)
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route("/api/sftp/<cid>/upload", methods=["POST"])
@require_auth("sftp:manage")
def sftp_upload(cid: str):
    entry = _conn_get(cid)
    if not entry:
        return jsonify({"error": "unknown connection"}), 404
    path = validate_remote_path(request.form.get("path") or "")
    f = request.files.get("file")
    if not f or not f.filename:
        return jsonify({"error": "file required"}), 400
    safe = secure_filename(f.filename)
    remote = posixpath.join(path, safe) if path != "/" else posixpath.join("/", safe)
    remote = validate_remote_path(remote)
    try:
        sf = _get_sftp(entry)
        sf.putfo(f.stream, remote)
        return jsonify({"ok": True, "path": remote})
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route("/api/sftp/<cid>/download", methods=["GET"])
@require_auth("sftp:manage")
def sftp_download(cid: str):
    entry = _conn_get(cid)
    if not entry:
        abort(404)
    path = validate_remote_path(request.args.get("path") or "")
    try:
        sf = _get_sftp(entry)
        flike = sf.open(path, "rb")

        def gen():
            try:
                while True:
                    chunk = flike.read(65536)
                    if not chunk:
                        break
                    yield chunk
            finally:
                flike.close()

        name = posixpath.basename(path) or "download"
        return Response(
            gen(),
            mimetype="application/octet-stream",
            headers={"Content-Disposition": f'attachment; filename="{name}"'},
        )
    except Exception:
        abort(400)


STATIC_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
DIST = os.path.join(STATIC_ROOT, "dist")
PWA_STATIC_FILES = frozenset({"manifest.webmanifest", "sw.js"})


@app.route("/assets/<path:sub>")
def spa_assets(sub):
    return send_from_directory(os.path.join(DIST, "assets"), sub)


@app.route("/", defaults={"path": ""})
@app.route("/<path:path>")
def spa(path):
    if path.startswith("api") or path.startswith("ws"):
        abort(404)
    index = os.path.join(DIST, "index.html")
    if not os.path.isfile(index):
        return (
            "Frontend not built. Run: cd frontend && npm ci && npm run build",
            503,
        )
    if path in PWA_STATIC_FILES:
        try:
            pwa_path = safe_join(STATIC_ROOT, path)
        except ValueError:
            pwa_path = None
        if pwa_path and os.path.isfile(pwa_path):
            if path.endswith(".webmanifest"):
                return send_file(pwa_path, mimetype="application/manifest+json")
            return send_file(pwa_path, mimetype="application/javascript")
    if path:
        try:
            file_path = safe_join(DIST, path)
        except ValueError:
            file_path = None
        if file_path and os.path.isfile(file_path):
            if path.endswith(".webmanifest"):
                return send_file(file_path, mimetype="application/manifest+json")
            if path.endswith(".js"):
                return send_file(file_path, mimetype="application/javascript")
            return send_file(file_path)
    return send_from_directory(DIST, "index.html")


with app.app_context():
    try:
        init_db()
    except Exception as e:
        log.warning("init_db skipped (DB unavailable): %s", e)
