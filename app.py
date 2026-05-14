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
import logging
import posixpath
import queue
import threading
import time
import uuid
from contextlib import contextmanager
from datetime import timedelta
from functools import wraps
from typing import Any

import mysql.connector
from mysql.connector import pooling
import paramiko
from cryptography.fernet import Fernet, InvalidToken
from dotenv import load_dotenv
from flask import Flask, jsonify, request, session, send_from_directory, send_file, abort, Response
from werkzeug.security import check_password_hash
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
SSH_KEEPALIVE_INTERVAL = int(os.getenv("SSH_KEEPALIVE_INTERVAL", "30"))


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
        transport = client.get_transport()
        if transport is not None:
            transport.set_keepalive(SSH_KEEPALIVE_INTERVAL)

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
    if session.get("logged_in"):
        return jsonify({"logged_in": True})
    return jsonify({"logged_in": False})


@app.route("/api/identities", methods=["GET"])
@require_login
def list_identities():
    with db_cursor() as (_, cur):
        cur.execute(
            "SELECT id, label, auth_type, created_at, updated_at FROM ssh_identities ORDER BY label"
        )
        rows = cur.fetchall()
    return jsonify({"items": rows})


@app.route("/api/identities", methods=["POST"])
@require_login
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
@require_login
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
@require_login
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


def _host_select_sql(extra_where: str = "") -> str:
    return f"""
            SELECT h.id, h.folder_id, h.label, h.hostname, h.port, h.identity_id, h.jump_host_id,
                   h.created_at, h.updated_at, h.last_connected_at,
                   COALESCE(i.label, 'One-time') AS identity_label, 
                   COALESCE(i.auth_type, h.inline_identity_auth_type) AS identity_auth_type,
                   pf.label AS folder_label,
                   jh.label AS jump_host_label
            FROM ssh_hosts h
            LEFT JOIN ssh_identities i ON i.id = h.identity_id
            LEFT JOIN ssh_folders pf ON pf.id = h.folder_id
            LEFT JOIN ssh_hosts jh ON jh.id = h.jump_host_id
            {extra_where}
            """

@app.route("/api/folders", methods=["GET"])
@require_login
def list_all_folders():
    with db_cursor() as (_, cur):
        cur.execute(
            "SELECT id, label, parent_id FROM ssh_folders ORDER BY label"
        )
        rows = cur.fetchall()
    return jsonify({"items": rows})


@app.route("/api/folders", methods=["POST"])
@require_login
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
@require_login
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
@require_login
def delete_folder(fid: int):
    with db_cursor() as (_, cur):
        cur.execute("DELETE FROM ssh_folders WHERE id = %s", (fid,))
        if cur.rowcount == 0:
            return jsonify({"error": "not found"}), 404
    return jsonify({"ok": True})


@app.route("/api/browse", methods=["GET"])
@require_login
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
    esc = _like_escape(q) if q else ""
    pat = f"%{esc}%" if q else ""

    with db_cursor() as (_, cur):
        breadcrumb: list[dict[str, Any]] = []
        if folder_id is not None:
            cur.execute("SELECT id FROM ssh_folders WHERE id = %s", (folder_id,))
            if not cur.fetchone():
                return jsonify({"error": "folder not found"}), 404
            breadcrumb = _folder_breadcrumb_rows(cur, folder_id)

        if q:
            if folder_id is None:
                cur.execute(
                    _host_select_sql(
                        "WHERE (h.label LIKE %s ESCAPE '\\\\' OR h.hostname LIKE %s ESCAPE '\\\\')"
                    )
                    + " ORDER BY h.label",
                    (pat, pat),
                )
                hosts = cur.fetchall()
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
                    hosts = cur.fetchall()
            return jsonify(
                {
                    "breadcrumb": breadcrumb,
                    "folders": [],
                    "hosts": hosts,
                    "search_active": True,
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
        hosts = cur.fetchall()

    return jsonify(
        {
            "breadcrumb": breadcrumb,
            "folders": folders,
            "hosts": hosts,
            "search_active": False,
        }
    )


@app.route("/api/hosts", methods=["GET"])
@require_login
def list_hosts():
    with db_cursor() as (_, cur):
        cur.execute(_host_select_sql("") + " ORDER BY h.label")
        rows = cur.fetchall()
    return jsonify({"items": rows})


@app.route("/api/hosts", methods=["POST"])
@require_login
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
    return jsonify({"id": hid}), 201


@app.route("/api/hosts/<int:hid>", methods=["PATCH"])
@require_login
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
    if not fields:
        return jsonify({"ok": True})
    args.append(hid)
    with db_cursor() as (_, cur):
        cur.execute(
            f"UPDATE ssh_hosts SET {', '.join(fields)} WHERE id = %s",
            tuple(args),
        )
        if cur.rowcount == 0:
            return jsonify({"error": "not found"}), 404
    return jsonify({"ok": True})


@app.route("/api/hosts/<int:hid>", methods=["DELETE"])
@require_login
def delete_host(hid: int):
    with db_cursor() as (_, cur):
        cur.execute("DELETE FROM ssh_hosts WHERE id = %s", (hid,))
        if cur.rowcount == 0:
            return jsonify({"error": "not found"}), 404
    return jsonify({"ok": True})


@app.route("/api/audit/connections", methods=["GET"])
@require_login
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


@app.route("/ws/terminal", websocket=True)
def ws_terminal():
    sock, use_gevent_wsgi = _open_terminal_socket()

    def bail_close(code: int, msg: str):
        try:
            sock.close(reason=code, message=msg)
        except Exception:
            pass
        return GeventWsAppResponse() if use_gevent_wsgi else Response(status=400)

    if not session.get("logged_in"):
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
                elif o.get("type") == "ping":
                    # Ping message to keep connection alive, ignore without sending to channel
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

        while not stop.is_set():
            drained_eof = False
            try:
                while True:
                    item = out_q.get_nowait()
                    if item is None:
                        drained_eof = True
                        break
                    sock.send(item)
            except queue.Empty:
                pass
            if drained_eof:
                break

            msg = sock.receive(timeout=0.15)
            if msg is None:
                if use_gevent_wsgi and getattr(sock, "_gw", None) is not None and sock._gw.closed:
                    break
                continue
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
@require_login
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
@require_login
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
@require_login
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
@require_login
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
@require_login
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
@require_login
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
