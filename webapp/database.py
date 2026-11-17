"""Versioned, additive SQLite migrations and explicit lab fixtures."""
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import time
from pathlib import Path
from contextlib import contextmanager

LEGACY_SALT = b"labshop-demo-salt"


@contextmanager
def connection(path):
    c = sqlite3.connect(path, timeout=10)
    try:
        with c:
            yield c
    finally:
        c.close()


def password_hash(password, salt=""):
    return hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt) if salt else LEGACY_SALT, 120_000).hex()


def verify_password(password, user):
    return hmac.compare_digest(user["pw_hash"], password_hash(password, user["pw_salt"]))


def migrate(path):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with connection(path) as c:
        c.execute("PRAGMA journal_mode=WAL")
        if not c.execute("SELECT 1 FROM sqlite_master WHERE name='users'").fetchone():
            c.executescript(Path(__file__).with_name("db").joinpath("schema.sql").read_text(encoding="utf-8"))
        columns = {r[1] for r in c.execute("PRAGMA table_info(users)")}
        for name, declaration in {"pw_salt": "TEXT NOT NULL DEFAULT ''", "is_active": "INTEGER NOT NULL DEFAULT 1",
                                  "created_at": "TEXT NOT NULL DEFAULT ''", "password_version": "INTEGER NOT NULL DEFAULT 1"}.items():
            if name not in columns:
                c.execute(f"ALTER TABLE users ADD COLUMN {name} {declaration}")
        c.execute("CREATE TABLE IF NOT EXISTS schema_migrations(version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)")
        c.execute("CREATE TABLE IF NOT EXISTS sessions(token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id), expires REAL NOT NULL)")
        c.execute("CREATE INDEX IF NOT EXISTS sessions_expiry ON sessions(expires)")
        c.execute("CREATE TABLE IF NOT EXISTS login_failures(ip TEXT NOT NULL, at REAL NOT NULL)")
        c.execute("CREATE INDEX IF NOT EXISTS failures_ip_time ON login_failures(ip,at)")
        c.execute("CREATE TABLE IF NOT EXISTS login_locks(ip TEXT PRIMARY KEY, until_at REAL NOT NULL)")
        c.execute("INSERT OR IGNORE INTO schema_migrations VALUES(1,datetime('now'))")


def seed_demo(path, credentials_path=None):
    """Only insert missing users. Never reset an existing user's password or orders."""
    migrate(path)
    users = {
        "khach@labshop.vn": ("Khách hàng C", "Khach@2026", "customer"),
        "admin@labshop.vn": ("Quản trị Lab Shop", "S3cureAdm!n#2026", "admin"),
        "minh@labshop.vn": ("Nguyễn Minh", "demo123", "customer"),
        "lan@labshop.vn": ("Trần Lan", secrets.token_urlsafe(16), "customer"),
        "nhanvien@labshop.vn": ("Nhân viên cửa hàng", secrets.token_urlsafe(16), "staff"),
    }
    manifest = {"created_at": time.time(), "accounts_added": []}
    with connection(path) as c:
        for email, (name, password, role) in users.items():
            if c.execute("SELECT 1 FROM users WHERE email=? COLLATE NOCASE", (email,)).fetchone():
                continue
            salt = secrets.token_hex(16)
            c.execute("INSERT INTO users(email,name,pw_hash,role,pw_salt,is_active,created_at,password_version) VALUES(?,?,?,?,?,1,datetime('now'),2)",
                      (email, name, password_hash(password, salt), role, salt))
            manifest["accounts_added"].append({"email": email, "password": password, "role": role})
        for email, code, pid in (("minh@labshop.vn", "DEMO-MINH-01", 1), ("lan@labshop.vn", "DEMO-LAN-01", 3)):
            if not c.execute("SELECT 1 FROM orders WHERE order_code=?", (code,)).fetchone():
                price = c.execute("SELECT price FROM products WHERE id=?", (pid,)).fetchone()[0]
                oid = c.execute("INSERT INTO orders(order_code,email,total,count,created_at) VALUES(?,?,?,?,datetime('now'))", (code,email,price,1)).lastrowid
                c.execute("INSERT INTO order_items VALUES(?,?,1,?)", (oid,pid,price))
        if credentials_path and manifest["accounts_added"]:
            p = Path(credentials_path)
            p.parent.mkdir(parents=True, exist_ok=True)
            # Write before committing users: a file error must roll back new records.
            with p.open("x", encoding="utf-8") as f:
                os.chmod(p, 0o600)
                json.dump(manifest, f, ensure_ascii=False, indent=2)
    return manifest
