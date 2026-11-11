#!/usr/bin/env python3
"""
seed.py — Tạo CSDL lab.db từ db/schema.sql và điền mật khẩu băm cho tài khoản thử.

  python seed.py            # tạo ./lab.db (ghi đè nếu đã có)
  python seed.py /duong/dan/lab.db

Mật khẩu chỉ lưu dưới dạng băm PBKDF2-HMAC-SHA256, không lưu bản rõ.
"""
import hashlib
import os
import sqlite3
import sys

# Windows: console mặc định cp1252 không in được tiếng Việt/emoji -> ép UTF-8.
for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

HERE = os.path.dirname(os.path.abspath(__file__))
SCHEMA = os.path.join(HERE, "db", "schema.sql")
_SALT = b"labshop-demo-salt"  # chỉ dùng trong lab

# Tài khoản thử nghiệm của lab (email -> (tên, mật khẩu, vai trò))
SEED_USERS = {
    "khach@labshop.vn": ("Khách hàng C", "Khach@2026", "customer"),
}


def pw_hash(pw: str) -> str:
    return hashlib.pbkdf2_hmac("sha256", pw.encode("utf-8"), _SALT, 120_000).hex()


def main():
    db_path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "lab.db")
    for ext in ("", "-wal", "-shm"):
        try:
            os.remove(db_path + ext)
        except OSError:
            pass
    with open(SCHEMA, encoding="utf-8") as f:
        schema = f.read()
    con = sqlite3.connect(db_path)
    con.executescript(schema)
    for email, (name, pw, role) in SEED_USERS.items():
        con.execute(
            "INSERT INTO users (email, name, pw_hash, role) VALUES (?,?,?,?)",
            (email, name, pw_hash(pw), role),
        )
    con.commit()
    n_prod = con.execute("SELECT COUNT(*) FROM products").fetchone()[0]
    n_user = con.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    con.close()
    print(f"✓ Đã tạo {db_path}: {n_prod} sản phẩm, {n_user} tài khoản thử.")


if __name__ == "__main__":
    main()
