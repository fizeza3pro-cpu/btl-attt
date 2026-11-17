"""Additive migration. SQLite backup is consistent even when WAL is enabled."""
import argparse
import sqlite3
from pathlib import Path
from database import migrate, seed_demo, connection

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("database")
    p.add_argument("--backup")
    p.add_argument("--seed-demo", action="store_true")
    p.add_argument("--credentials")
    a = p.parse_args()
    if a.backup and Path(a.database).exists():
        if Path(a.backup).exists():
            p.error("backup already exists")
        with connection(a.database) as src, connection(a.backup) as dst:
            src.backup(dst)
    migrate(a.database)
    if a.seed_demo:
        if not a.credentials:
            p.error("--seed-demo requires --credentials (operator-only file)")
        if Path(a.credentials).exists():
            p.error("credentials file exists; choose a new path")
        result = seed_demo(a.database, a.credentials)
        print("Accounts added:", len(result["accounts_added"]))
    print("Migration complete (version 1); existing records preserved.")
