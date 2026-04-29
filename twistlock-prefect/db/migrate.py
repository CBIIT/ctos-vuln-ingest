"""
Apply db/migrate.sql against the database configured in .env (repo root).

Usage:
    uv run python twistlock-prefect/db/migrate.py
"""

from __future__ import annotations

import sys
from pathlib import Path

import psycopg2
from dotenv import dotenv_values

_REPO_ROOT = next(p for p in [Path.cwd(), *Path.cwd().parents] if (p / ".env").exists())
_SQL_FILE = Path(__file__).resolve().parent / "migrate.sql"


def main() -> None:
    env = dotenv_values(_REPO_ROOT / ".env")

    required = ["DB_HOST", "DB_NAME", "DB_USER", "DB_PASSWORD"]
    missing = [k for k in required if not env.get(k)]
    if missing:
        print(f"ERROR: missing from .env: {', '.join(missing)}", file=sys.stderr)
        sys.exit(1)

    conn = psycopg2.connect(
        host=env["DB_HOST"],
        port=int(env.get("DB_PORT", 5432)),
        dbname=env["DB_NAME"],
        user=env["DB_USER"],
        password=env["DB_PASSWORD"],
        connect_timeout=10,
    )

    sql = _SQL_FILE.read_text()

    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(sql)
        print(f"Migration applied successfully to {env['DB_NAME']} on {env['DB_HOST']}")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
