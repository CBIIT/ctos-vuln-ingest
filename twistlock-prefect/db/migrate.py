"""
Apply db/migrate.sql against both database instances configured in .env (repo root).

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


def _db_targets(env: dict) -> list[dict]:
    required_1 = ["DB_HOST", "DB_NAME", "DB_USER", "DB_PASSWORD"]
    required_2 = ["DB2_HOST", "DB2_NAME", "DB2_USER", "DB2_PASSWORD"]

    missing = [k for k in required_1 if not env.get(k)]
    if missing:
        print(f"ERROR: missing from .env: {', '.join(missing)}", file=sys.stderr)
        sys.exit(1)

    targets = [
        {
            "host": env["DB_HOST"],
            "port": int(env.get("DB_PORT", 5432)),
            "dbname": env["DB_NAME"],
            "user": env["DB_USER"],
            "password": env["DB_PASSWORD"],
        }
    ]

    missing2 = [k for k in required_2 if not env.get(k)]
    if missing2:
        print(f"WARNING: second DB not configured ({', '.join(missing2)} missing) — skipping", file=sys.stderr)
    else:
        targets.append(
            {
                "host": env["DB2_HOST"],
                "port": int(env.get("DB2_PORT", 5432)),
                "dbname": env["DB2_NAME"],
                "user": env["DB2_USER"],
                "password": env["DB2_PASSWORD"],
            }
        )

    return targets


def main() -> None:
    env = dotenv_values(_REPO_ROOT / ".env")
    targets = _db_targets(env)
    sql = _SQL_FILE.read_text()

    for target in targets:
        conn = psycopg2.connect(**target, connect_timeout=10)
        try:
            with conn:
                with conn.cursor() as cur:
                    cur.execute(sql)
            print(f"Migration applied successfully to {target['dbname']} on {target['host']}")
        finally:
            conn.close()


if __name__ == "__main__":
    main()
