"""
Seed the components table from projects.config.json (repo root).

Existing rows are left untouched (INSERT ... ON CONFLICT DO NOTHING).
Safe to re-run — already-loaded components are simply skipped.

Usage:
    uv run python twistlock-prefect/db/seed.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import psycopg2
from dotenv import dotenv_values

_REPO_ROOT = next(p for p in [Path.cwd(), *Path.cwd().parents] if (p / ".env").exists())
_CONFIG_FILE = _REPO_ROOT / "projects.config.json"


def main() -> None:
    env = dotenv_values(_REPO_ROOT / ".env")

    required = ["DB_HOST", "DB_NAME", "DB_USER", "DB_PASSWORD"]
    missing = [k for k in required if not env.get(k)]
    if missing:
        print(f"ERROR: missing from .env: {', '.join(missing)}", file=sys.stderr)
        sys.exit(1)

    config = json.loads(_CONFIG_FILE.read_text())

    rows = [
        (project["project"], component["image_name"], component["current_tag"])
        for project in config
        for component in project["components"]
    ]

    conn = psycopg2.connect(
        host=env["DB_HOST"],
        port=int(env.get("DB_PORT", 5432)),
        dbname=env["DB_NAME"],
        user=env["DB_USER"],
        password=env["DB_PASSWORD"],
        connect_timeout=10,
    )

    inserted = 0
    skipped = 0

    try:
        with conn:
            with conn.cursor() as cur:
                for project, image_name, current_tag in rows:
                    cur.execute(
                        """
                        INSERT INTO components (project, image_name, current_tag)
                        VALUES (%s, %s, %s)
                        ON CONFLICT (project, image_name) DO NOTHING
                        """,
                        (project, image_name, current_tag),
                    )
                    if cur.rowcount == 1:
                        inserted += 1
                    else:
                        skipped += 1
        print(f"Seed complete: {inserted} inserted, {skipped} skipped ({env['DB_NAME']} on {env['DB_HOST']})")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
