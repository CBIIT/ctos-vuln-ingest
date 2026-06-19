# twistlock-vuln-reporter

Prefect flow that pulls vulnerability scan data from Twistlock (Prisma Cloud Compute) daily and inserts it into PostgreSQL.

## How it works

1. **Authenticate** — obtains a bearer token from the Twistlock API.
2. **Fetch components** — reads the `components` table in PostgreSQL to get the list of images to scan (`project`, `image_name`, `current_tag`).
3. **Resolve prod tag** — for each component, queries Twistlock for all scanned tags of that image and selects the most recent one prefixed with `prod-`. If found and different from the stored tag, the `components` table is updated and the old tag is archived to `components_history` before scanning proceeds. If no `prod-` tag is found in Twistlock, the existing `current_tag` is used as-is.
4. **Pull scan data** — calls `GET /api/v1/registry` for each component and extracts the vulnerabilities array.
5. **Insert** — writes a new row to `scans` (recording the component, ISO week, timestamp, and scanned tag) and inserts the linked rows in `vulnerabilities`. Every run is stored independently — multiple runs per day are all kept.

Components with no Twistlock scan data are skipped with a warning; the flow continues and does not fail.

## Credential loading

| Context | Source |
|---|---|
| **Local dev** | `.env` at repo root (loaded via `python-dotenv`) |
| **Prefect runtime** | Prefect Variables → AWS Secrets Manager |

The flow detects context by checking whether `PREFECT_API_URL` is set in the environment.

### Prefect Variables (store ARNs, not secrets)

| Variable name | Contains |
|---|---|
| `twistlock-secret-arn` | ARN of the Secrets Manager secret with `username`, `password`, `base_url` |
| `dev-vuln-secret-arn` | ARN of the Secrets Manager secret for the dev DB (`host`, `port`, `dbname`, `username`, `password`) |
| `prod-vuln-secret-arn` | ARN of the Secrets Manager secret for the prod DB (`host`, `port`, `dbname`, `username`, `password`) |

The secrets themselves are fetched from AWS Secrets Manager at flow runtime via `boto3` — no secret values are stored in Prefect. The flow reads components from the dev DB and writes scan results to both dev and prod DBs on every run.

## Local development

### Prerequisites

- Python 3.13+
- [`uv`](https://github.com/astral-sh/uv)
- Docker (for local Postgres) or a reachable PostgreSQL instance
- Network access to the Twistlock console

### Setup

```bash
# 1. Copy env file — defaults already match the Docker Compose database
cp .env.example .env
# Fill in TWISTLOCK_BASE_URL / credentials; DB values work as-is with Docker

# 2. Install Python dependencies
cd twistlock-prefect
uv sync
```

### Start a local Postgres instance

```bash
# From repo root — starts Postgres 16 on localhost:5432
docker compose up -d
```

The container reads `DB_NAME`, `DB_USER`, and `DB_PASSWORD` from your `.env` (defaulting to `vuln_ingest` / `vuln_user` / `vuln_pass` if not set).

### Apply the database schema

Run once after the container is up (safe to re-run — all statements use `IF NOT EXISTS`):

```bash
# From repo root
uv run python twistlock-prefect/db/migrate.py
```

This executes [twistlock-prefect/db/migrate.sql](twistlock-prefect/db/migrate.sql), which creates all tables plus their indexes.

### Seed the components table

Load the initial component list from `projects.config.json` into the DB:

```bash
uv run python twistlock-prefect/db/seed.py
```

Safe to re-run — existing rows are skipped (`ON CONFLICT DO NOTHING`). The script prints how many rows were inserted vs skipped.

### Run the flow

```bash
# From repo root
uv run python twistlock-prefect/flows/twistlock_vuln_pull.py
```

Or from inside `twistlock-prefect/`:

```bash
uv run python flows/twistlock_vuln_pull.py
```

### Lint

```bash
uv run ruff check flows/
```

## Deployment

The flow is deployed via `prefect.yaml` in this directory.

```bash
# From repo root or twistlock-prefect/
prefect deploy --all
```

Deployment config:

| Setting | Value |
|---|---|
| Name | `twistlock-daily-pull` |
| Schedule | Daily at 10:00 UTC (06:00 ET) |
| Work pool | `ccdi-dcc-8gb-prefect-3.4.19-python3.13` |
| Pull step | Git clone `ctos-vuln-ingest` + `pip install -r requirements.txt` |

> **Note:** If upgrading from the previous weekly deployment (`twistlock-weekly-pull`), delete the old deployment from the Prefect UI after deploying to avoid duplicate runs.

## Project layout

```
.env.example                          # Template — copy to .env at repo root
docker-compose.yml                    # Local Postgres 16 container
twistlock-prefect/
├── prefect.yaml                      # Deployment definition
├── requirements.txt                  # Dependencies installed by the Prefect worker
├── pyproject.toml                    # Local uv dev setup
├── db/
│   ├── migrate.sql                   # Idempotent DDL for all three tables
│   ├── migrate.py                    # Runner: applies migrate.sql via .env creds
│   └── seed.py                       # Loads projects.config.json into components table
└── flows/
    └── twistlock_vuln_pull.py        # Flow + tasks
```

## Database schema

Full DDL is in [twistlock-prefect/db/migrate.sql](twistlock-prefect/db/migrate.sql).

### `components`
| Column | Type | Description |
|---|---|---|
| `id` | SERIAL | Primary key |
| `project` | TEXT | Project name |
| `image_name` | TEXT | Container image name |
| `current_tag` | TEXT | Current image tag (mutable — auto-updated to the latest `prod-*` tag found in Twistlock) |
| `created_at` | TIMESTAMPTZ | Row creation timestamp |

### `components_history`
| Column | Type | Description |
|---|---|---|
| `id` | SERIAL | Primary key |
| `component_id` | INTEGER | FK → `components.id` |
| `old_tag` | TEXT | Tag value before it was updated |
| `archived_at` | TIMESTAMPTZ | When the tag was superseded |

### `scans`
| Column | Type | Description |
|---|---|---|
| `id` | SERIAL | Primary key |
| `component_id` | INTEGER | FK → `components.id` |
| `week` | TEXT | ISO week string, e.g. `2025-W04` |
| `scanned_at` | TIMESTAMPTZ | Exact timestamp of the scan run |
| `vuln_count` | INTEGER | Number of vulnerabilities found |
| `scanned_tag` | TEXT | Image tag that was actually scanned (snapshot — unaffected by future tag changes) |

### `vulnerabilities`
| Column | Type | Description |
|---|---|---|
| `id` | SERIAL | Primary key |
| `scan_id` | INTEGER | FK → `scans.id` |
| `cve_id` | TEXT | CVE identifier |
| `severity` | TEXT | Severity level (e.g. `critical`, `high`) |
| `package_name` | TEXT | Affected package |
| `package_version` | TEXT | Affected package version |
| `fix_status` | TEXT | Fix availability status |
| `cvss` | NUMERIC | CVSS score |
| `description` | TEXT | CVE description |
| `image_id` | TEXT | Twistlock internal image ID |
| `image_name` | TEXT | Image name (denormalized from scan) |

### `project_image_mapping`
| Column | Type | Description |
|---|---|---|
| `id` | SERIAL | Primary key |
| `project` | TEXT | Project name |
| `image_name` | TEXT | Container image name |
| `created_at` | TIMESTAMPTZ | Row creation timestamp |

### `image_tag_mapping`
| Column | Type | Description |
|---|---|---|
| `id` | SERIAL | Primary key |
| `project_image_mapping_id` | INTEGER | FK → `project_image_mapping.id` |
| `image_name` | TEXT | Container image name |
| `current_tag` | TEXT | Tag that was scanned |
| `is_prod` | BOOLEAN | `true` only when the tag starts with `prod-` |
| `created_at` | TIMESTAMPTZ | Row creation timestamp |
