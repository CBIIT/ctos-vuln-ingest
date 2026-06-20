"""
Prefect flow: pull Twistlock (Prisma Cloud Compute) vulnerability scan data
and upsert it into PostgreSQL.

Credential loading strategy:
  - Prefect runtime (PREFECT_API_URL is set): read Prefect Variables to get
    AWS Secrets Manager ARNs, then call boto3 to retrieve the actual secrets.
    Variables used: twistlock-secret-arn, dev-vuln-secret-arn, prod-vuln-secret-arn
  - Local dev: load from .env via python-dotenv.
    DB_* vars are the dev DB; DB2_* vars are the prod DB.
"""

from __future__ import annotations

import json
import logging
import logging.config
import os
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

import boto3
import psycopg2
import requests
import urllib3
from dotenv import dotenv_values

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try:
    from prefect import flow, get_run_logger, task
    from prefect.artifacts import create_markdown_artifact, create_table_artifact
    from prefect.variables import Variable
except ImportError:
    # No-op stand-ins so the file can be imported without a Prefect installation.
    def flow(**kwargs):
        def decorator(fn):
            return fn
        return decorator

    def task(**kwargs):
        def decorator(fn):
            return fn
        return decorator

    def get_run_logger():
        return logging.getLogger(__name__)

    def create_table_artifact(**kwargs):
        pass

    def create_markdown_artifact(**kwargs):
        pass

    Variable = None

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
_stdlib_logger = logging.getLogger(__name__)


def _get_logger():
    """Return Prefect's run logger inside a flow/task, stdlib logger otherwise."""
    try:
        return get_run_logger()
    except Exception:
        return _stdlib_logger

# ---------------------------------------------------------------------------
# Credential / config loading
# ---------------------------------------------------------------------------

def _is_prefect_runtime() -> bool:
    """True when running inside a Prefect worker (PREFECT_API_URL is set)."""
    return bool(os.environ.get("PREFECT_API_URL"))


def _secret_from_aws(secret_arn: str) -> dict[str, Any]:
    """Fetch a secret JSON blob from AWS Secrets Manager by ARN."""
    client = boto3.client("secretsmanager")
    response = client.get_secret_value(SecretId=secret_arn)
    return json.loads(response["SecretString"])


def _db_target_from_secret(secret: dict[str, Any]) -> dict[str, Any]:
    """Map an AWS Secrets Manager secret dict to a db_target dict."""
    return {
        "db_host": secret["host"],
        "db_port": int(secret.get("port", 5432)),
        "db_name": secret["dbname"],
        "db_user": secret["username"],
        "db_password": secret["password"],
    }


def get_credentials() -> dict[str, Any]:
    """
    Return a unified credentials dict with db_targets — a list of two DB configs
    (dev and prod) that the flow writes to on every run.

    In Prefect runtime:
      Reads three Prefect Variables:
        - twistlock-secret-arn  → Twistlock API credentials + base_url
        - dev-vuln-secret-arn   → dev DB (primary; also used to read components)
        - prod-vuln-secret-arn  → prod DB

    Locally:
      Reads from .env:
        - TWISTLOCK_* vars for the API
        - DB_* vars for the dev DB
        - DB2_* vars for the prod DB
    """
    if _is_prefect_runtime():
        twistlock_arn = Variable.get("twistlock-secret-arn")
        dev_arn       = Variable.get("dev-vuln-secret-arn")
        prod_arn      = Variable.get("prod-vuln-secret-arn")

        tw_secret   = _secret_from_aws(twistlock_arn)
        dev_secret  = _secret_from_aws(dev_arn)
        prod_secret = _secret_from_aws(prod_arn)

        return {
            "twistlock_base_url": tw_secret["base_url"],
            "twistlock_username": tw_secret["username"],
            "twistlock_password": tw_secret["password"],
            "db_targets": [
                _db_target_from_secret(dev_secret),
                _db_target_from_secret(prod_secret),
            ],
        }
    else:
        _repo_root = next(
            p for p in [Path.cwd(), *Path.cwd().parents] if (p / ".env").exists()
        )
        env = dotenv_values(_repo_root / ".env")
        return {
            "twistlock_base_url": env["TWISTLOCK_BASE_URL"],
            "twistlock_username": env["TWISTLOCK_USERNAME"],
            "twistlock_password": env["TWISTLOCK_PASSWORD"],
            "db_targets": [
                {
                    "db_host": env["DB_HOST"],
                    "db_port": int(env.get("DB_PORT", 5432)),
                    "db_name": env["DB_NAME"],
                    "db_user": env["DB_USER"],
                    "db_password": env["DB_PASSWORD"],
                },
                {
                    "db_host": env["DB2_HOST"],
                    "db_port": int(env.get("DB2_PORT", 5432)),
                    "db_name": env["DB2_NAME"],
                    "db_user": env["DB2_USER"],
                    "db_password": env["DB2_PASSWORD"],
                },
            ],
        }


# ---------------------------------------------------------------------------
# Twistlock API helpers
# ---------------------------------------------------------------------------

_REGISTRY_COLLECTION = "CRDC+CCDI+All+Collection"
_REGISTRY_PROJECT    = "Central+Console"

# ECR registry hosting all application images
_ECR_REGISTRY_ID = "986019062625"
_ECR_REGION      = "us-east-1"

class TwistlockAuthError(Exception):
    pass


def _authenticate(creds: dict[str, Any]) -> str:
    """POST /api/v1/authenticate and return the bearer token."""
    url = f"{creds['twistlock_base_url'].rstrip('/')}/api/v1/authenticate"
    resp = requests.post(
        url,
        json={"username": creds["twistlock_username"], "password": creds["twistlock_password"]},
        timeout=30,
        verify=False,  # NCI internal CA — self-signed cert
    )
    if resp.status_code != 200:
        raise TwistlockAuthError(f"Auth failed: {resp.status_code} {resp.text}")
    return resp.json()["token"]


def _build_search_param(image_name: str, image_tag: str) -> str:
    """
    Encode imageName:imageTag the way Twistlock expects:
    dots escaped as %5C., colon double-encoded as %253A.
    Mirrors the TypeScript buildSearchParam() in twistlock-reporter.
    """
    from urllib.parse import quote
    raw = f"{image_name}:{image_tag}"
    encoded = quote(raw, safe="")
    return encoded.replace(".", "%5C.").replace("%3A", "%253A")


# ---------------------------------------------------------------------------
# Prefect tasks
# ---------------------------------------------------------------------------

@task(name="authenticate-twistlock", retries=2, retry_delay_seconds=10)
def authenticate_twistlock(creds: dict[str, Any]) -> str:
    """Obtain a Twistlock API bearer token."""
    _get_logger().info("Authenticating with Twistlock at %s", creds["twistlock_base_url"])
    token = _authenticate(creds)
    _get_logger().info("Twistlock authentication successful")
    return token


@task(name="fetch-components-from-db")
def fetch_components_from_db(creds: dict[str, Any]) -> list[dict[str, Any]]:
    """
    Read the component list from the dev DB (db_targets[0]).
    Returns rows as dicts with keys: id, project, image_name, current_tag.
    """
    target = creds["db_targets"][0]
    _get_logger().info("Fetching components from %s/%s", target["db_host"], target["db_name"])
    conn = _db_connect(target)
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id, project, image_name, current_tag FROM components ORDER BY id"
            )
            cols = [desc[0] for desc in cur.description]
            rows = [dict(zip(cols, row)) for row in cur.fetchall()]
        _get_logger().info("Fetched %d components from DB", len(rows))
        return rows
    finally:
        conn.close()


def _ecr_latest_prod_tag(image_name: str) -> str | None:
    """
    Query ECR for all tags on this repository that start with 'prod-' and return
    the one on the most recently pushed image (by imagePushedAt). Returns None if
    no prod- tagged image exists or the repository is not found.
    """
    ecr = boto3.client("ecr", region_name=_ECR_REGION)
    try:
        paginator = ecr.get_paginator("describe_images")
        pages = paginator.paginate(
            registryId=_ECR_REGISTRY_ID,
            repositoryName=image_name,
            filter={"tagStatus": "TAGGED"},
        )
        prod_images = []
        for page in pages:
            for detail in page.get("imageDetails", []):
                prod_tags = [t for t in detail.get("imageTags", []) if t.startswith("prod-")]
                if prod_tags:
                    # Use the first prod- tag found on this image digest
                    prod_images.append((detail["imagePushedAt"], prod_tags[0]))

        if not prod_images:
            return None

        prod_images.sort(key=lambda x: x[0], reverse=True)
        return prod_images[0][1]

    except ecr.exceptions.RepositoryNotFoundException:
        _get_logger().warning("[resolve-prod-tag] ECR repository not found: %s", image_name)
        return None
    except Exception as e:
        _get_logger().warning("[resolve-prod-tag] ECR lookup failed for %s: %s", image_name, e)
        return None


def _twistlock_has_tag(image_name: str, tag: str, token: str, base_url: str) -> bool:
    """
    Return True if Twistlock has a scan result for image_name:tag.
    Used to gate ECR-resolved tags — we only update if Twistlock has scanned it.
    """
    from urllib.parse import quote
    headers = {"Authorization": f"Bearer {token}"}
    search = quote(f"{image_name}:{tag}", safe="").replace(".", "%5C.").replace("%3A", "%253A")
    url = (
        f"{base_url.rstrip('/')}/api/v1/registry"
        f"?collections={_REGISTRY_COLLECTION}&compact=true&limit=5&offset=0"
        f"&project={_REGISTRY_PROJECT}&search={search}"
    )
    resp = requests.get(url, headers=headers, timeout=30, verify=False)
    if resp.status_code != 200:
        return False
    results = resp.json() or []
    return any(
        r.get("repoTag", {}).get("repo") == image_name
        and r.get("repoTag", {}).get("tag") == tag
        for r in results
    )


@task(name="resolve-prod-tag", retries=1, retry_delay_seconds=5)
def resolve_prod_tag(
    token: str,
    image_name: str,
    base_url: str,
) -> str | None:
    """
    Resolve the latest prod- tag for an image using ECR as the source of truth
    (sorted by imagePushedAt), then validate it exists in Twistlock before returning.
    Falls back to None if ECR has no prod- tag or Twistlock hasn't scanned it yet.
    """
    ecr_tag = _ecr_latest_prod_tag(image_name)
    if not ecr_tag:
        _get_logger().info("[resolve-prod-tag] No prod- tag found in ECR for %s", image_name)
        return None

    _get_logger().info("[resolve-prod-tag] ECR latest prod tag for %s: %s — checking Twistlock", image_name, ecr_tag)

    if not _twistlock_has_tag(image_name, ecr_tag, token, base_url):
        _get_logger().warning(
            "[resolve-prod-tag] %s:%s not yet scanned in Twistlock — skipping update",
            image_name, ecr_tag,
        )
        return None

    _get_logger().info("[resolve-prod-tag] Confirmed %s:%s in Twistlock", image_name, ecr_tag)
    return ecr_tag


@task(name="update-component-tag")
def update_component_tag(
    creds: dict[str, Any],
    component: dict[str, Any],
    new_tag: str,
) -> None:
    """
    Update components.current_tag to new_tag across all DB targets.
    Archives the old tag in components_history first.
    """
    for db_target in creds["db_targets"]:
        conn = _db_connect(db_target)
        try:
            with conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        INSERT INTO components_history (component_id, old_tag)
                        VALUES (%s, %s)
                        """,
                        (component["id"], component["current_tag"]),
                    )
                    cur.execute(
                        """
                        UPDATE components SET current_tag = %s WHERE id = %s
                        """,
                        (new_tag, component["id"]),
                    )
            _get_logger().info(
                "[%s] Updated %s tag: %s → %s on %s",
                component["project"],
                component["image_name"],
                component["current_tag"],
                new_tag,
                db_target["db_host"],
            )
        finally:
            conn.close()


@task(name="pull-scan-data", retries=1, retry_delay_seconds=5)
def pull_scan_data(
    token: str,
    component: dict[str, Any],
    creds: dict[str, Any],
) -> list[dict[str, Any]] | None:
    """
    Single-call Twistlock lookup:
      GET /api/v1/registry with compact=false and search=image:tag
      Returns full scan data including vulnerabilities in one request,
      and correctly filters to the exact tag (unlike v34.03/registry which paginates).

    Re-authenticates once on 401 (token expiry).
    Returns the flat list of vulnerability dicts, or None if no data found.
    """
    base = creds["twistlock_base_url"].rstrip("/")
    image_name = component["image_name"]
    image_tag  = component["current_tag"]
    headers    = {"Authorization": f"Bearer {token}"}

    search = _build_search_param(image_name, image_tag)
    url = (
        f"{base}/api/v1/registry"
        f"?collections={_REGISTRY_COLLECTION}&compact=false&limit=1&offset=0"
        f"&project={_REGISTRY_PROJECT}&reverse=true&search={search}&sort=vulnerabilityRiskScore"
    )

    _get_logger().info("[%s] Pulling scan data for %s:%s", component["project"], image_name, image_tag)
    resp = requests.get(url, headers=headers, timeout=60, verify=False)

    # Re-auth once on token expiry
    if resp.status_code == 401:
        _get_logger().warning("[%s] Got 401 for %s; re-authenticating", component["project"], image_name)
        token = _authenticate(creds)
        headers["Authorization"] = f"Bearer {token}"
        resp = requests.get(url, headers=headers, timeout=60, verify=False)

    if resp.status_code != 200:
        _get_logger().error("[%s] Twistlock API error for %s: HTTP %s", component["project"], image_name, resp.status_code)
        return None

    results = resp.json() or []
    match = next(
        (r for r in results
         if r.get("repoTag", {}).get("repo") == image_name
         and r.get("repoTag", {}).get("tag") == image_tag),
        None,
    )
    if not match:
        _get_logger().warning("[%s] No scan result matched %s:%s in Twistlock response", component["project"], image_name, image_tag)
        return None

    vulns = match.get("vulnerabilities") or []
    if not vulns:
        _get_logger().warning("[%s] No vulnerabilities found in scan for %s:%s", component["project"], image_name, image_tag)
        return None

    # Attach image metadata to each vuln for DB insertion
    for v in vulns:
        v["_image_id"]   = match.get("_id", "")
        v["_image_name"] = image_name

    _get_logger().info("[%s] Found %d vulnerabilities for %s:%s", component["project"], len(vulns), image_name, image_tag)
    return vulns


@task(name="insert-scan")
def insert_scan(
    creds: dict[str, Any],
    component: dict[str, Any],
    vulns: list[dict[str, Any]],
) -> None:
    """
    Write scan data to all DB targets. Each target receives:
      - a new scans row + vulnerability rows (append-only, intentional)
      - upserts into project_image_mapping and image_tag_mapping
    Fails the flow if any DB write fails.
    """
    for db_target in creds["db_targets"]:
        _get_logger().info(
            "[%s] Writing scan for %s:%s to %s/%s",
            component["project"],
            component["image_name"],
            component["current_tag"],
            db_target["db_host"],
            db_target["db_name"],
        )
        conn = _db_connect(db_target)
        try:
            _write_scan_to_db(conn, component, vulns)
            _get_logger().info(
                "[%s] Successfully wrote %d vulns for %s to %s/%s",
                component["project"],
                len(vulns),
                component["image_name"],
                db_target["db_host"],
                db_target["db_name"],
            )
        finally:
            conn.close()


# ---------------------------------------------------------------------------
# DB helpers
# ---------------------------------------------------------------------------

def _db_connect(db_target: dict[str, Any]):
    """Open and return a psycopg2 connection from a db_target dict."""
    return psycopg2.connect(
        host=db_target["db_host"],
        port=db_target["db_port"],
        dbname=db_target["db_name"],
        user=db_target["db_user"],
        password=db_target["db_password"],
        connect_timeout=10,
    )


def _write_scan_to_db(
    conn,
    component: dict[str, Any],
    vulns: list[dict[str, Any]],
) -> None:
    """
    Write one component's scan results to a single DB connection in one transaction:
      1. Insert scans row
      2. Bulk-insert vulnerabilities rows
      3. Upsert project_image_mapping
      4. Upsert image_tag_mapping
    """
    scan_week = _current_iso_week()
    with conn:
        with conn.cursor() as cur:
            # 1. Insert scan record
            cur.execute(
                """
                INSERT INTO scans (component_id, week, scanned_at, vuln_count, scanned_tag)
                VALUES (%s, %s, %s, %s, %s)
                RETURNING id
                """,
                (
                    component["id"],
                    scan_week,
                    datetime.now(timezone.utc),
                    len(vulns),
                    component["current_tag"],
                ),
            )
            scan_id = cur.fetchone()[0]

            # 2. Bulk-insert vulnerabilities
            for v in vulns:
                cur.execute(
                    """
                    INSERT INTO vulnerabilities (
                        scan_id, cve_id, severity, package_name, package_version,
                        fix_status, cvss, description, image_id, image_name
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        scan_id,
                        v.get("cve"),
                        v.get("severity"),
                        v.get("packageName"),
                        v.get("packageVersion"),
                        v.get("status"),
                        v.get("cvss"),
                        v.get("description"),
                        v.get("_image_id"),
                        v.get("_image_name"),
                    ),
                )

            # 3. Upsert project_image_mapping
            cur.execute(
                """
                INSERT INTO project_image_mapping (project, image_name)
                VALUES (%s, %s)
                ON CONFLICT (project, image_name) DO UPDATE SET project = EXCLUDED.project
                RETURNING id
                """,
                (component["project"], component["image_name"]),
            )
            pim_id = cur.fetchone()[0]

            # 4. Upsert image_tag_mapping — is_prod only when tag starts with "prod-"
            is_prod = component["current_tag"].startswith("prod-")
            cur.execute(
                """
                INSERT INTO image_tag_mapping (project_image_mapping_id, image_name, current_tag, is_prod)
                VALUES (%s, %s, %s, %s)
                ON CONFLICT (project_image_mapping_id, current_tag) DO NOTHING
                """,
                (pim_id, component["image_name"], component["current_tag"], is_prod),
            )

    _get_logger().info(
        "Inserted scan %s for component %s (week %s, %d vulns)",
        scan_id,
        component["image_name"],
        scan_week,
        len(vulns),
    )


def _current_iso_week() -> str:
    """Return the ISO week string for today, e.g. '2025-W04'."""
    today = date.today()
    year, week, _ = today.isocalendar()
    return f"{year}-W{week:02d}"


# ---------------------------------------------------------------------------
# Flow
# ---------------------------------------------------------------------------

@flow(name="twistlock-vuln-pull", log_prints=True)
def twistlock_vuln_pull() -> None:
    """
    Daily flow: authenticate with Twistlock, auto-resolve prod- tags for each
    component, update the DB if a newer prod tag is found, pull scan data,
    and write into all DB targets.
    """
    creds = get_credentials()
    token = authenticate_twistlock(creds)
    components = fetch_components_from_db(creds)

    if not components:
        _get_logger().warning("No components found in DB — nothing to scan")
        return

    db_hosts = [t["db_host"] for t in creds["db_targets"]]
    _get_logger().info(
        "Starting scan for %d components across %d DB target(s): %s",
        len(components),
        len(db_hosts),
        ", ".join(db_hosts),
    )

    skipped, written, tag_updates = 0, 0, 0
    base_url = creds["twistlock_base_url"]
    summary_rows = []

    for component in components:
        # Attempt to resolve a prod- tag from Twistlock before scanning
        image_name = component["image_name"]
        old_tag = component["current_tag"]
        resolved_tag = resolve_prod_tag.with_options(name=f"resolve-prod-tag/{image_name}")(token, image_name, base_url)
        tag_changed = False
        if resolved_tag and resolved_tag != old_tag:
            _get_logger().info(
                "[%s] Updating tag for %s: %s → %s",
                component["project"],
                image_name,
                old_tag,
                resolved_tag,
            )
            update_component_tag.with_options(name=f"update-component-tag/{image_name}")(creds, component, resolved_tag)
            component = {**component, "current_tag": resolved_tag}
            tag_updates += 1
            tag_changed = True

        vulns = pull_scan_data.with_options(name=f"pull-scan-data/{image_name}")(token, component, creds)

        if vulns:
            insert_scan.with_options(name=f"insert-scan/{image_name}")(creds, component, vulns)
            written += 1
            summary_rows.append({
                "project": component["project"],
                "image": image_name,
                "tag": component["current_tag"],
                "tag_updated": f"yes → {old_tag}" if tag_changed else "no",
                "vulns_written": len(vulns),
            })
        else:
            _get_logger().warning(
                "[%s] Skipping %s (id=%s): no scan data from Twistlock",
                component["project"],
                component["image_name"],
                component["id"],
            )
            skipped += 1
            summary_rows.append({
                "project": component["project"],
                "image": image_name,
                "tag": component["current_tag"],
                "tag_updated": f"yes → {old_tag}" if tag_changed else "no",
                "vulns_written": "skipped",
            })

    run_date = date.today().isoformat()
    create_table_artifact(
        key="scan-summary",
        table=summary_rows,
        description=f"Vulnerability scan summary for {run_date} (week {_current_iso_week()})",
    )
    create_markdown_artifact(
        key="scan-stats",
        markdown=f"""## Scan run: {run_date}

| Metric | Value |
|---|---|
| Week | {_current_iso_week()} |
| Components scanned | {written} |
| Components skipped | {skipped} |
| Tags auto-updated | {tag_updates} |
| Total components | {len(components)} |
""",
    )

    _get_logger().info(
        "twistlock_vuln_pull complete for week %s — %d written, %d skipped, %d tag(s) updated",
        _current_iso_week(),
        written,
        skipped,
        tag_updates,
    )


# ---------------------------------------------------------------------------
# Local entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # Run locally with: uv run python flows/twistlock_vuln_pull.py
    # No Prefect server needed — decorators are no-ops when PREFECT_API_URL is unset.
    twistlock_vuln_pull()
