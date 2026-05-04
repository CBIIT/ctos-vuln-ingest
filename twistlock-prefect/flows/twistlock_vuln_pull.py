"""
Prefect flow: pull Twistlock (Prisma Cloud Compute) vulnerability scan data
and upsert it into PostgreSQL.

Credential loading strategy:
  - Prefect runtime (PREFECT_API_URL is set): read Prefect Variables to get
    AWS Secrets Manager ARNs, then call boto3 to retrieve the actual secrets.
  - Local dev: load from .env via python-dotenv.
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

# Prefect imports are only needed when running inside a Prefect worker.
# Importing them locally would require a running Prefect server.
if os.environ.get("PREFECT_API_URL"):
    from prefect import flow, get_run_logger, task
    from prefect.variables import Variable
else:
    # Provide no-op stand-ins so the decorators are harmless locally.
    # Both @flow and @task are always called with keyword args here,
    # so they always receive zero positional args — just return the decorator.
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

    Variable = None  # never accessed outside Prefect runtime

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
logger = logging.getLogger(__name__)

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


def get_credentials() -> dict[str, Any]:
    """
    Return a unified credentials dict.

    In Prefect runtime:
      1. Read TWISTLOCK_SECRET_ARN and DB_SECRET_ARN from Prefect Variables
         (those Variables store the ARN string, not the secret itself).
      2. Fetch the actual secrets from AWS Secrets Manager at runtime.
         The Twistlock secret contains username, password, and base_url.

    Locally:
      Load everything from .env.
    """
    if _is_prefect_runtime():
        # --- Prefect / AWS path ---
        # base_url is stored in the Twistlock secret alongside credentials
        twistlock_arn = Variable.get("twistlock-secret-arn")
        db_arn = Variable.get("db-secret-arn")

        tw_secret = _secret_from_aws(twistlock_arn)
        db_secret = _secret_from_aws(db_arn)

        return {
            "twistlock_base_url": tw_secret["base_url"],
            "twistlock_username": tw_secret["username"],
            "twistlock_password": tw_secret["password"],
            "db_host": db_secret["host"],
            "db_port": int(db_secret.get("port", 5432)),
            "db_name": db_secret["dbname"],
            "db_user": db_secret["username"],
            "db_password": db_secret["password"],
        }
    else:
        # --- Local .env path ---
        # Walk up from cwd until we find the .env file
        _repo_root = next(
            p for p in [Path.cwd(), *Path.cwd().parents] if (p / ".env").exists()
        )
        env = dotenv_values(_repo_root / ".env")
        return {
            "twistlock_base_url": env["TWISTLOCK_BASE_URL"],
            "twistlock_username": env["TWISTLOCK_USERNAME"],
            "twistlock_password": env["TWISTLOCK_PASSWORD"],
            "db_host": env["DB_HOST"],
            "db_port": int(env.get("DB_PORT", 5432)),
            "db_name": env["DB_NAME"],
            "db_user": env["DB_USER"],
            "db_password": env["DB_PASSWORD"],
        }


# ---------------------------------------------------------------------------
# Twistlock API helpers
# ---------------------------------------------------------------------------

_REGISTRY_COLLECTION = "CRDC+CCDI+All+Collection"
_REGISTRY_PROJECT    = "Central+Console"

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


def _resolve_registry(base: str, image_name: str, image_tag: str, headers: dict) -> str | None:
    """
    GET /api/v1/registry to find the registry host for an image:tag.
    Returns the registry string (e.g. 986019062625.dkr.ecr.us-east-1.amazonaws.com)
    or None if not found.
    """
    search = _build_search_param(image_name, image_tag)
    url = (
        f"{base}/api/v1/registry"
        f"?collections={_REGISTRY_COLLECTION}&compact=true&limit=17&offset=0"
        f"&project={_REGISTRY_PROJECT}&reverse=true&search={search}&sort=vulnerabilityRiskScore"
    )
    resp = requests.get(url, headers=headers, timeout=60, verify=False)
    if resp.status_code != 200 or resp.text.strip() in ("null", ""):
        return None
    items = resp.json() or []
    match = next(
        (i for i in items
         if i.get("repoTag", {}).get("repo") == image_name
         and i.get("repoTag", {}).get("tag") == image_tag),
        None,
    )
    return match["repoTag"]["registry"] if match else None


# ---------------------------------------------------------------------------
# Prefect tasks (decorators are no-ops when running locally as a plain script)
# ---------------------------------------------------------------------------

@task(name="authenticate-twistlock", retries=2, retry_delay_seconds=10)
def authenticate_twistlock(creds: dict[str, Any]) -> str:
    """Obtain a Twistlock API bearer token."""
    logger.info("Authenticating with Twistlock at %s", creds["twistlock_base_url"])
    token = _authenticate(creds)
    logger.info("Twistlock authentication successful")
    return token


@task(name="fetch-components-from-db")
def fetch_components_from_db(creds: dict[str, Any]) -> list[dict[str, Any]]:
    """
    Read the component list from the components table.
    Returns rows as dicts with keys: id, project, image_name, current_tag.
    """
    conn = _db_connect(creds)
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id, project, image_name, current_tag FROM components ORDER BY id"
            )
            cols = [desc[0] for desc in cur.description]
            rows = [dict(zip(cols, row)) for row in cur.fetchall()]
        logger.info("Fetched %d components from DB", len(rows))
        return rows
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

    resp = requests.get(url, headers=headers, timeout=60, verify=False)

    # Re-auth once on token expiry
    if resp.status_code == 401:
        logger.warning("Got 401 for %s; re-authenticating", image_name)
        token = _authenticate(creds)
        headers["Authorization"] = f"Bearer {token}"
        resp = requests.get(url, headers=headers, timeout=60, verify=False)

    if resp.status_code != 200:
        logger.error("Twistlock API error for %s: %s %s", image_name, resp.status_code, resp.text)
        return None

    results = resp.json() or []
    match = next(
        (r for r in results
         if r.get("repoTag", {}).get("repo") == image_name
         and r.get("repoTag", {}).get("tag") == image_tag),
        None,
    )
    if not match:
        logger.warning("No scan result matched %s:%s in response", image_name, image_tag)
        return None

    vulns = match.get("vulnerabilities") or []
    if not vulns:
        logger.warning("No vulnerabilities in scan for %s:%s", image_name, image_tag)
        return None

    # Attach image metadata to each vuln for DB insertion
    for v in vulns:
        v["_image_id"]   = match.get("_id", "")
        v["_image_name"] = image_name

    logger.info("Fetched %d vulnerabilities for %s", len(vulns), image_name)
    return vulns


@task(name="insert-scan")
def insert_scan(
    creds: dict[str, Any],
    component: dict[str, Any],
    vulns: list[dict[str, Any]],
) -> None:
    """
    Insert a new scan record (scans table) and linked vulnerability rows.
    Every run is stored independently — multiple runs in the same week are all kept.
    """
    scan_week = _current_iso_week()
    conn = _db_connect(creds)
    try:
        with conn:
            with conn.cursor() as cur:
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

                # Bulk-insert vulnerabilities
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
        logger.info(
            "Inserted scan %s for component %s (week %s, %d vulns)",
            scan_id,
            component["image_name"],
            scan_week,
            len(vulns),
        )
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# DB helpers
# ---------------------------------------------------------------------------

def _db_connect(creds: dict[str, Any]):
    """Open and return a psycopg2 connection."""
    return psycopg2.connect(
        host=creds["db_host"],
        port=creds["db_port"],
        dbname=creds["db_name"],
        user=creds["db_user"],
        password=creds["db_password"],
        connect_timeout=10,
    )


def _current_iso_week() -> str:
    """Return the ISO week string for today, e.g. '2025-W04'."""
    today = date.today()
    year, week, _ = today.isocalendar()
    return f"{year}-W{week:02d}"


# ---------------------------------------------------------------------------
# Flow (decorator is a no-op locally)
# ---------------------------------------------------------------------------

@flow(name="twistlock-vuln-pull", log_prints=True)
def twistlock_vuln_pull() -> None:
    """
    Weekly flow: authenticate with Twistlock, iterate over all components,
    pull scan data, and upsert into PostgreSQL.
    """
    creds = get_credentials()
    token = authenticate_twistlock(creds)
    components = fetch_components_from_db(creds)

    if not components:
        logger.warning("No components found in DB — nothing to scan")
        return

    for component in components:
        vulns = pull_scan_data(token, component, creds)

        if vulns:
            insert_scan(creds, component, vulns)
        else:
            logger.warning(
                "Skipping component '%s' (id=%s): no scan data from Twistlock",
                component["image_name"],
                component["id"],
            )

    logger.info("twistlock_vuln_pull complete for week %s", _current_iso_week())


# ---------------------------------------------------------------------------
# Local entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # Run locally with: uv run python flows/twistlock_vuln_pull.py
    # No Prefect server needed — decorators are no-ops when PREFECT_API_URL is unset.
    twistlock_vuln_pull()
