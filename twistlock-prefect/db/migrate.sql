-- Idempotent schema migration for the Twistlock vulnerability ingest pipeline.
-- Safe to run multiple times: all statements use IF NOT EXISTS.

CREATE TABLE IF NOT EXISTS components (
    id          SERIAL      PRIMARY KEY,
    project     TEXT        NOT NULL,
    image_name  TEXT        NOT NULL,
    current_tag TEXT        NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (project, image_name)
);

CREATE TABLE IF NOT EXISTS scans (
    id           SERIAL      PRIMARY KEY,
    component_id INTEGER     NOT NULL REFERENCES components(id) ON DELETE CASCADE,
    week         TEXT        NOT NULL,  -- ISO week, e.g. '2025-W04'
    scanned_at   TIMESTAMPTZ NOT NULL,
    vuln_count   INTEGER     NOT NULL,
    scanned_tag  TEXT
);

-- Drop unique constraint if it exists from a prior migration (allow multiple runs per week)
ALTER TABLE scans DROP CONSTRAINT IF EXISTS scans_component_id_week_key;
-- Add scanned_tag to existing DBs (idempotent)
ALTER TABLE scans ADD COLUMN IF NOT EXISTS scanned_tag TEXT;

CREATE INDEX IF NOT EXISTS idx_scans_component_week
    ON scans (component_id, week);

CREATE TABLE IF NOT EXISTS vulnerabilities (
    id              SERIAL  PRIMARY KEY,
    scan_id         INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    cve_id          TEXT,
    severity        TEXT,
    package_name    TEXT,
    package_version TEXT,
    fix_status      TEXT,
    cvss            NUMERIC,
    description     TEXT,
    image_id        TEXT,
    image_name      TEXT
);

CREATE INDEX IF NOT EXISTS idx_vulnerabilities_scan_id
    ON vulnerabilities (scan_id);

CREATE INDEX IF NOT EXISTS idx_vulnerabilities_cve_id
    ON vulnerabilities (cve_id);

CREATE TABLE IF NOT EXISTS project_image_mapping (
    id         SERIAL      PRIMARY KEY,
    project    TEXT        NOT NULL,
    image_name TEXT        NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (project, image_name)
);

CREATE TABLE IF NOT EXISTS image_tag_mapping (
    id                       SERIAL      PRIMARY KEY,
    project_image_mapping_id INTEGER     NOT NULL REFERENCES project_image_mapping(id) ON DELETE CASCADE,
    image_name               TEXT        NOT NULL,
    current_tag              TEXT        NOT NULL,
    is_prod                  BOOLEAN     NOT NULL DEFAULT false,
    created_at               TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (project_image_mapping_id, current_tag)
);
