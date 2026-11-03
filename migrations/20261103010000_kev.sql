-- CISA Known Exploited Vulnerabilities catalog, one row per CVE
CREATE TABLE kev_entries (
    cve_id           TEXT PRIMARY KEY,
    vendor_project   TEXT NOT NULL,
    product          TEXT NOT NULL,
    name             TEXT NOT NULL,
    -- Date CISA added the CVE to the catalog
    date_added       DATE NOT NULL,
    known_ransomware BOOLEAN NOT NULL,
    -- Entry exactly as published, so fields added by CISA later are kept
    data             JSONB NOT NULL,
    -- When Tocsin first saw the entry: drives "new KEV entry" alerts
    first_seen_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- State of the catalog sync (single row)
CREATE TABLE kev_sync (
    id              BOOLEAN PRIMARY KEY DEFAULT true CHECK (id),
    catalog_version TEXT,
    -- Validators of the last downloaded feed, for conditional requests
    -- (cisa.gov honors If-Modified-Since but ignores If-None-Match)
    etag            TEXT,
    last_modified   TEXT,
    -- Last successful check, whether or not the catalog changed
    checked_at      TIMESTAMPTZ,
    -- Error of the last attempt; NULL when it succeeded
    last_error      TEXT,
    last_attempt_at TIMESTAMPTZ
);

INSERT INTO kev_sync DEFAULT VALUES;
