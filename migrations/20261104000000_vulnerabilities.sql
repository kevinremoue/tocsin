-- Advisories (OSV schema), whatever their source
CREATE TABLE vulnerabilities (
    id           TEXT PRIMARY KEY,
    -- CVE IDs of the advisory: its own ID, its aliases, its upstream IDs
    cve_ids      TEXT[] NOT NULL DEFAULT '{}',
    -- Groups advisories describing the same flaw: first CVE ID, otherwise the advisory ID
    canonical_id TEXT NOT NULL,
    summary      TEXT,
    -- 0 unknown, 1 low, 2 medium, 3 high, 4 critical
    severity     SMALLINT NOT NULL CHECK (severity BETWEEN 0 AND 4),
    cvss_score   REAL,
    cvss_vector  TEXT,
    published_at TIMESTAMPTZ,
    -- Modification time as reported by the source, compared verbatim to skip refetching
    modified     TEXT NOT NULL,
    withdrawn    BOOLEAN NOT NULL DEFAULT false,
    data         JSONB NOT NULL,
    fetched_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX vulnerabilities_cve_ids_idx ON vulnerabilities USING GIN (cve_ids);
CREATE INDEX vulnerabilities_canonical_idx ON vulnerabilities (canonical_id);

-- Advisories affecting a package version. Keyed by purl: shared by every project using it
CREATE TABLE component_vulns (
    purl    TEXT NOT NULL,
    vuln_id TEXT NOT NULL REFERENCES vulnerabilities (id) ON DELETE CASCADE,
    PRIMARY KEY (purl, vuln_id)
);

CREATE INDEX component_vulns_vuln_idx ON component_vulns (vuln_id);

-- Last time each purl was matched against the vulnerability sources
CREATE TABLE purl_scans (
    purl       TEXT PRIMARY KEY,
    scanned_at TIMESTAMPTZ NOT NULL
);

-- Latest release of each project: what runs in production
CREATE VIEW latest_sboms AS
SELECT DISTINCT ON (project_id) id, project_id, version, created_at
FROM sboms
ORDER BY project_id, created_at DESC, id DESC;
