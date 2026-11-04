-- EPSS scores (FIRST Exploit Prediction Scoring System), kept only for the CVEs of stored
-- advisories: the daily file covers every CVE, Tocsin only needs its own
CREATE TABLE epss_scores (
    cve_id        TEXT PRIMARY KEY,
    -- Probability of exploitation activity in the next 30 days, 0 to 1
    score         REAL NOT NULL,
    percentile    REAL NOT NULL,
    score_date    DATE NOT NULL,
    model_version TEXT NOT NULL
);

-- State of the EPSS sync (single row)
CREATE TABLE epss_sync (
    id              BOOLEAN PRIMARY KEY DEFAULT true CHECK (id),
    model_version   TEXT,
    score_date      DATE,
    -- Validators of the last downloaded file, for conditional requests
    etag            TEXT,
    last_modified   TEXT,
    -- Start of the last download: advisories stored later have CVEs not looked up yet
    downloaded_at   TIMESTAMPTZ,
    checked_at      TIMESTAMPTZ,
    last_error      TEXT,
    last_attempt_at TIMESTAMPTZ
);

INSERT INTO epss_sync DEFAULT VALUES;

-- Findings get the highest EPSS score among the CVEs of their advisories. Columns can only be
-- appended to a view, so the definition is repeated with them at the end.
CREATE OR REPLACE VIEW findings AS
SELECT ls.project_id,
       v.canonical_id                                  AS vuln_key,
       max(v.severity)                                 AS severity,
       max(v.cvss_score)                               AS cvss_score,
       array_agg(DISTINCT v.id ORDER BY v.id)          AS vuln_ids,
       array_agg(DISTINCT c.purl ORDER BY c.purl)      AS purls,
       (array_agg(v.summary ORDER BY v.summary IS NULL, v.id))[1] AS summary,
       bool_or(EXISTS (SELECT 1 FROM kev_entries k WHERE k.cve_id = ANY (v.cve_ids))) AS kev,
       a.state,
       a.justification,
       a.detail,
       COALESCE(a.state IN ('not_affected', 'false_positive', 'resolved'), false) AS suppressed,
       max(e.score)                                    AS epss,
       max(e.percentile)                               AS epss_percentile
FROM latest_sboms ls
JOIN components c ON c.sbom_id = ls.id
JOIN component_vulns cv ON cv.purl = c.purl
JOIN vulnerabilities v ON v.id = cv.vuln_id AND NOT v.withdrawn
LEFT JOIN epss_scores e ON e.cve_id = ANY (v.cve_ids)
LEFT JOIN analyses a ON a.project_id = ls.project_id AND a.vuln_key = v.canonical_id
GROUP BY ls.project_id, v.canonical_id, a.state, a.justification, a.detail;

-- 'epss': an unsuppressed finding has an EPSS score of at least `value` (0 to 1)
ALTER TABLE policies DROP CONSTRAINT policies_kind_check;
ALTER TABLE policies ADD CONSTRAINT policies_kind_check
    CHECK (kind IN ('license', 'severity', 'kev', 'epss'));
