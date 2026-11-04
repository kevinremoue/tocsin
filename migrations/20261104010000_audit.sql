-- Audit decisions, per project and flaw (canonical vulnerability ID). States and
-- justifications follow CycloneDX VEX.
CREATE TABLE analyses (
    project_id    BIGINT NOT NULL REFERENCES projects (id) ON DELETE CASCADE,
    vuln_key      TEXT NOT NULL,
    state         TEXT NOT NULL CHECK (state IN (
                      'in_triage', 'exploitable', 'not_affected', 'false_positive', 'resolved')),
    justification TEXT CHECK (justification IN (
                      'code_not_present', 'code_not_reachable', 'requires_configuration',
                      'requires_dependency', 'requires_environment', 'protected_by_compiler',
                      'protected_at_runtime', 'protected_at_perimeter',
                      'protected_by_mitigating_control')),
    detail        TEXT,
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (project_id, vuln_key)
);

-- One row per (project, flaw) affecting the project's latest release, advisories grouped
CREATE VIEW findings AS
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
       COALESCE(a.state IN ('not_affected', 'false_positive', 'resolved'), false) AS suppressed
FROM latest_sboms ls
JOIN components c ON c.sbom_id = ls.id
JOIN component_vulns cv ON cv.purl = c.purl
JOIN vulnerabilities v ON v.id = cv.vuln_id AND NOT v.withdrawn
LEFT JOIN analyses a ON a.project_id = ls.project_id AND a.vuln_key = v.canonical_id
GROUP BY ls.project_id, v.canonical_id, a.state, a.justification, a.detail;
