-- Existing analyses retain rationale but have no accepted evidence: revalidation is required.
ALTER TABLE analyses ADD COLUMN evidence JSONB;

-- Material applicability, not advisory names, prose, severity or exploitation signals.
CREATE FUNCTION finding_evidence(project BIGINT, vulnerability TEXT) RETURNS JSONB
LANGUAGE sql STABLE AS $$
 SELECT jsonb_agg(item ORDER BY item::text) FROM (
   SELECT DISTINCT jsonb_build_object('purl', c.purl,
     'affected', COALESCE(v.data->'affected', '[]'::jsonb)) AS item
   FROM latest_sboms ls JOIN components c ON c.sbom_id = ls.id
   JOIN component_vulns cv ON cv.purl = c.purl
   JOIN vulnerabilities v ON v.id = cv.vuln_id AND NOT v.withdrawn
   WHERE ls.project_id = project AND v.canonical_id = vulnerability
 ) evidence
$$;

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
       COALESCE(a.state IN ('not_affected', 'false_positive', 'resolved') AND a.evidence = finding_evidence(ls.project_id, v.canonical_id), false) AS suppressed,
       max(e.score)                                    AS epss,
       max(e.percentile)                               AS epss_percentile
FROM latest_sboms ls
JOIN components c ON c.sbom_id = ls.id
JOIN component_vulns cv ON cv.purl = c.purl
JOIN vulnerabilities v ON v.id = cv.vuln_id AND NOT v.withdrawn
LEFT JOIN epss_scores e ON e.cve_id = ANY (v.cve_ids)
LEFT JOIN analyses a ON a.project_id = ls.project_id AND a.vuln_key = v.canonical_id
GROUP BY ls.project_id, v.canonical_id, a.state, a.justification, a.detail, a.evidence;


-- An episode is independent of rule thresholds and component changes while actionable.
CREATE TABLE finding_episodes (
 project_id BIGINT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
 vuln_key TEXT NOT NULL,
 episode BIGINT NOT NULL DEFAULT 1,
 actionable BOOLEAN NOT NULL,
 PRIMARY KEY (project_id, vuln_key)
);
INSERT INTO finding_episodes (project_id, vuln_key, actionable)
 SELECT project_id, vuln_key, NOT suppressed FROM findings;
INSERT INTO finding_episodes (project_id, vuln_key, actionable)
 SELECT DISTINCT project_id, vuln_key, false FROM alerts ON CONFLICT DO NOTHING;
ALTER TABLE alerts ADD COLUMN episode BIGINT NOT NULL DEFAULT 1;
ALTER TABLE alerts DROP CONSTRAINT alerts_pkey;
ALTER TABLE alerts ADD PRIMARY KEY (project_id, vuln_key, rule, episode);

-- Absence is conclusive only when every matchable identifier has a successful scan.
CREATE FUNCTION matching_complete(project BIGINT) RETURNS BOOLEAN LANGUAGE sql STABLE AS $$
 SELECT NOT EXISTS (
 SELECT 1 FROM latest_sboms ls JOIN components c ON c.sbom_id = ls.id
 LEFT JOIN purl_scans s ON s.purl = c.purl
 WHERE ls.project_id = project AND c.purl LIKE 'pkg:%@%' AND s.purl IS NULL)
$$;

CREATE FUNCTION reconcile_findings() RETURNS void LANGUAGE plpgsql AS $$
BEGIN
 UPDATE analyses a SET evidence = NULL WHERE evidence IS NOT NULL AND (
   (finding_evidence(a.project_id, a.vuln_key) IS NOT NULL
    AND evidence IS DISTINCT FROM finding_evidence(a.project_id, a.vuln_key))
   OR (finding_evidence(a.project_id, a.vuln_key) IS NULL AND matching_complete(a.project_id)));
 UPDATE finding_episodes e SET actionable = false WHERE actionable AND (
   EXISTS (SELECT 1 FROM findings f WHERE f.project_id=e.project_id AND f.vuln_key=e.vuln_key AND f.suppressed)
   OR (NOT EXISTS (SELECT 1 FROM findings f WHERE f.project_id=e.project_id AND f.vuln_key=e.vuln_key)
       AND matching_complete(e.project_id)));
 INSERT INTO finding_episodes (project_id, vuln_key, actionable)
 SELECT project_id, vuln_key, true FROM findings WHERE NOT suppressed
 ON CONFLICT (project_id, vuln_key) DO UPDATE SET
   episode = finding_episodes.episode + CASE WHEN finding_episodes.actionable THEN 0 ELSE 1 END,
   actionable = true;
END $$;
