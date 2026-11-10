-- Applicability arrays are sets: feed ordering and repeated entries are not new evidence.
CREATE FUNCTION normalize_evidence(value JSONB) RETURNS JSONB LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE result JSONB;
BEGIN
 IF jsonb_typeof(value) = 'array' THEN
   SELECT COALESCE(jsonb_agg(v ORDER BY v::text), '[]'::jsonb) INTO result
   FROM (SELECT DISTINCT normalize_evidence(x) AS v FROM jsonb_array_elements(value) x) items;
 ELSIF jsonb_typeof(value) = 'object' THEN
   SELECT COALESCE(jsonb_object_agg(k, normalize_evidence(v)), '{}'::jsonb) INTO result
   FROM jsonb_each(value) AS fields(k, v)
   WHERE k NOT IN ('database_specific');
 ELSE result := value;
 END IF;
 RETURN result;
END $$;

CREATE OR REPLACE FUNCTION finding_evidence(project BIGINT, vulnerability TEXT) RETURNS JSONB
LANGUAGE sql STABLE AS $$
 SELECT normalize_evidence(jsonb_agg(item)) FROM (
   SELECT DISTINCT jsonb_build_object('purl', c.purl,
     'affected', COALESCE(v.data->'affected', '[]'::jsonb)) AS item
   FROM latest_sboms ls JOIN components c ON c.sbom_id = ls.id
   JOIN component_vulns cv ON cv.purl = c.purl
   JOIN vulnerabilities v ON v.id = cv.vuln_id AND NOT v.withdrawn
   WHERE ls.project_id = project AND v.canonical_id = vulnerability
 ) evidence
$$;
UPDATE analyses SET evidence = normalize_evidence(evidence) WHERE evidence IS NOT NULL;

-- The same supplied-component scope as intake: nested components, not the root application.
CREATE FUNCTION supplied_components(document JSONB) RETURNS SETOF JSONB LANGUAGE sql IMMUTABLE AS $$
 WITH RECURSIVE tree(component) AS (
   SELECT value FROM jsonb_array_elements(COALESCE(document->'components', '[]'::jsonb))
   UNION ALL
   SELECT child.value FROM tree CROSS JOIN LATERAL
     jsonb_array_elements(COALESCE(tree.component->'components', '[]'::jsonb)) child
 ) SELECT component FROM tree
$$;

CREATE OR REPLACE FUNCTION matching_complete(project BIGINT) RETURNS BOOLEAN LANGUAGE sql STABLE AS $$
 SELECT EXISTS (SELECT 1 FROM latest_sboms WHERE project_id=project) AND NOT EXISTS (
 SELECT 1 FROM latest_sboms ls JOIN sboms b ON b.id=ls.id
 CROSS JOIN LATERAL supplied_components(b.document) c
 LEFT JOIN purl_scans s ON s.purl = c->>'purl'
 LEFT JOIN matching_attempts a ON a.purl = c->>'purl'
 WHERE ls.project_id = project AND (
   COALESCE(c->>'purl', '') !~ '^pkg:[^/?#]+/[^?#]+@[^/?#]+([?#].*)?$'
   OR s.purl IS NULL OR a.attempted_at > s.scanned_at))
$$;

-- One retained complete evaluation, independent of replacement/deletion of an SBOM row.
-- The immutable document fingerprint distinguishes re-uploads of the same version.
CREATE TABLE project_evaluations (
 project_id BIGINT PRIMARY KEY REFERENCES projects(id) ON DELETE CASCADE,
 release TEXT NOT NULL,
 sbom_id BIGINT NOT NULL,
 declared_at TIMESTAMPTZ NOT NULL,
 document_fingerprint TEXT NOT NULL,
 evaluated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 identifier_evaluations JSONB NOT NULL,
 findings JSONB NOT NULL
);
CREATE FUNCTION capture_evaluations(project BIGINT DEFAULT NULL) RETURNS void LANGUAGE sql AS $$
 INSERT INTO project_evaluations (project_id, release, sbom_id, declared_at,
   document_fingerprint, identifier_evaluations, findings)
 SELECT ls.project_id, ls.version, ls.id, ls.created_at, md5(b.document::text),
   COALESCE((SELECT jsonb_agg(jsonb_build_object('purl', c.purl, 'evaluated_at', s.scanned_at) ORDER BY c.purl)
     FROM components c JOIN purl_scans s ON s.purl=c.purl WHERE c.sbom_id=ls.id), '[]'::jsonb),
   COALESCE((SELECT jsonb_agg(to_jsonb(f) ORDER BY f.vuln_key) FROM findings f
     WHERE f.project_id=ls.project_id), '[]'::jsonb)
 FROM latest_sboms ls JOIN sboms b ON b.id=ls.id
 WHERE (project IS NULL OR ls.project_id=project) AND matching_complete(ls.project_id)
 ON CONFLICT (project_id) DO UPDATE SET release=EXCLUDED.release, sbom_id=EXCLUDED.sbom_id,
   declared_at=EXCLUDED.declared_at, document_fingerprint=EXCLUDED.document_fingerprint,
   evaluated_at=now(), identifier_evaluations=EXCLUDED.identifier_evaluations, findings=EXCLUDED.findings
$$;
