-- An unsuccessful attempt never replaces last-known links or establishes absence.
CREATE TABLE matching_attempts (purl TEXT PRIMARY KEY, attempted_at TIMESTAMPTZ NOT NULL DEFAULT now());
CREATE OR REPLACE FUNCTION matching_complete(project BIGINT) RETURNS BOOLEAN LANGUAGE sql STABLE AS $$
 SELECT NOT EXISTS (
 SELECT 1 FROM latest_sboms ls JOIN components c ON c.sbom_id = ls.id
 LEFT JOIN purl_scans s ON s.purl = c.purl
 LEFT JOIN matching_attempts a ON a.purl = c.purl
 WHERE ls.project_id = project AND c.purl LIKE 'pkg:%@%'
 AND (s.purl IS NULL OR a.attempted_at > s.scanned_at))
$$;
