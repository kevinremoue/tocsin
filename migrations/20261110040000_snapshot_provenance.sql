-- Re-reading cached evidence does not fabricate a new evaluation timestamp.
CREATE OR REPLACE FUNCTION capture_evaluations(project BIGINT DEFAULT NULL) RETURNS void LANGUAGE sql AS $$
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
 WHERE (project_evaluations.release, project_evaluations.sbom_id, project_evaluations.declared_at,
        project_evaluations.document_fingerprint, project_evaluations.identifier_evaluations, project_evaluations.findings)
 IS DISTINCT FROM (EXCLUDED.release, EXCLUDED.sbom_id, EXCLUDED.declared_at,
        EXCLUDED.document_fingerprint, EXCLUDED.identifier_evaluations, EXCLUDED.findings)
$$;
