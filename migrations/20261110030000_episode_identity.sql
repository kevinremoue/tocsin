-- Episode identities are globally unique, so merging vulnerabilities cannot collide with
-- another vulnerability's historical episode numbers. Delivery history remains append-only.
CREATE SEQUENCE finding_episode_id_seq;
CREATE TEMP TABLE episode_remap ON COMMIT DROP AS
 SELECT project_id, vuln_key, episode, nextval('finding_episode_id_seq') AS new_episode FROM (
   SELECT project_id, vuln_key, episode FROM alerts
   UNION SELECT project_id, vuln_key, episode FROM finding_episodes
 ) episodes;
UPDATE alerts a SET episode = r.new_episode FROM episode_remap r
 WHERE a.project_id=r.project_id AND a.vuln_key=r.vuln_key AND a.episode=r.episode;
UPDATE finding_episodes e SET episode = r.new_episode FROM episode_remap r
 WHERE e.project_id=r.project_id AND e.vuln_key=r.vuln_key AND e.episode=r.episode;
ALTER TABLE finding_episodes ALTER COLUMN episode SET DEFAULT nextval('finding_episode_id_seq');
ALTER TABLE alerts DROP CONSTRAINT alerts_pkey;
ALTER TABLE alerts ADD COLUMN id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY;
-- Multiple real deliveries for independently actionable findings remain visible after a merge.
CREATE INDEX alerts_episode_idx ON alerts (project_id, vuln_key, rule, episode);

CREATE OR REPLACE FUNCTION reconcile_findings() RETURNS void LANGUAGE plpgsql AS $$
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
   episode = CASE WHEN finding_episodes.actionable THEN finding_episodes.episode ELSE nextval('finding_episode_id_seq') END,
   actionable = true;
END $$;

-- Preserve every delivery and map only ongoing actionable episodes to the merged one.
CREATE FUNCTION merge_finding_episodes(old_name TEXT, new_name TEXT) RETURNS void LANGUAGE plpgsql AS $$
DECLARE old_episode RECORD; target RECORD; destination BIGINT;
BEGIN
 FOR old_episode IN SELECT * FROM finding_episodes WHERE vuln_key=old_name LOOP
   SELECT * INTO target FROM finding_episodes WHERE project_id=old_episode.project_id AND vuln_key=new_name;
   IF NOT FOUND THEN
     INSERT INTO finding_episodes (project_id, vuln_key, episode, actionable)
     VALUES (old_episode.project_id, new_name, old_episode.episode, old_episode.actionable);
     destination := old_episode.episode;
   ELSE
     destination := CASE WHEN target.actionable THEN target.episode
                         WHEN old_episode.actionable THEN old_episode.episode ELSE target.episode END;
     UPDATE finding_episodes SET episode=destination, actionable=target.actionable OR old_episode.actionable
       WHERE project_id=old_episode.project_id AND vuln_key=new_name;
   END IF;
   IF old_episode.actionable THEN
     UPDATE alerts SET episode=destination WHERE project_id=old_episode.project_id
       AND vuln_key=old_name AND episode=old_episode.episode;
   END IF;
 END LOOP;
 UPDATE alerts SET vuln_key=new_name WHERE vuln_key=old_name;
 DELETE FROM finding_episodes WHERE vuln_key=old_name;
END $$;
