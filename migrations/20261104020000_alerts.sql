-- Alerts sent, so that each (project, flaw, rule) is notified only once
CREATE TABLE alerts (
    project_id BIGINT NOT NULL REFERENCES projects (id) ON DELETE CASCADE,
    vuln_key   TEXT NOT NULL,
    -- 'kev' or 'severity'
    rule       TEXT NOT NULL,
    severity   SMALLINT NOT NULL,
    kev        BOOLEAN NOT NULL,
    sent_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (project_id, vuln_key, rule)
);
