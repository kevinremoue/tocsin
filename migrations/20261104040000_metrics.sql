-- Daily snapshot of each project's unsuppressed findings, for history
CREATE TABLE project_metrics (
    project_id BIGINT NOT NULL REFERENCES projects (id) ON DELETE CASCADE,
    day        DATE NOT NULL,
    critical   INTEGER NOT NULL,
    high       INTEGER NOT NULL,
    medium     INTEGER NOT NULL,
    low        INTEGER NOT NULL,
    unknown    INTEGER NOT NULL,
    kev        INTEGER NOT NULL,
    suppressed INTEGER NOT NULL,
    components INTEGER NOT NULL,
    PRIMARY KEY (project_id, day)
);
