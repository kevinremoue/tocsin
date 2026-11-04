-- Licenses declared for each component in the SBOM (SPDX IDs, names or expressions)
ALTER TABLE components ADD COLUMN licenses TEXT[] NOT NULL DEFAULT '{}';

-- Policies evaluated against each project's latest release
CREATE TABLE policies (
    id         BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name       TEXT NOT NULL,
    -- 'license': a component declares the license `value` (SPDX ID, case-insensitive)
    -- 'severity': an unsuppressed finding is at least `value` (low, medium, high, critical)
    -- 'kev': an unsuppressed finding is in the KEV catalog (`value` unused)
    kind       TEXT NOT NULL CHECK (kind IN ('license', 'severity', 'kev')),
    value      TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
