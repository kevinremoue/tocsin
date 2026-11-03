CREATE TABLE projects (
    id         BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name       TEXT NOT NULL UNIQUE,
    -- SHA-256 of the project's bearer token; the plaintext token is never stored
    token_hash TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- One CycloneDX SBOM per production release
CREATE TABLE sboms (
    id         BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    project_id BIGINT NOT NULL REFERENCES projects (id) ON DELETE CASCADE,
    version    TEXT NOT NULL,
    document   JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (project_id, version)
);

-- Latest release per project = reference SBOM for matching
CREATE INDEX sboms_latest_idx ON sboms (project_id, created_at DESC);

-- Components extracted from the SBOM; matching key = purl (with version)
CREATE TABLE components (
    sbom_id BIGINT NOT NULL REFERENCES sboms (id) ON DELETE CASCADE,
    purl    TEXT NOT NULL,
    PRIMARY KEY (sbom_id, purl)
);

CREATE INDEX components_purl_idx ON components (purl);
