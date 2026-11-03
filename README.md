# 🔔 Tocsin

[![CI](https://github.com/kevinremoue/tocsin/actions/workflows/ci.yml/badge.svg)](https://github.com/kevinremoue/tocsin/actions/workflows/ci.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

**Tocsin rings the alarm when what you run in production is hit by a vulnerability that is being actively exploited.**

It is a lightweight alternative to [Dependency-Track](https://dependencytrack.org/): your CI pipelines push a CycloneDX SBOM for every production release, Tocsin matches the components against known vulnerabilities, and alerts you only when a project is affected by a CVE listed in the [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) (Known Exploited Vulnerabilities).

No dashboards full of thousands of "medium" findings: one alert per project and exploited CVE, when it matters.

> [!WARNING]
> **Tocsin is in early development.** SBOM ingestion and the dashboard work today; vulnerability matching and alerting are being built (see the [roadmap](#roadmap)). The dashboard has no authentication yet: do not expose Tocsin to an untrusted network.

## How it works

```
CI pipeline ──(CycloneDX SBOM)──▶ Tocsin ◀── OSV.dev (CVE ↔ package)
                                    │    ◀── CISA KEV (actively exploited CVEs)
                                    ▼
                            Google Chat alert
```

- **One SBOM per release.** Each project's CI pushes its SBOM when it ships a production release. Tocsin keeps every release and matches against the **latest** one, which is what runs in production.
- **Matching by package URL** ([purl](https://github.com/package-url/purl-spec)) of each CycloneDX component.
- **Alert only on KEV.** An alert fires when a new KEV entry matches a stored SBOM, or when a newly pushed SBOM matches a known KEV entry. Each (project, CVE) pair is sent only once.
- **Small footprint.** A single Rust binary and a Postgres database.

## Quick start

Requires Docker with Compose.

```sh
git clone https://github.com/kevinremoue/tocsin.git && cd tocsin
export TOCSIN_ADMIN_TOKEN=$(openssl rand -hex 32)   # keep it: it creates projects
docker compose up -d --build
```

Tocsin listens on <http://localhost:3000>. Create a project; the response contains its token, shown **only once**:

```sh
curl -X POST http://localhost:3000/api/projects \
  -H "Authorization: Bearer $TOCSIN_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name": "my-service"}'
# {"name":"my-service","token":"3f9c…"}
```

Push an SBOM with that token:

```sh
curl -X POST "http://localhost:3000/api/sboms?version=1.4.2" \
  -H "Authorization: Bearer $PROJECT_TOKEN" \
  -H "Content-Type: application/json" \
  --data-binary @bom.json
# {"project":"my-service","version":"1.4.2","components":187}
```

Open the dashboard to see the project, its releases and the components of its latest release.

## Pushing SBOMs from CI

Generate a CycloneDX JSON SBOM with the tool of your choice ([Syft](https://github.com/anchore/syft), [cdxgen](https://github.com/CycloneDX/cdxgen), [cargo-cyclonedx](https://github.com/CycloneDX/cyclonedx-rust-cargo), the CycloneDX Maven/Gradle/npm plugins, …), then push it on each production release. GitHub Actions example:

```yaml
- name: Generate SBOM
  run: syft . -o cyclonedx-json=bom.json

- name: Push SBOM to Tocsin
  run: |
    curl --fail-with-body -X POST "$TOCSIN_URL/api/sboms?version=${GITHUB_REF_NAME}" \
      -H "Authorization: Bearer ${{ secrets.TOCSIN_TOKEN }}" \
      -H "Content-Type: application/json" \
      --data-binary @bom.json
  env:
    TOCSIN_URL: https://tocsin.example.com
```

## API

| Endpoint | Auth | Description |
|---|---|---|
| `POST /api/projects` | admin token | Body `{"name": "…"}` (1–100 chars of `[A-Za-z0-9._-]`). Returns `201` with the project token, shown once (only its SHA-256 is stored). `409` if the name exists, `403` if `TOCSIN_ADMIN_TOKEN` is unset. |
| `POST /api/sboms[?version=]` | project token | Body: a CycloneDX JSON document (up to 50 MB). The project comes from the token. The version comes from `?version=`, otherwise `metadata.component.version`. Re-pushing a version replaces its SBOM. |
| `GET /health` | none | `200` when the database is reachable, `503` otherwise. |
| `GET /`, `GET /projects/{name}` | none | Server-rendered dashboard. |

Tokens are sent as `Authorization: Bearer <token>`. Components without a purl are skipped, since they cannot be matched.

## Configuration

Tocsin is configured with environment variables:

| Variable | Default | Description |
|---|---|---|
| `DATABASE_URL` | *(required)* | Postgres connection string. Migrations run automatically at startup. |
| `TOCSIN_ADMIN_TOKEN` | *(unset)* | Admin token for `POST /api/projects`. When unset, the admin API is disabled. |
| `BIND_ADDR` | `0.0.0.0:3000` | Listen address. |
| `RUST_LOG` | `info` | Log filter ([`tracing` syntax](https://docs.rs/tracing-subscriber/latest/tracing_subscriber/filter/struct.EnvFilter.html)). |

## Roadmap

- [x] SBOM ingestion API with per-project tokens
- [x] Server-rendered dashboard
- [x] Docker image and Compose setup
- [ ] **CISA KEV catalog**: periodic sync, detection of new entries
- [ ] **OSV.dev matching**: purl → CVEs, keep only those in KEV
- [ ] **Google Chat alerts**: one per (project, CVE), on new KEV entries and on new SBOMs
- [ ] Dashboard: KEV CVEs affecting each project, alert history
- [ ] Dashboard authentication (required before any exposed deployment)
- [ ] More vulnerability sources: NVD, GitHub Advisories
- [ ] More notification channels (Slack, email, generic webhook)

Ideas and feedback are welcome in [issues](https://github.com/kevinremoue/tocsin/issues).

## Development

The toolchain and tasks are managed by [mise](https://mise.jdx.dev/). You also need Docker for the development database.

```sh
mise install          # Rust toolchain + sqlx-cli
mise run dev          # start Postgres (port 5433), apply migrations, run Tocsin
mise run test         # run the tests (each test gets its own throwaway database)
mise run lint         # rustfmt, clippy, and the .sqlx/ freshness check
```

SQL queries are checked against the database at compile time by `sqlx`. After adding or changing a query, run `mise run db:prepare` and commit the updated `.sqlx/` directory: the Docker build compiles offline from it.

See [CONTRIBUTING.md](CONTRIBUTING.md) for more.

## Security

Please report vulnerabilities privately, as described in [SECURITY.md](SECURITY.md).

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <https://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <https://opensource.org/licenses/MIT>)

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
