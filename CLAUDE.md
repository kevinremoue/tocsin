# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

Tocsin aims to be a Dependency-Track equivalent that is much lighter in resource usage and ready to run serverless. It collects each project's SBOM, tracks every known vulnerability affecting its components, highlights those in the CISA KEV (Known Exploited Vulnerabilities) catalog, ranks findings by their FIRST EPSS score, and posts an alert to Google Chat when a project is affected by a KEV CVE.

Current state (all of it is covered by `docs/`, the user-facing reference):
- `src/main.rs`: CLI (`serve` default, `migrate`, `kev-sync`, `epss-sync`, `refresh`), pool setup, graceful shutdown on SIGTERM.
- `src/config.rs`: every setting, read once from env vars (`Config::from_env`); `Config::for_tests()` for tests. Add new settings here and to `docs/src/configuration.md`.
- `src/api.rs`: router and API handlers. `AppState { db, config, http }`. Auth: admin token, project token (`Project` extractor), or `named_project()` (admin or that project's token; others get 404). Uploads (`/api/sboms`, VEX import) accept gzip via `RequestDecompressionLayer`; the 50 MB limit applies after decompression.
- `src/sbom.rs`: CycloneDX parsing: purls and licenses, recursively.
- `src/vulns.rs`: `Severity`, CVSS v3 calculator, `Advisory::from_osv`, the `VulnSource` trait, `match_purls` / `refresh_all` / `stale_purls`. Advisories sharing a CVE share `canonical_id` = one finding. Store the source-reported `modified` (OSV's batch endpoint truncates to µs, advisories have ns), or every refresh refetches.
- `src/osv.rs`: OSV client (`VulnSource`): querybatch (1000/batch, pagination via `page_token`, drops a purl OSV rejects by index and retries), `GET /v1/vulns/{id}`.
- `src/kev.rs`: CISA KEV sync (one attempt, result recorded in `kev_sync`). cisa.gov honors `If-Modified-Since`, not `If-None-Match`: both sent.
- `src/epss.rs`: EPSS sync from FIRST's daily CSV file (FIRST says the API is for lookups, not for keeping a copy): conditional download, forced when advisories were stored since the last download; only CVEs of stored advisories kept (`epss_scores` is replaced each time). FIRST requests attribution: keep the dashboard footer credit.
- `src/jobs.rs`: `kev-sync`, `epss-sync` and `refresh` jobs (each ends with alert evaluation; `kev-sync` and `refresh` also record metrics), `snapshot_metrics`, the optional in-process `scheduler`.
- `src/alerts.rs`: `Notifier` trait, `GoogleChat`, `evaluate()` (advisory lock against duplicate sends across instances; an alert is recorded only after delivery; no notifier = nothing evaluated).
- `src/vex.rs`: audit states/justifications, analysis upsert, CycloneDX VEX export/import. `src/policies.rs`: policy validation and the violations query.
- `src/web/`: maud SSR dashboard. `mod.rs`: layout, helpers, `audit_cell`, `require_auth` (Basic/bearer; sets the `Viewer` extension and the CSP/security headers), embedded assets served from `/static/` (`static/tocsin.css` under a content-hash path, `static/htmx-<version>.min.js`, vendored, 0BSD). `actions.rs`: every POST (audit, projects, SBOM/VEX uploads, policies, jobs); they reuse the API's functions (`api::new_project`, `api::ingest`, `vex::record`, `api::new_policy`, `api::run_job_now`…). Writes need `Viewer::can_write` (admin token presented), even on a public dashboard; `CsrfLayer` refuses cross-site posts. Plain posts redirect with a fixed `?done=` message or render a result page; htmx posts (`HX-Request`) get a fragment. The CSP forbids inline scripts and styles: no `style=` attributes, no inline JS (htmx runs with `allowEval: false`). `chart.rs`: server-drawn SVG. `projects.rs`, `vulns.rs`, `kev.rs`, `admin.rs`: pages. Every value is escaped; links from feeds go through `safe_links` (http(s) only). Dates are formatted in SQL (`to_char`), so there is no chrono/time dependency.
- `src/tests.rs`: end-to-end tests with fake OSV, CISA, EPSS and Google Chat servers (local axum). No test touches the network.
- reqwest is built with `rustls-no-provider`; `http::client()` installs the `ring` provider sqlx already uses (no aws-lc-rs).

Endpoints: see `docs/src/api.md`.

Schema: `projects`, `sboms`, `components` (purl + licenses), `vulnerabilities` (OSV docs, `cve_ids`, `canonical_id`, `severity` 0-4), `component_vulns` (per purl), `purl_scans`, `analyses`, `alerts`, `policies`, `project_metrics`, `kev_entries`, `kev_sync`, `epss_scores`, `epss_sync`; views `latest_sboms` and `findings` (grouped per project and canonical_id, with audit state and `suppressed`). `sqlx::query!` cannot infer nullability through views: use `"col!"` overrides. Add a new migration for every schema change; never edit an applied migration.

## Commands

The repo is managed with `mise` (`mise.toml`): it pins the toolchain (Rust and `sqlx-cli`) and defines the tasks. Run `mise install` once, then use the tasks rather than raw `cargo` commands:

- `mise run db:up` / `mise run db:down`: local Postgres via `docker-compose.yml`, exposed on **port 5433** because 5432 is often already taken. `DATABASE_URL` is set in `mise.toml` `[env]`.
- `mise run db:migrate`: apply `migrations/` with sqlx-cli. The app also runs pending migrations at startup (`sqlx::migrate!()`).
- `build`, `test`, `lint` and `dev` all depend on `db:migrate` (which depends on `db:up`): `sqlx::query!` macros check SQL against the live, migrated database at compile time, and `#[sqlx::test]` creates a throwaway migrated database per test.
- `mise run build` / `mise run dev` (`dev` starts Postgres first, then `cargo run`; listens on `BIND_ADDR`, default `0.0.0.0:3000`)
- `mise run test`; run a single test with `mise run test -- <test_name>`
- `mise run seed` loads `examples/sboms/` (real vulnerable purls, hits the real OSV/CISA) into a running `mise run dev`; `mise run db:reset` wipes the dev DB. `mise.toml` sets a dev-only `TOCSIN_ADMIN_TOKEN=dev-admin-token` and `TOCSIN_SCHEDULER=true`.
- `mise run lint` (fmt check + clippy `-D warnings` + `cargo sqlx prepare --check`), `mise run fmt`
- `mise run db:prepare`: regenerate `.sqlx/` (committed query metadata). **Run it after adding or changing any `query!` macro**, otherwise lint and CI fail. The `Dockerfile` builds with `SQLX_OFFLINE=true` from it.

Add new tooling or commands to `mise.toml`, not to ad-hoc scripts.

## Open source

The project is public, dual-licensed MIT OR Apache-2.0. Everything in the repo (code, comments, UI strings, docs) is in English. CI (`.github/workflows/ci.yml`) runs `mise run lint`, `mise run test` and a Docker build. Documentation is an mdBook site in `docs/` (`mise run docs:serve` / `docs:build`), deployed to GitHub Pages by `.github/workflows/docs.yml`; it is the reference for users (API, configuration, roadmap), so update the matching page when behavior changes, and keep `README.md` short. user-visible changes go under `Unreleased` in `CHANGELOG.md`.

## Decided design

- **Goal:** a Dependency-Track equivalent (projects, components, vulnerabilities with severity, then auditing/VEX, licenses and policies, metrics, notifications), but light in resources and serverless-ready. Low memory and fast cold starts are requirements, not nice-to-haves.
- **Stack:** Rust, `axum` on tokio, Postgres through `sqlx` (compile-time-checked queries, `sqlx` migrations). Start as a single binary and add other infrastructure (Redis, queues, …) only when a concrete need appears.
- **Serverless-ready (decided 2026-11-04):** a portable container speaking HTTP, with **Cloud Run as the reference target** (also Azure Container Apps, Knative, Lambda through the Lambda Web Adapter). Consequences:
  - the HTTP server is stateless and may scale to zero: **no long-running background loops** in the request-serving process. Periodic work (KEV sync, vulnerability refresh) runs as jobs triggered from outside (Cloud Scheduler, cron): a one-shot CLI subcommand and/or a token-protected HTTP endpoint;
  - startup must stay cheap: migrations become a separate step for deployments (automatic at startup only as a local/dev convenience);
  - request work must fit platform limits (Cloud Run: 32 MB request body, request timeout); accept gzip-compressed SBOM uploads; long work goes to jobs;
  - Postgres stays the database (works with serverless providers such as Cloud SQL, Neon, Aurora Serverless); mind connection counts with many instances.
- **Run locally:** Docker Compose (Tocsin + Postgres; `docker compose up` runs both, `mise run db:up` only Postgres). There is no k8s or Helm yet.
- **SBOM intake:** CycloneDX JSON, pushed over the REST API by each project's CI/CD pipeline when it builds a real release (production). Store it per project and release version. Matching uses each project's latest release SBOM, i.e. what runs in production.
- **API authentication:** bearer token per project. A token can only push SBOMs for its own project.
- **Vulnerability scope (decided 2026-11-04):** track **all** vulnerabilities affecting each project's latest release, with severity, like Dependency-Track. KEV membership is the priority signal shown everywhere.
- **Vulnerability data:** pull from several sources behind a common interface. OSV.dev comes first, then others (NVD, GitHub Advisories). The CISA KEV catalog provides the "actively exploited" signal.
- **Matching key:** the package URL (purl) of each CycloneDX component.
- **Alert rule:** by default, alert only when a project is affected by a KEV CVE (other rules, such as a severity threshold, may come later). Two events can trigger an alert:
  - a new KEV entry matches components in the SBOMs already stored;
  - a newly pushed SBOM matches a KEV entry that is already known.

  Send each (project, CVE) pair only once.
- **Alerting:** Google Chat webhook for now. Keep the notifier pluggable, because other channels may follow.
- **Interface (decided 2026-11-05):** REST API plus a server-rendered dashboard (maud) with htmx for in-place updates; no SPA, no Node toolchain, assets embedded in the binary. Every API action is also available in the dashboard, with forms that work without JavaScript.
