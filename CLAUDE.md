# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

Tocsin is a lightweight alternative to Dependency-Track. It collects each project's SBOM, matches the components against known CVEs, and posts an alert to Google Chat when a project is affected by a CVE in the CISA KEV (Known Exploited Vulnerabilities) catalog.

Current state:
- `src/main.rs`: startup, configured through the env vars `DATABASE_URL`, `BIND_ADDR` and `TOCSIN_ADMIN_TOKEN`.
- `src/api.rs`: router, handlers and bearer auth.
- `src/web.rs`: SSR dashboard built with `maud`, which auto-escapes every value (no template files, no JS). Pages: `/` lists projects, `/projects/{name}` shows releases and the components of the latest release. Dates are formatted in SQL (`to_char`), so there is no chrono or time dependency. The dashboard has no authentication yet.
- `src/sbom.rs`: CycloneDX parsing. It extracts purls recursively; components without a purl are skipped.

Endpoints:
- `POST /api/projects` (admin token): creates a project and returns its token once. Only the SHA-256 of the token is stored. If `TOCSIN_ADMIN_TOKEN` is unset, this endpoint answers 403.
- `POST /api/sboms[?version=]` (project token, `Content-Type: application/json`): the project comes from the token. The version comes from `?version=`, otherwise `metadata.component.version`. Re-pushing a version replaces its SBOM and components.

Schema: `projects`, `sboms` (one per release, raw JSONB), `components` (keyed by purl). Add a new migration for every schema change; never edit an applied migration.

## Commands

The repo is managed with `mise` (`mise.toml`): it pins the toolchain (Rust and `sqlx-cli`) and defines the tasks. Run `mise install` once, then use the tasks rather than raw `cargo` commands:

- `mise run db:up` / `mise run db:down`: local Postgres via `docker-compose.yml`, exposed on **port 5433** because 5432 is often already taken. `DATABASE_URL` is set in `mise.toml` `[env]`.
- `mise run db:migrate`: apply `migrations/` with sqlx-cli. The app also runs pending migrations at startup (`sqlx::migrate!()`).
- `build`, `test`, `lint` and `dev` all depend on `db:migrate` (which depends on `db:up`): `sqlx::query!` macros check SQL against the live, migrated database at compile time, and `#[sqlx::test]` creates a throwaway migrated database per test.
- `mise run build` / `mise run dev` (`dev` starts Postgres first, then `cargo run`; listens on `BIND_ADDR`, default `0.0.0.0:3000`)
- `mise run test`; run a single test with `mise run test -- <test_name>`
- `mise run lint` (fmt check + clippy `-D warnings` + `cargo sqlx prepare --check`), `mise run fmt`
- `mise run db:prepare`: regenerate `.sqlx/` (committed query metadata). **Run it after adding or changing any `query!` macro**, otherwise lint and CI fail. The `Dockerfile` builds with `SQLX_OFFLINE=true` from it.

Add new tooling or commands to `mise.toml`, not to ad-hoc scripts.

## Open source

The project is public, dual-licensed MIT OR Apache-2.0. Everything in the repo (code, comments, UI strings, docs) is in English. CI (`.github/workflows/ci.yml`) runs `mise run lint`, `mise run test` and a Docker build. Documentation is an mdBook site in `docs/` (`mise run docs:serve` / `docs:build`), deployed to GitHub Pages by `.github/workflows/docs.yml`; it is the reference for users (API, configuration, roadmap), so update the matching page when behavior changes, and keep `README.md` short. user-visible changes go under `Unreleased` in `CHANGELOG.md`.

## Decided design

- **Stack:** Rust, `axum` on tokio, Postgres through `sqlx` (compile-time-checked queries, `sqlx` migrations). Start as a single binary and add other infrastructure (Redis, …) only when a concrete need appears.
- **Run locally:** Docker Compose (Tocsin + Postgres; `docker compose up` runs both, `mise run db:up` only Postgres). There is no k8s or Helm yet.
- **SBOM intake:** CycloneDX JSON, pushed over the REST API by each project's CI/CD pipeline when it builds a real release (production). Store it per project and release version. Matching uses each project's latest release SBOM, i.e. what runs in production.
- **API authentication:** bearer token per project. A token can only push SBOMs for its own project.
- **Vulnerability data:** pull from several sources behind a common interface. OSV.dev comes first, then others (NVD, GitHub Advisories). The CISA KEV catalog provides the "actively exploited" signal.
- **Matching key:** the package URL (purl) of each CycloneDX component.
- **Alert rule:** alert only when a project is affected by a KEV CVE. Two events can trigger an alert:
  - a new KEV entry matches components in the SBOMs already stored;
  - a newly pushed SBOM matches a KEV entry that is already known.

  Send each (project, CVE) pair only once.
- **Alerting:** Google Chat webhook for now. Keep the notifier pluggable, because other channels may follow.
- **Interface:** REST API plus a small server-side-rendered dashboard; there is no SPA.
