# How it works

```
CI pipeline ──(CycloneDX SBOM)──▶ Tocsin ◀── OSV.dev (CVE ↔ package)
                                    │    ◀── CISA KEV (actively exploited CVEs)
                                    ▼
                            Google Chat alert
```

> Ingestion and the dashboard are implemented. The vulnerability sources and alerting described below are the planned design; see the [roadmap](roadmap.md).

## SBOM intake

Each project's CI pushes a CycloneDX JSON SBOM when it builds a production release. Tocsin stores:

- the raw document, one per (project, version);
- the deduplicated list of component purls, nested components included.

The **latest release** of each project is its reference SBOM: it represents what runs in production, and it is the one Tocsin matches against.

## Matching key: the package URL

Components are identified by their [package URL](https://github.com/package-url/purl-spec), for example `pkg:npm/lodash@4.17.20` or `pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1`. A purl names the ecosystem, the package and the exact version, which is what vulnerability databases such as OSV.dev index.

## Vulnerability data

Vulnerability data will come from several sources behind a common interface:

- **[OSV.dev](https://osv.dev/)** first: it maps package versions to known vulnerabilities and their CVE aliases.
- **[NVD](https://nvd.nist.gov/)** and **[GitHub Advisories](https://github.com/advisories)** later.
- **[CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)** provides the "actively exploited" signal: only CVEs in this catalog trigger alerts.

## Alert rule

Tocsin alerts only when a project is affected by a KEV CVE. Two events can trigger an alert:

- a **new KEV entry** matches components in the SBOMs already stored;
- a **newly pushed SBOM** matches a KEV entry that is already known.

Each (project, CVE) pair is sent **only once**, so a CVE that stays in your stack does not page you on every release.

## Notifications

Alerts go to a Google Chat webhook first. The notifier is pluggable, so other channels (Slack, email, generic webhooks) can follow.

## Data model

| Table | Content |
|---|---|
| `projects` | Name, SHA-256 of the project token, creation date. |
| `sboms` | One row per (project, version): the raw CycloneDX document (JSONB) and its reception date. |
| `components` | The purls extracted from each SBOM. |

## Stack

Tocsin is written in Rust with [axum](https://github.com/tokio-rs/axum) and [sqlx](https://github.com/launchbadge/sqlx) on Postgres. The dashboard is rendered on the server with [maud](https://maud.lambda.xyz/), which escapes every value, and uses no JavaScript.
