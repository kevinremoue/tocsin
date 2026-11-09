# How it works

```
CI pipeline ──(CycloneDX SBOM)──▶ Tocsin ◀── OSV.dev (advisories by package)
                                    │    ◀── CISA KEV (actively exploited CVEs)
                                    │    ◀── FIRST EPSS (exploitation probability)
                                    ▼
                            Google Chat alert
```

## SBOM intake

Each project's CI pushes a CycloneDX JSON SBOM when it builds a production release. Tocsin stores:

- the raw document, one per (project, version);
- the deduplicated list of component purls with their declared licenses, nested components included.

The **latest release** of each project is its reference SBOM: it represents what runs in production, and it is the one Tocsin matches, measures and alerts on.

## Matching key: the package URL

Components are identified by their [package URL](https://github.com/package-url/purl-spec), for example `pkg:npm/lodash@4.17.20` or `pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1`. A purl names the ecosystem, the package and the exact version, which is what OSV.dev indexes. Purls without a version cannot be matched and are skipped.

## Vulnerability matching

Matching runs during SBOM pushes (for components not matched recently) and in the refresh job (for every latest release):

1. Purls are sent to OSV's batch API, 1,000 per request. OSV answers with the IDs and modification times of the advisories affecting each one, paginated when there are many. A purl OSV rejects is skipped with a warning.
2. Advisories that are new, or modified since Tocsin stored them, are downloaded (8 at a time). Unchanged ones are not downloaded again, so a daily refresh mostly costs the batch requests.
3. The links between purls and advisories are replaced. Links are stored **per purl**, not per project: projects sharing a component share the work.

Advisories are stored in the [OSV schema](https://ossf.github.io/osv-schema/), which is also the common format for future sources. Their CVE IDs come from the advisory's ID, its `aliases` and its `upstream` field. Withdrawn advisories are kept but ignored.

**Findings** group the advisories of a project's latest release by flaw: advisories sharing a CVE become one finding, named by that CVE, with the highest severity among them. See [Vulnerabilities and auditing](vulnerabilities.md) for severity and audit states.

## KEV catalog sync

Tocsin downloads the [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) in the KEV sync job (every 6 hours by default):

- **Conditional requests.** Tocsin sends `If-Modified-Since` and `If-None-Match`, so a check costs a `304 Not Modified` answer when the catalog has not changed. The catalog itself is about 2 MB.
- **Upsert.** Each entry is stored with its vendor, product, name, date added and ransomware flag, plus the raw entry as published. Entries that did not change are not rewritten.
- **Failures.** A failed check is logged, shown on the dashboard and retried at the next run; the stored entries are kept. A single malformed entry is skipped with a warning.

A finding is **KEV** when one of its advisories' CVEs is in the catalog.

## EPSS sync

The EPSS sync job (daily by default) downloads FIRST's daily scores file, gzipped CSV, about 3 MB for 400,000 CVEs:

- **Conditional requests**, as for KEV. When advisories were stored since the last download, the file is downloaded in full anyway, so that their CVEs get a score.
- **Only your CVEs are kept.** The file is decompressed and parsed as it is read, and the rows for the CVEs of stored advisories replace the previous scores. The table stays at a few hundred rows instead of 400,000.
- **Failures** are recorded and shown on the dashboard, like KEV sync failures; the stored scores are kept.

A finding's EPSS score is the highest among its advisories' CVEs.

## Alerts

After each push, KEV sync, EPSS sync and refresh, Tocsin looks for findings that match an alert rule (KEV by default, optionally a severity or EPSS threshold), are not suppressed, and were not notified yet for that project and rule. It sends one message per project, then records each alert. See [Alerts](alerts.md).

## Metrics

Each push, audit decision and job records today's counts for the affected projects: findings per severity, KEV findings, suppressed findings, components. One row per project and day forms the history shown on the project page.

## Serverless design

The server keeps no state between requests and runs no background work unless `TOCSIN_SCHEDULER=true`. Everything periodic is a job that runs once and exits, triggered from outside. Work inside a request is bounded: matching during a push stops after 60 seconds and is completed by the next refresh. Alert evaluation takes a Postgres advisory lock, so concurrent instances do not send duplicates.

## Data model

| Table | Content |
|---|---|
| `projects` | Name, SHA-256 of the project token, creation date. |
| `sboms` | One row per (project, version): the raw CycloneDX document (JSONB) and its reception date. |
| `components` | The purls of each SBOM, with their declared licenses. |
| `vulnerabilities` | Advisories in the OSV schema: CVE IDs, grouping key, severity, CVSS, raw document. |
| `component_vulns` | Which advisories affect which purl. |
| `purl_scans` | When each purl was last matched. |
| `analyses` | Audit decisions per project and flaw. |
| `kev_entries`, `kev_sync` | The KEV catalog, and the state of its sync. |
| `epss_scores`, `epss_sync` | EPSS scores of known CVEs, and the state of their sync. |
| `alerts` | Alerts sent, one per (project, flaw, rule). |
| `policies` | Policy rules. |
| `project_metrics` | Daily counts per project. |

The views `latest_sboms` (each project's latest release) and `findings` (advisories grouped per project and flaw, with their audit state) are what most pages and endpoints query.

## Stack

Tocsin is written in Rust with [axum](https://github.com/tokio-rs/axum) and [sqlx](https://github.com/launchbadge/sqlx) on Postgres. The dashboard is rendered on the server with [maud](https://maud.lambda.xyz/), which escapes every value. Its forms work without JavaScript; [htmx](https://htmx.org) (about 14 KB, embedded in the binary) updates parts of a page in place. There is no frontend build and no Node toolchain. HTTPS uses rustls.
