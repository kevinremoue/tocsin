# API

Tocsin exposes a JSON REST API. Errors are returned as plain-text messages with the matching HTTP status.

## Authentication

Requests authenticate with a bearer token:

```
Authorization: Bearer <token>
```

There are two kinds of tokens:

- **Admin token**: the value of `TOCSIN_ADMIN_TOKEN`. It can do everything.
- **Project tokens**: returned once when a project is created. A project token can push SBOMs for its project, and read or audit that project only.

Tokens are never stored in clear: Tocsin keeps their SHA-256 hash. For endpoints under `/api/projects/{name}/…`, both the admin token and that project's token work; any other token gets `404`, so project names cannot be probed.

| Endpoint | Token |
|---|---|
| `POST /api/projects`, `GET /api/projects` | admin |
| `POST /api/sboms` | project |
| `GET /api/projects/{name}/findings`, `…/violations`, `…/vex` | admin or project |
| `PUT`, `DELETE /api/projects/{name}/analyses/{id}`, `POST …/vex` | admin or project |
| `GET`, `POST /api/policies`, `DELETE /api/policies/{id}` | admin |
| `POST /api/jobs/{job}` | admin |
| `GET /health` | none |

## Projects

### Create a project

```
POST /api/projects
{"name": "my-service"}
```

`name` must be 1–100 characters from `A-Z a-z 0-9 . _ -`. Returns `201` with the project token, shown only once:

```json
{"name": "my-service", "token": "3f9c2b…"}
```

`400` invalid name · `401` wrong admin token · `403` admin API disabled (`TOCSIN_ADMIN_TOKEN` unset) · `409` name taken.

### List projects

```
GET /api/projects
```

```json
[{"name": "my-service", "version": "1.4.2", "findings": 12, "kev": 1, "critical": 2, "high": 5}]
```

Counts cover unsuppressed findings of the latest release.

## SBOMs

```
POST /api/sboms[?version=<version>]
Content-Type: application/json
[Content-Encoding: gzip]
```

**Body:** a CycloneDX JSON document, up to 50 MB once decompressed. The project comes from the token. The version comes from `?version=`, otherwise from `metadata.component.version`. Pushing an existing version replaces its SBOM and components.

Tocsin extracts the purl and licenses of every component, nested components included, then matches the components against the vulnerability sources (see [Pushing SBOMs from CI](ci-integration.md#the-push-response)).

**Response:** `201`

```json
{"project": "my-service", "version": "1.4.2", "components": 187,
 "matching": "done", "findings": 12, "kev": 1, "alerted": 1}
```

`400` not CycloneDX, or no version · `401` wrong token · `413` too large · `415` missing `Content-Type`.

## Findings

```
GET /api/projects/{name}/findings[?suppressed=true]
```

The vulnerabilities affecting the project's latest release, KEV first, then by EPSS score, then by severity. Suppressed findings are left out unless `?suppressed=true`.

```json
{"project": "my-service", "findings": [{
  "id": "CVE-2021-44228",
  "advisories": ["CVE-2021-44228", "GHSA-jfh8-c2jp-5v3q"],
  "severity": "critical", "cvss": 10.0, "kev": true,
  "epss": {"score": 0.94358, "percentile": 0.99956},
  "summary": "Remote code injection in Log4j",
  "components": ["pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"],
  "analysis": {"state": "in_triage", "justification": null, "detail": null},
  "suppressed": false
}]}
```

`id` is the flaw's CVE, or the advisory ID when it has none. `epss` is the highest [EPSS](vulnerabilities.md#likely-to-be-exploited-epss) score among the flaw's CVEs, `null` when it has none yet. `analysis` is `null` until a decision is recorded.

## Audit

```
PUT /api/projects/{name}/analyses/{id}
{"state": "not_affected", "justification": "code_not_reachable", "detail": "…"}
```

Records a decision. `{id}` is the CVE or any advisory ID of the flaw. `state` is one of `in_triage`, `exploitable`, `not_affected`, `false_positive`, `resolved`; `justification` and `detail` are optional. See [Vulnerabilities and auditing](vulnerabilities.md#auditing) for the values. Returns the stored analysis; `400` for an invalid state or justification.

```
DELETE /api/projects/{name}/analyses/{id}
```

Removes the decision. Returns `204`.

## VEX

```
GET /api/projects/{name}/vex
```

The project's findings and analyses as a CycloneDX 1.6 VEX document.

```
POST /api/projects/{name}/vex
Content-Type: application/json
```

Imports the `analysis` of each vulnerability of a CycloneDX VEX document. Returns `{"imported": 3, "skipped": ["CVE-…: no analysis.state"]}`.

## Policies

```
GET /api/policies
POST /api/policies          {"name": "No critical", "kind": "severity", "value": "critical"}
DELETE /api/policies/{id}
GET /api/projects/{name}/violations
```

`kind` is `license` (value: SPDX ID), `severity` (value: `critical`, `high`, `medium` or `low`), `kev`, or `epss` (value: a probability such as `0.5`, or a percentage such as `50%`; stored as a probability). See [Policies](policies.md).

## Jobs

```
POST /api/jobs/kev-sync
POST /api/jobs/refresh
POST /api/jobs/epss-sync
```

Runs a job now and returns its result, for schedulers that call URLs. The same jobs run as [commands](commands.md). `404` unknown job · `502` the job failed (its error in the body).

```json
{"kev": {"catalog": "synced", "version": "2026.11.03", "new": 1, "updated": 0, "total": 1767}, "alerted": 1}
{"purls": 256, "links": 162, "fetched": 3, "alerted": 0}
{"epss": {"scores": "synced", "model": "v2026.06.15", "date": "2026-11-04", "scored": 192, "total": 400189}, "alerted": 0}
```

## Health

```
GET /health
```

No authentication. `200` when the database is reachable, `503` otherwise.

## Dashboard

The dashboard pages require the admin token, as the password of HTTP Basic auth (any user name) or as a bearer token, unless `TOCSIN_DASHBOARD_PUBLIC=true`.

| Page | Content |
|---|---|
| `/` | Portfolio: KEV and EPSS sync status, totals, and each project's latest release, findings per severity, KEV count, violations. |
| `/projects/{name}` | Findings (`?suppressed=on` to include suppressed ones), policy violations, daily history, releases, components with licenses. |
| `/vulns` | Every flaw affecting a project. `q` searches, `kev=on` keeps KEV ones, `page` paginates. |
| `/vulns/{id}` | A flaw: affected projects, advisories, details, references. `{id}` is the CVE or an advisory ID. |
| `/kev` | The KEV catalog. `q` searches, `ransomware=on`, `affecting=on` (only entries affecting a project), `page`. |
| `/kev/{cve}` | A KEV entry, and the projects it affects. |
| `/policies` | Policies and their violations. |
| `/alerts` | Alerts sent, and the current rules. |
