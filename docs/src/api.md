# API

Tocsin exposes a small JSON REST API. Errors are returned as plain-text messages with the matching HTTP status.

## Authentication

Requests authenticate with a bearer token:

```
Authorization: Bearer <token>
```

There are two kinds of tokens:

- **Admin token**: the value of `TOCSIN_ADMIN_TOKEN`. It can create projects.
- **Project tokens**: returned once when a project is created. A project token can only push SBOMs for its own project.

Tokens are never stored in clear: Tocsin keeps their SHA-256 hash.

## Create a project

```
POST /api/projects
```

**Auth:** admin token.

**Body:**

```json
{"name": "my-service"}
```

`name` must be 1–100 characters from `A-Z a-z 0-9 . _ -`. It is used in dashboard URLs.

**Response:** `201 Created`

```json
{"name": "my-service", "token": "3f9c2b…"}
```

The token is shown only once. Store it in your CI secrets.

| Status | Meaning |
|---|---|
| `400` | Invalid project name. |
| `401` | Missing or wrong admin token. |
| `403` | The admin API is disabled because `TOCSIN_ADMIN_TOKEN` is not set. |
| `409` | A project with this name already exists. |

## Push an SBOM

```
POST /api/sboms[?version=<version>]
```

**Auth:** project token. The project is taken from the token.

**Headers:** `Content-Type: application/json`

**Body:** a CycloneDX JSON document, up to 50 MB. Tocsin stores the document as-is and extracts the purl of every component, nested components included. Components without a purl are skipped.

**Version:** taken from the `version` query parameter, otherwise from `metadata.component.version`. Pushing an existing version replaces its SBOM and components.

**Response:** `201 Created`

```json
{"project": "my-service", "version": "1.4.2", "components": 187}
```

`components` is the number of distinct purls extracted.

| Status | Meaning |
|---|---|
| `400` | Not a CycloneDX document, or no version found. |
| `401` | Missing or wrong project token. |
| `413` | The document is larger than 50 MB. |
| `415` | Missing `Content-Type: application/json`. |

## Health

```
GET /health
```

**Auth:** none. Returns `200 OK` when the database is reachable, `503 Service Unavailable` otherwise.

## Dashboard

| Page | Content |
|---|---|
| `GET /` | The KEV catalog status, then all projects with their latest release, release date, component count and number of releases. |
| `GET /projects/{name}` | The project's releases, and the components of its latest release. |
| `GET /kev` | The KEV catalog, newest first, 100 entries per page. Query parameters: `q` searches the CVE ID, vendor, product and name; `ransomware=on` keeps only entries known to be used in ransomware campaigns; `page` selects the page. |
| `GET /kev/{cve}` | One KEV entry: description, required action, due date, weaknesses (CWE), reference links, and when Tocsin first saw it. `404` if the CVE is not in the catalog. |

The dashboard is server-rendered HTML and has no authentication yet.
