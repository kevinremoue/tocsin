# Getting started

This guide runs Tocsin locally with Docker Compose, creates a project and pushes a first SBOM. It takes about five minutes.

## Prerequisites

- Docker with the Compose plugin
- `curl` and `openssl` (to generate a token)

## 1. Start Tocsin

```sh
git clone https://github.com/kevinremoue/tocsin.git
cd tocsin
export TOCSIN_ADMIN_TOKEN=$(openssl rand -hex 32)
docker compose up -d --build
```

This starts Postgres and Tocsin. At startup Tocsin applies its migrations, then (because Compose enables the built-in scheduler) downloads the KEV catalog. Check that it is up:

```sh
curl http://localhost:3000/health   # 200 OK
```

The admin token creates projects and protects the dashboard. Keep it somewhere safe: Tocsin only stores its hash.

## 2. Create a project

A project is one application or service whose releases you want to monitor.

```sh
curl -X POST http://localhost:3000/api/projects \
  -H "Authorization: Bearer $TOCSIN_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name": "my-service"}'
```

```json
{"name": "my-service", "token": "3f9c…"}
```

The project token is shown **only once**. It is the secret your CI uses to push SBOMs for this project, and only for this project.

```sh
export PROJECT_TOKEN=3f9c…
```

## 3. Push an SBOM

Generate a CycloneDX JSON SBOM for your application, for example with [Syft](https://github.com/anchore/syft):

```sh
syft path/to/my-service -o cyclonedx-json=bom.json
```

Then push it for a release version:

```sh
curl -X POST "http://localhost:3000/api/sboms?version=1.4.2" \
  -H "Authorization: Bearer $PROJECT_TOKEN" \
  -H "Content-Type: application/json" \
  --data-binary @bom.json
```

```json
{"project": "my-service", "version": "1.4.2", "components": 187,
 "matching": "done", "findings": 12, "kev": 1, "alerted": 0}
```

Tocsin stored the release, matched its components against OSV.dev, and found 12 vulnerabilities, one of them actively exploited. `alerted` is 0 because no notification channel is configured yet: see [Alerts](alerts.md).

If you leave out `?version=`, Tocsin uses `metadata.component.version` from the SBOM.

## 4. Open the dashboard

Go to <http://localhost:3000>. Your browser asks for credentials: use any user name, and the admin token as password.

- **Projects** shows the portfolio: findings per project and severity, KEV first.
- Click a project to see its vulnerabilities, policy violations, history, releases and components. From there you can also audit findings, upload another release and export or import VEX.
- You can also create projects from the dashboard, manage **Policies**, and run the jobs from the **Projects** page.
- **Vulnerabilities** lists every vulnerability affecting your projects; **KEV catalog** browses the catalog and shows which entries affect you.

## Next steps

- Automate post-deployment production declarations in your pipelines: [Pushing SBOMs from CI](ci-integration.md).
- Triage findings: [Vulnerabilities and auditing](vulnerabilities.md).
- Get notified: [Alerts](alerts.md).
- Run Tocsin for your team: [Deploying Tocsin](deployment.md), or [serverless on Cloud Run](cloud-run.md).
- Stop the local stack with `docker compose down` (add `-v` to delete the data).
