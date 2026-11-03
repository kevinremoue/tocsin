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

This starts Postgres and Tocsin. Migrations run automatically when Tocsin starts. Check that it is up:

```sh
curl http://localhost:3000/health   # 200 OK
```

The admin token lets you create projects. Keep it somewhere safe: Tocsin only stores its hash. If `TOCSIN_ADMIN_TOKEN` is not set, the admin API is disabled.

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
{"project": "my-service", "version": "1.4.2", "components": 187}
```

If you leave out `?version=`, Tocsin uses `metadata.component.version` from the SBOM.

## 4. Open the dashboard

Go to <http://localhost:3000>. You see your project with its latest release; click it to see every release and the components of the latest one.

## Next steps

- Automate the push in your pipelines: [Pushing SBOMs from CI](ci-integration.md).
- Run Tocsin for your team: [Deployment](deployment.md).
- Stop the local stack with `docker compose down` (add `-v` to delete the data).
