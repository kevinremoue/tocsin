# Deploying Tocsin

Tocsin is a single binary that needs a Postgres database, outbound HTTPS, and something to trigger its periodic jobs. It runs the same way on a VM, in Kubernetes, or on a serverless platform such as [Cloud Run](cloud-run.md).

## Requirements

- **Postgres**: tested with Postgres 18. The database user needs the right to create tables for migrations.
- **Outbound HTTPS** to `api.osv.dev` (vulnerabilities), `www.cisa.gov` (KEV catalog), and your notification webhook. If your network blocks them, mirror the feeds and set `TOCSIN_OSV_URL` and `TOCSIN_KEV_URL`.
- **Resources**: about 20 MB of memory and a fraction of a CPU. Storage grows with the number and size of SBOMs you keep, since each document is stored in full.

## Three things to run

| What | Command | When |
|---|---|---|
| Migrations | `tocsin migrate` | Before starting a new version |
| The server | `tocsin serve` (the default) | Always, or on demand on serverless |
| The jobs | `tocsin kev-sync`, `tocsin refresh`, `tocsin epss-sync` | Every 6 hours, every day, and every day after 13:30 UTC (after the refresh) |

See [Commands](commands.md) for the details.

**Migrations** also run when the server starts, unless `TOCSIN_MIGRATE_ON_START=false`. On a single server that is the simplest setup. With many instances (serverless, Kubernetes), run `tocsin migrate` as a deployment step and turn the automatic run off, so instances start faster.

**Jobs** can run in three ways; pick one:

- **Built-in scheduler**: set `TOCSIN_SCHEDULER=true` and the server runs them at their interval. Fine for an always-on server; on a platform that scales to zero, the jobs stop with the instance.
- **Commands**: run `tocsin kev-sync`, `tocsin refresh` and `tocsin epss-sync` from cron, a Kubernetes CronJob or Cloud Run jobs. Each runs once and exits.
- **HTTP**: `POST /api/jobs/kev-sync`, `POST /api/jobs/refresh` and `POST /api/jobs/epss-sync` with the admin token, from any scheduler that can send an authenticated request.

## Docker image

The repository's `Dockerfile` builds a small distroless image (no shell) that runs as an unprivileged user:

```sh
docker build -t tocsin .
docker run --rm tocsin migrate   # with DATABASE_URL set
docker run -d --name tocsin -p 3000:3000 \
  -e DATABASE_URL=postgres://tocsin:secret@db.internal:5432/tocsin \
  -e TOCSIN_ADMIN_TOKEN=… -e TOCSIN_SCHEDULER=true \
  tocsin
```

See [Configuration](configuration.md) for all the settings. The `docker-compose.yml` file in the repository is meant for local use; its database credentials are for development only.

## From source

With a recent Rust toolchain:

```sh
SQLX_OFFLINE=true cargo build --release
./target/release/tocsin
```

`SQLX_OFFLINE=true` compiles against the query metadata committed in `.sqlx/`, so no database is needed at build time.

## Recommendations

- **TLS.** Run Tocsin behind a reverse proxy or a platform (Cloud Run, a load balancer) that terminates HTTPS. Tokens travel in the `Authorization` header.
- **Dashboard access.** The dashboard requires the admin token (HTTP Basic auth: any user name, the token as password). There are no user accounts yet: everyone with dashboard access uses the same token. Put an identity-aware proxy in front if you need per-user access.
- **Secrets.** Treat `TOCSIN_ADMIN_TOKEN`, project tokens and the webhook URL as secrets. Tocsin only stores the hashes of tokens, so a lost project token cannot be recovered: create a new project instead.
- **Database connections.** Each instance opens up to `TOCSIN_DB_MAX_CONNECTIONS` (5 by default). Multiply by your maximum instance count and keep it under the database's connection limit.
- **Health checks.** Point your orchestrator at `GET /health`: `200` when the database is reachable, `503` otherwise. It needs no authentication.
- **Shutdown.** Tocsin stops gracefully on `SIGTERM`, finishing in-flight requests.
- **Backups.** Back up the Postgres database as usual. It holds the projects, token hashes, SBOMs, analyses and policies; vulnerability data can be re-fetched.
