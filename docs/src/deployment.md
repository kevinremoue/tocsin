# Deployment

Tocsin is a single binary that needs a Postgres database. There is no other dependency.

> **Before you deploy:** the dashboard has no authentication yet and shows the components of every project. Until [dashboard authentication](roadmap.md) ships, keep Tocsin on a private network, or put it behind a reverse proxy that adds authentication.

## Requirements

- **Postgres**: tested with Postgres 18. Tocsin creates and migrates its schema at startup; the database user needs the right to create tables.
- **Storage**: database size grows with the number and size of the SBOMs you keep, since each document is stored in full.

## Docker image

The repository's `Dockerfile` builds a minimal image that runs as an unprivileged user:

```sh
docker build -t tocsin .
docker run -d --name tocsin -p 3000:3000 \
  -e DATABASE_URL=postgres://tocsin:secret@db.internal:5432/tocsin \
  -e TOCSIN_ADMIN_TOKEN=… \
  tocsin
```

See [Configuration](configuration.md) for all the settings.

The `docker-compose.yml` file in the repository is meant for local use. Its database credentials are for development only: change them for any real deployment.

## From source

With a recent Rust toolchain:

```sh
SQLX_OFFLINE=true cargo build --release
./target/release/tocsin
```

`SQLX_OFFLINE=true` compiles against the query metadata committed in `.sqlx/`, so no database is needed at build time.

## Recommendations

- **TLS.** Run Tocsin behind a reverse proxy (Caddy, nginx, Traefik, a cloud load balancer) that terminates HTTPS. Tokens travel in the `Authorization` header and must not cross the network in clear text.
- **Secrets.** Treat `TOCSIN_ADMIN_TOKEN` and project tokens as secrets. Tocsin only stores their SHA-256 hashes, so a lost project token cannot be recovered: create a new project instead.
- **Admin API.** Set `TOCSIN_ADMIN_TOKEN` only when you need to create projects, if you want to keep the admin API closed the rest of the time.
- **Health checks.** Point your orchestrator or load balancer at `GET /health`: it answers `200` when the database is reachable and `503` otherwise.
- **Backups.** Back up the Postgres database as usual. It holds the projects, token hashes and every SBOM received.
