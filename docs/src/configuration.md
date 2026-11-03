# Configuration

Tocsin is configured entirely through environment variables.

| Variable | Default | Description |
|---|---|---|
| `DATABASE_URL` | *(required)* | Postgres connection string, for example `postgres://user:password@host:5432/tocsin`. Pending migrations run automatically at startup. |
| `TOCSIN_ADMIN_TOKEN` | *(unset)* | Token for the admin API (`POST /api/projects`). When unset or empty, the admin API answers `403` and a warning is logged at startup. |
| `BIND_ADDR` | `0.0.0.0:3000` | Address and port to listen on. |
| `TOCSIN_KEV_URL` | CISA feed | URL of the KEV catalog in [CISA's JSON format](https://www.cisa.gov/known-exploited-vulnerabilities-catalog). The default is `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`; point it to a mirror if Tocsin cannot reach cisa.gov. |
| `TOCSIN_KEV_SYNC_MINUTES` | `360` | How often to check the KEV catalog, in minutes. The first check runs at startup. |
| `RUST_LOG` | `info` | Log filter, in [`tracing-subscriber` syntax](https://docs.rs/tracing-subscriber/latest/tracing_subscriber/filter/struct.EnvFilter.html). For example `debug`, or `tocsin=debug,sqlx=warn`. |

Settings for the other vulnerability sources and for notifications will be added here as those features ship.

## Limits

| Limit | Value |
|---|---|
| SBOM upload size | 50 MB |
| Project name | 1–100 characters from `A-Z a-z 0-9 . _ -` |
