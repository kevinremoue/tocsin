# Configuration

Tocsin is configured entirely through environment variables. Boolean settings accept `true`/`false` (also `1`/`0`, `yes`/`no`, `on`/`off`).

## Server and database

| Variable | Default | Description |
|---|---|---|
| `DATABASE_URL` | *(required)* | Postgres connection string, for example `postgres://user:password@host:5432/tocsin`. |
| `BIND_ADDR` | `0.0.0.0:3000` | Address and port to listen on. |
| `TOCSIN_DB_MAX_CONNECTIONS` | `5` | Database connections per instance. Keep instances × connections under the database's limit. |
| `TOCSIN_MIGRATE_ON_START` | `true` | Apply pending migrations when `serve` starts. Set to `false` when migrations run as a deployment step (`tocsin migrate`). |
| `RUST_LOG` | `info` | Log filter, in [`tracing-subscriber` syntax](https://docs.rs/tracing-subscriber/latest/tracing_subscriber/filter/struct.EnvFilter.html). For example `debug`, or `tocsin=debug,sqlx=warn`. |

## Access

| Variable | Default | Description |
|---|---|---|
| `TOCSIN_ADMIN_TOKEN` | *(unset)* | Token for the admin API (projects, policies, jobs) and the dashboard. When unset, the admin API answers `403` and the dashboard is open: only acceptable locally. |
| `TOCSIN_DASHBOARD_PUBLIC` | `false` | Serve the dashboard without authentication even when an admin token is set. |
| `TOCSIN_PUBLIC_URL` | *(unset)* | Base URL of the dashboard, e.g. `https://tocsin.example.com`. Used for links in alerts. |

## Jobs and vulnerability data

| Variable | Default | Description |
|---|---|---|
| `TOCSIN_SCHEDULER` | `false` | Run the periodic jobs inside `serve`. Leave off on serverless platforms and trigger the jobs externally (see [Deploying Tocsin](deployment.md)). |
| `TOCSIN_KEV_SYNC_MINUTES` | `360` | Interval of the KEV sync, for the built-in scheduler. |
| `TOCSIN_REFRESH_MINUTES` | `1440` | Interval of the vulnerability refresh, for the built-in scheduler. Also how recent a component's last match must be for an SBOM push to skip it. |
| `TOCSIN_EPSS_SYNC_MINUTES` | `1440` | Interval of the EPSS sync, for the built-in scheduler. FIRST publishes new scores once a day, shortly after 13:30 UTC. |
| `TOCSIN_MATCH_ON_PUSH` | `true` | Match a pushed SBOM's new components within the push request (at most 60 seconds). When `false`, the refresh job does it. |
| `TOCSIN_KEV_URL` | CISA feed | URL of the KEV catalog in [CISA's JSON format](https://www.cisa.gov/known-exploited-vulnerabilities-catalog). The default is `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`. |
| `TOCSIN_OSV_URL` | `https://api.osv.dev` | Base URL of the OSV API, for a mirror or proxy. |
| `TOCSIN_EPSS_URL` | FIRST daily file | URL of the daily EPSS scores file (CSV, gzipped or not). The default is `https://epss.empiricalsecurity.com/epss_scores-current.csv.gz`. |

## Alerts

| Variable | Default | Description |
|---|---|---|
| `TOCSIN_GOOGLE_CHAT_WEBHOOK` | *(unset)* | Google Chat incoming webhook URL. Without it, alerts are not sent (nor recorded). |
| `TOCSIN_ALERT_KEV` | `true` | Alert on findings in the KEV catalog. |
| `TOCSIN_ALERT_MIN_SEVERITY` | *(unset)* | Also alert on findings at least this severe: `critical`, `high`, `medium` or `low`. |
| `TOCSIN_ALERT_MIN_EPSS` | *(unset)* | Also alert on findings with an EPSS score at least this high: a probability (`0.5`) or a percentage (`50%`). |

## Limits

| Limit | Value |
|---|---|
| SBOM and VEX upload size | 50 MB once decompressed (gzip accepted) |
| Matching time during a push | 60 seconds, then deferred to the refresh job |
| Project name | 1–100 characters from `A-Z a-z 0-9 . _ -` |
