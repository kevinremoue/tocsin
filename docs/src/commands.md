# Commands

Tocsin is one binary with a few commands. Each reads its settings from the [environment](configuration.md).

| Command | What it does |
|---|---|
| `tocsin` or `tocsin serve` | Runs the HTTP server (API and dashboard) until `SIGTERM` or Ctrl-C. Applies pending migrations first unless `TOCSIN_MIGRATE_ON_START=false`, and runs the periodic jobs if `TOCSIN_SCHEDULER=true`. |
| `tocsin migrate` | Applies pending database migrations, then exits. Safe to run concurrently: migrations take a database lock. |
| `tocsin kev-sync` | Syncs the CISA KEV catalog once, alerts on findings that just became KEV, then exits. |
| `tocsin epss-sync` | Downloads the day's EPSS scores once, keeps those of your CVEs, alerts on findings that reached the EPSS threshold, then exits. |
| `tocsin refresh` | Re-matches every project's latest release against OSV.dev once, records metrics, sends pending alerts, then exits. |
| `tocsin help` | Prints the list of commands. |

Jobs print their result as JSON on standard output and exit with a non-zero status on failure, so a scheduler can detect it:

```sh
$ tocsin kev-sync
{"alerted":0,"kev":{"catalog":"synced","new":2,"total":1769,"updated":1,"version":"2026.11.05"}}
$ tocsin epss-sync
{"alerted":0,"epss":{"date":"2026-11-04","model":"v2026.06.15","scored":192,"scores":"synced","total":400189}}
$ tocsin refresh
{"alerted":1,"fetched":3,"links":162,"purls":256}
```

The same jobs are available over HTTP for schedulers that call URLs: `POST /api/jobs/kev-sync`, `POST /api/jobs/epss-sync` and `POST /api/jobs/refresh`, with the admin token. See the [API](api.md#jobs).
