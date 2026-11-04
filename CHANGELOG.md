# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- SBOM intake: `POST /api/sboms` with a project token, CycloneDX JSON, gzip-compressed uploads accepted; component purls and licenses extracted, nested components included.
- Vulnerability matching through OSV.dev for every component, during the push (bounded to 60 s) and in the refresh job; advisories grouped by CVE, severity from GitHub ratings or CVSS v3 scores.
- CISA KEV catalog sync with conditional requests; KEV findings flagged everywhere.
- Google Chat alerts, once per project and vulnerability: KEV by default (`TOCSIN_ALERT_KEV`), optional severity threshold (`TOCSIN_ALERT_MIN_SEVERITY`).
- Auditing with CycloneDX VEX states and justifications; VEX export and import.
- Policies on licenses, severity and KEV, with violations.
- EPSS scores from FIRST's daily file (`epss-sync` job, conditional download, only known CVEs kept): shown on findings, used to order them, `epss` policy kind and `TOCSIN_ALERT_MIN_EPSS` alert rule.
- Daily metrics per project.
- Findings API for CI gating: `GET /api/projects/{name}/findings`.
- Dashboard: portfolio, projects, vulnerabilities, KEV catalog, policies, alerts; protected by the admin token.
- Commands `serve`, `migrate`, `kev-sync`, `epss-sync` and `refresh`; jobs also over `POST /api/jobs/{job}`; optional in-process scheduler (`TOCSIN_SCHEDULER`). Graceful shutdown on SIGTERM.
- Distroless Docker image, Docker Compose setup, documentation site with a Cloud Run guide.

[Unreleased]: https://github.com/kevinremoue/tocsin/commits/main
