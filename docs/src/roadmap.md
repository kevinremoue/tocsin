# Roadmap

Tocsin is in early development. Version 0.1.0 will be tagged once a pushed SBOM can trigger an alert end to end.

## Done

- [x] SBOM ingestion API with per-project tokens
- [x] Server-rendered dashboard
- [x] Docker image and Docker Compose setup
- [x] Documentation site

## Next

- [ ] **CISA KEV catalog**: periodic sync and detection of new entries
- [ ] **OSV.dev matching**: purl → CVEs, keeping only those in KEV
- [ ] **Google Chat alerts**: one per (project, CVE), on new KEV entries and on new SBOMs
- [ ] **Dashboard**: KEV CVEs affecting each project, alert history
- [ ] **Dashboard authentication**, required before any exposed deployment

## Later

- [ ] More vulnerability sources: NVD, GitHub Advisories
- [ ] More notification channels: Slack, email, generic webhook

Ideas and feedback are welcome in [GitHub issues](https://github.com/kevinremoue/tocsin/issues).
