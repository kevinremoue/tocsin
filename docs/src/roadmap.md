# Roadmap

Tocsin works end to end but has not been tagged as a release yet. Version 0.1.0 will be tagged once it has been validated on a real serverless deployment.

## Done

- [x] SBOM ingestion API with per-project tokens, gzip uploads
- [x] Vulnerability matching through OSV.dev, all vulnerabilities with severity and CVSS v3
- [x] CISA KEV catalog sync; KEV findings flagged everywhere
- [x] Google Chat alerts: KEV by default, optional severity threshold, once per rule and actionable episode
- [x] Auditing with CycloneDX VEX states, VEX export and import
- [x] Policies: license, severity, KEV
- [x] Metrics with daily history
- [x] Dashboard: portfolio, projects, vulnerabilities, KEV catalog, policies, alerts; protected by the admin token
- [x] Dashboard actions: audit, project creation, SBOM upload, VEX export and import, policies, jobs; history chart
- [x] Serverless-ready: jobs as commands or HTTP endpoints, migrations as a separate step, Cloud Run guide
- [x] Docker image (distroless), documentation site
- [x] EPSS scores next to KEV, with an EPSS policy and alert rule

## Next

- [ ] Validate the Cloud Run guide on a real deployment, then tag 0.1.0
- [ ] More notification channels: Slack, Microsoft Teams, email, generic webhook
- [ ] CVSS v4 scoring
- [ ] Users and roles (read-only vs admin), OIDC login

## Later

- [ ] More vulnerability sources. GitHub Advisories already arrive through OSV.dev; NVD would add CPE-based matching for OS and vendor products
- [ ] CycloneDX XML and SPDX intake
- [ ] More policy kinds: component name or version ranges, license groups
- [ ] Project tags and grouping

Ideas and feedback are welcome in [GitHub issues](https://github.com/kevinremoue/tocsin/issues).
