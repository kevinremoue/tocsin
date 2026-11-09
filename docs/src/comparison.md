# Tocsin and Dependency-Track

[Dependency-Track](https://dependencytrack.org/) is the reference open-source platform for SBOM analysis, maintained by OWASP. Tocsin covers the core of the same job in a much smaller footprint. This page is an honest comparison, to help you choose.

## Resources

| | Tocsin | Dependency-Track |
|---|---|---|
| Runtime | One Rust binary (~10 MB), distroless image | Java API server, separate front end |
| Memory | ~20 MB | 4.5 GB minimum, 16 GB recommended |
| Scale to zero | Yes | No |
| Database | Postgres | Postgres, and others |

## Features

| Feature | Tocsin | Dependency-Track |
|---|---|---|
| CycloneDX JSON intake over REST | ✅ (gzip accepted) | ✅ |
| CycloneDX XML | ❌ | ✅ |
| SPDX | ❌ | ❌ |
| Matching by package URL | ✅ | ✅ |
| Matching by CPE (OS, vendor products) | ❌ | ✅ |
| Vulnerability sources | OSV.dev (includes GitHub Advisories), CISA KEV, FIRST EPSS | NVD, GitHub Advisories, OSV, Snyk, OSS Index, VulnDB, … |
| Severity and CVSS | ✅ (CVSS v3) | ✅ (v2, v3, v4, OWASP risk rating) |
| EPSS scores | ✅ (with policies and alerts) | ✅ |
| Actively exploited (CISA KEV) as a first-class signal | ✅ | ❌ (EPSS instead) |
| Audit (analysis states, justifications) | ✅ (UI and API) | ✅ (UI and API) |
| VEX export and import | ✅ CycloneDX | ✅ CycloneDX |
| Policies | License, severity, KEV | License, license group, severity, component, age, coordinates, … |
| Metrics and history | ✅ daily | ✅ |
| Notifications | Google Chat | Slack, Teams, email, webhooks, Jira, … |
| Users, teams, permissions | ❌ one admin token | ✅ LDAP, OIDC |
| Project hierarchy, tags | ❌ | ✅ |
| Dashboard | Server-rendered, works without JavaScript; projects, uploads, audit, VEX, policies and jobs | Rich web application |

## When to pick which

**Tocsin** fits when you want the essential signal (what we run in production, and which of it is under active attack) with almost no infrastructure and operating cost, and your components are identified by package URL.

**Dependency-Track** fits when you need its breadth: CPE matching for OS and vendor products, many vulnerability sources and notification channels, multiple users and teams, or rich policy management in a UI.

Several of the gaps above are on the [roadmap](roadmap.md).
