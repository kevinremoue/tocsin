# Tocsin

**Tocsin rings the alarm when what you run in production is hit by a vulnerability that is being actively exploited.**

A *tocsin* is the alarm bell that towns rang in an emergency. Tocsin, the tool, is a lightweight alternative to [Dependency-Track](https://dependencytrack.org/):

1. Your CI pipelines push a [CycloneDX](https://cyclonedx.org/) SBOM for every production release.
2. Tocsin matches the components against known vulnerabilities.
3. It alerts you **only** when a project is affected by a CVE listed in the [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), the catalog of vulnerabilities known to be exploited in the wild.

No dashboard full of thousands of "medium" findings: one alert per project and exploited CVE, when it matters.

> **Status: early development.** SBOM ingestion, the KEV catalog sync and the dashboard work today. Vulnerability matching and alerting are being built; see the [roadmap](roadmap.md). The dashboard has no authentication yet, so do not expose Tocsin to an untrusted network.

## Why only KEV?

Most dependency scanners report every known CVE. On a real codebase that means hundreds of findings, most of which will never be exploited, and alert fatigue sets in quickly. The KEV catalog lists the vulnerabilities that attackers *are* exploiting. When one of them is in your production stack, you want to know right away, and you want that signal not to be buried.

Tocsin is deliberately narrow: it is not a full vulnerability-management platform. If you need policy engines, license compliance or risk scoring, Dependency-Track is a great fit. Tocsin is for teams that want a small service with a strong signal.

## Design principles

- **Production first.** Matching uses each project's latest release SBOM, which is what runs in production.
- **Strong signal.** Alert on actively exploited CVEs only, and send each (project, CVE) pair once.
- **Small footprint.** A single Rust binary and a Postgres database. No queue, no cache, no JavaScript front end.
- **Standard formats.** CycloneDX SBOMs in, components identified by [package URL](https://github.com/package-url/purl-spec) (purl).

Ready to try it? Head to [Getting started](getting-started.md).
