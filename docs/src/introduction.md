# Tocsin

**Know which vulnerabilities affect what you run in production, and get alerted when one is actively exploited.**

A *tocsin* is the alarm bell that towns rang in an emergency. Tocsin, the tool, is a lightweight, serverless-ready alternative to [Dependency-Track](https://dependencytrack.org/):

1. Your CI pipelines push a [CycloneDX](https://cyclonedx.org/) SBOM for every production release.
2. Tocsin matches each component against known vulnerabilities from [OSV.dev](https://osv.dev), with their severity.
3. Vulnerabilities in the [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), the ones known to be exploited in the wild, are flagged first and trigger an alert.
4. You audit findings (not affected, false positive, resolved…), define policies, and follow metrics over time.

> **Status: early development.** Tocsin works end to end but has not been tagged as a release yet. See the [roadmap](roadmap.md).

## Why another tool?

Dependency-Track is the reference open-source platform for SBOM analysis. It is also a Java application that needs several gigabytes of memory and runs all the time. Tocsin covers the core of the same job:

| | Tocsin | Dependency-Track |
|---|---|---|
| Runtime | One Rust binary, ~10 MB | Java API server + front end |
| Memory | ~20 MB | 4.5 GB minimum, 16 GB recommended |
| Startup | Under a second | Tens of seconds to minutes |
| Scale to zero | Yes: periodic work runs as jobs | No: background tasks run in the server |
| Database | Postgres | Postgres (or others) |

Tocsin is deliberately smaller in scope. The [comparison page](comparison.md) lists what it covers and what it does not.

## Actively exploited first

A real codebase easily has dozens or hundreds of known vulnerabilities, most of which will never be exploited. Tocsin shows them all, like Dependency-Track, but puts the ones in the KEV catalog first, everywhere, and alerts on them by default. When one of them is in your production stack, you hear about it right away, and the signal is not buried.

## Design principles

- **Production first.** Matching uses each project's latest release SBOM, which is what runs in production.
- **Strong signal.** Alert on actively exploited CVEs by default, and send each rule once per actionable episode.
- **Small footprint.** A single binary and a Postgres database. No queue, no cache, no frontend build: the dashboard is rendered on the server.
- **Serverless-ready.** No long-running work in the server: scheduled jobs run on demand, so instances can scale to zero.
- **Standard formats.** CycloneDX SBOMs in, CycloneDX VEX in and out, components identified by [package URL](https://github.com/package-url/purl-spec), advisories in the [OSV schema](https://ossf.github.io/osv-schema/).

Ready to try it? Head to [Getting started](getting-started.md).
