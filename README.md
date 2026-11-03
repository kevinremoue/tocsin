# 🔔 Tocsin

[![CI](https://github.com/kevinremoue/tocsin/actions/workflows/ci.yml/badge.svg)](https://github.com/kevinremoue/tocsin/actions/workflows/ci.yml)
[![Docs](https://img.shields.io/badge/docs-kevinremoue.github.io%2Ftocsin-blue.svg)](https://kevinremoue.github.io/tocsin/)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

**Tocsin rings the alarm when what you run in production is hit by a vulnerability that is being actively exploited.**

It is a lightweight alternative to [Dependency-Track](https://dependencytrack.org/): your CI pipelines push a CycloneDX SBOM for every production release, Tocsin matches the components against known vulnerabilities, and alerts you only when a project is affected by a CVE listed in the [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) (Known Exploited Vulnerabilities).

No dashboard full of thousands of "medium" findings: one alert per project and exploited CVE, when it matters.

> [!WARNING]
> **Tocsin is in early development.** SBOM ingestion, the KEV catalog sync and the dashboard work today; vulnerability matching and alerting are being built (see the [roadmap](https://kevinremoue.github.io/tocsin/roadmap.html)). The dashboard has no authentication yet: do not expose Tocsin to an untrusted network.

## How it works

```
CI pipeline ──(CycloneDX SBOM)──▶ Tocsin ◀── OSV.dev (CVE ↔ package)
                                    │    ◀── CISA KEV (actively exploited CVEs)
                                    ▼
                            Google Chat alert
```

- **One SBOM per release**, matched by [package URL](https://github.com/package-url/purl-spec). Tocsin matches against each project's latest release, which is what runs in production.
- **Alert only on KEV**, and each (project, CVE) pair only once.
- **Small footprint**: a single Rust binary and a Postgres database.

## Quick start

```sh
git clone https://github.com/kevinremoue/tocsin.git && cd tocsin
export TOCSIN_ADMIN_TOKEN=$(openssl rand -hex 32)
docker compose up -d --build
```

Tocsin is now on <http://localhost:3000>. Create a project, then push an SBOM with the token it returns:

```sh
curl -X POST http://localhost:3000/api/projects \
  -H "Authorization: Bearer $TOCSIN_ADMIN_TOKEN" \
  -H "Content-Type: application/json" -d '{"name": "my-service"}'

curl -X POST "http://localhost:3000/api/sboms?version=1.4.2" \
  -H "Authorization: Bearer $PROJECT_TOKEN" \
  -H "Content-Type: application/json" --data-binary @bom.json
```

The [getting started guide](https://kevinremoue.github.io/tocsin/getting-started.html) walks through it step by step.

## Documentation

The full documentation is at **<https://kevinremoue.github.io/tocsin/>**:

- [Pushing SBOMs from CI](https://kevinremoue.github.io/tocsin/ci-integration.html) (GitHub Actions, GitLab CI)
- [Deployment](https://kevinremoue.github.io/tocsin/deployment.html)
- [Configuration](https://kevinremoue.github.io/tocsin/configuration.html) and [API reference](https://kevinremoue.github.io/tocsin/api.html)
- [How it works](https://kevinremoue.github.io/tocsin/how-it-works.html)

Its sources are in [`docs/`](docs/). Preview them locally with `mise run docs:serve`.

## Contributing

Bug reports, ideas and pull requests are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for the development setup. To report a vulnerability, follow [SECURITY.md](SECURITY.md).

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <https://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <https://opensource.org/licenses/MIT>)

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
