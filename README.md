# 🔔 Tocsin

[![CI](https://github.com/kevinremoue/tocsin/actions/workflows/ci.yml/badge.svg)](https://github.com/kevinremoue/tocsin/actions/workflows/ci.yml)
[![Docs](https://img.shields.io/badge/docs-kevinremoue.github.io%2Ftocsin-blue.svg)](https://kevinremoue.github.io/tocsin/)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

**Know which vulnerabilities affect what you run in production, and get alerted when one is actively exploited.**

Tocsin is a lightweight, serverless-ready alternative to [Dependency-Track](https://dependencytrack.org/). Your CI pipelines push a CycloneDX SBOM for each production release; Tocsin tracks every known vulnerability affecting its components (from [OSV.dev](https://osv.dev)), highlights the ones in the [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) of actively exploited vulnerabilities, ranks the rest by their [EPSS](https://www.first.org/epss) probability of exploitation, and alerts you on Google Chat.

It is a single 10 MB Rust binary using about 20 MB of memory, with Postgres as its only dependency. It scales to zero on Cloud Run and similar platforms.

> [!WARNING]
> **Tocsin is in early development** and not yet tagged as a release. See the [roadmap](https://kevinremoue.github.io/tocsin/roadmap.html).

## Features

- **SBOM intake** over a REST API: CycloneDX JSON, gzip accepted, one SBOM per release. Tocsin matches each project's latest release, which is what runs in production.
- **All known vulnerabilities** for each component, matched by [package URL](https://github.com/package-url/purl-spec) through OSV.dev (GitHub Advisories, PyPI, npm, Maven, Go, RustSec, Debian, Alpine, …), with severity and CVSS score. Advisories describing the same flaw are grouped under its CVE.
- **Actively exploited first**: CVEs in the CISA KEV catalog are flagged everywhere and trigger alerts.
- **Likely to be exploited next**: each finding's EPSS score, from FIRST's daily file.
- **Alerts** on Google Chat, once per project and vulnerability: on KEV CVEs by default, and optionally above a severity or EPSS threshold.
- **Auditing** from the dashboard or the API: mark findings as not affected, false positive, resolved…, with CycloneDX VEX export and import.
- **Policies** on licenses, severity, KEV and EPSS, with their violations.
- **Metrics**: per-project and portfolio counts, with daily history.
- **Dashboard**: server-rendered and light (no frontend build, works without JavaScript); create projects, upload SBOMs, audit, manage policies and run jobs. Protected by the admin token.
- **CI gating**: query a project's findings to fail a build when it ships a KEV CVE.

## Quick start

```sh
git clone https://github.com/kevinremoue/tocsin.git && cd tocsin
export TOCSIN_ADMIN_TOKEN=$(openssl rand -hex 32)
docker compose up -d --build
```

Create a project, then push an SBOM with the token it returns:

```sh
curl -X POST http://localhost:3000/api/projects \
  -H "Authorization: Bearer $TOCSIN_ADMIN_TOKEN" \
  -H "Content-Type: application/json" -d '{"name": "my-service"}'

curl -X POST "http://localhost:3000/api/sboms?version=1.4.2" \
  -H "Authorization: Bearer $PROJECT_TOKEN" \
  -H "Content-Type: application/json" --data-binary @bom.json
# {"project":"my-service","version":"1.4.2","components":187,"matching":"done","findings":12,"kev":1,...}
```

Open <http://localhost:3000> and log in with any user name and the admin token as password. The [getting started guide](https://kevinremoue.github.io/tocsin/getting-started.html) walks through it step by step.

## Documentation

The full documentation is at **<https://kevinremoue.github.io/tocsin/>**:

- [Pushing SBOMs from CI](https://kevinremoue.github.io/tocsin/ci-integration.html), [vulnerabilities and auditing](https://kevinremoue.github.io/tocsin/vulnerabilities.html), [policies](https://kevinremoue.github.io/tocsin/policies.html), [alerts](https://kevinremoue.github.io/tocsin/alerts.html)
- [Deployment](https://kevinremoue.github.io/tocsin/deployment.html) and [serverless on Cloud Run](https://kevinremoue.github.io/tocsin/cloud-run.html)
- [Configuration](https://kevinremoue.github.io/tocsin/configuration.html), [API](https://kevinremoue.github.io/tocsin/api.html), [commands](https://kevinremoue.github.io/tocsin/commands.html)
- [Tocsin and Dependency-Track](https://kevinremoue.github.io/tocsin/comparison.html): what is covered, what is not

Its sources are in [`docs/`](docs/). Preview them locally with `mise run docs:serve`.

## Contributing

Bug reports, ideas and pull requests are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for the development setup. To report a vulnerability, follow [SECURITY.md](SECURITY.md).

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <https://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <https://opensource.org/licenses/MIT>)

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
