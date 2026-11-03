# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `POST /api/projects`: create a project (admin token) and get its bearer token.
- `POST /api/sboms`: push a CycloneDX JSON SBOM per release with a project token; purls are extracted, nested components included.
- Server-rendered dashboard listing projects, their releases and the components of the latest release.
- `GET /health` endpoint.
- Docker image and Docker Compose setup.

[Unreleased]: https://github.com/kevinremoue/tocsin/commits/main
