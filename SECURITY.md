# Security policy

Tocsin is a security tool, so its own security matters. Thank you for helping keep it safe.

## Reporting a vulnerability

**Please do not report security vulnerabilities through public issues.**

Report them privately through GitHub: go to the [Security tab](https://github.com/kevinremoue/tocsin/security) and click **Report a vulnerability**. Please include:

- a description of the issue and its impact;
- steps to reproduce, or a proof of concept;
- the version or commit you tested.

You should receive a first answer within a week. Once the issue is confirmed, a fix will be prepared and released, and you will be credited in the advisory unless you prefer otherwise.

## Supported versions

Tocsin is pre-1.0: only the latest release and the `main` branch receive security fixes.

## Deployment notes

Until dashboard authentication ships (see the roadmap in the [README](README.md)):

- the dashboard (`/` and `/projects/…`) is **unauthenticated** and shows the components of every project: do not expose it to an untrusted network;
- run Tocsin behind a reverse proxy that terminates TLS, since tokens travel in the `Authorization` header;
- treat `TOCSIN_ADMIN_TOKEN` and project tokens as secrets. Only their SHA-256 hashes are stored in the database.
