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

- Set `TOCSIN_ADMIN_TOKEN`: it protects the admin API and the dashboard. Without it the dashboard is open, which is only acceptable locally. There are no user accounts yet: everyone with dashboard access shares the admin token.
- Run Tocsin behind TLS (a reverse proxy or a platform such as Cloud Run), since tokens travel in the `Authorization` header.
- Treat `TOCSIN_ADMIN_TOKEN`, project tokens and `TOCSIN_GOOGLE_CHAT_WEBHOOK` as secrets. Only the SHA-256 hashes of tokens are stored in the database.
- SBOMs and vulnerability feeds are untrusted input: the dashboard escapes every value, and only `http(s)` links from feeds are rendered as links.
