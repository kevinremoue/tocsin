# Contributing

Contributions are welcome: bug reports, ideas, documentation and code. The full guide is [CONTRIBUTING.md](https://github.com/kevinremoue/tocsin/blob/main/CONTRIBUTING.md) in the repository. This page covers the essentials.

## Development setup

You need [mise](https://mise.jdx.dev/) and Docker.

```sh
git clone https://github.com/kevinremoue/tocsin.git
cd tocsin
mise install     # pinned Rust toolchain, sqlx-cli and mdBook
mise run dev     # Postgres on port 5433, migrations, then cargo run
```

| Task | What it does |
|---|---|
| `mise run test` | Run the tests. Filter with `mise run test -- <name>`. |
| `mise run lint` | `cargo fmt --check`, clippy with `-D warnings`, and the `.sqlx/` freshness check. |
| `mise run db:prepare` | Refresh `.sqlx/` after changing a SQL query. |
| `mise run docs:serve` | Preview this documentation at <http://localhost:3001>. |

## Documentation

This site is built with [mdBook](https://rust-lang.github.io/mdBook/) from the `docs/` folder of the repository. Each page has an edit button at the top right that opens it on GitHub. To change the page list, edit `docs/src/SUMMARY.md`.

## Security issues

Please do not open public issues for vulnerabilities. Follow the [security policy](https://github.com/kevinremoue/tocsin/blob/main/SECURITY.md) instead.
