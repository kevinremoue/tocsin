# Contributing to Tocsin

Thanks for your interest in Tocsin! Bug reports, ideas and pull requests are all welcome.

## Before you start

- **Bugs and ideas:** open an [issue](https://github.com/kevinremoue/tocsin/issues). For a bigger change, please describe it in an issue first, so we can agree on the approach before you spend time on code.
- **Security issues:** do not open a public issue; follow [SECURITY.md](SECURITY.md).
- Everyone taking part in the project is expected to follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## Development setup

You need [mise](https://mise.jdx.dev/) and Docker.

```sh
mise install     # pinned Rust toolchain, sqlx-cli and mdBook
mise run dev     # Postgres on port 5433, migrations, then cargo run
```

Useful tasks (`mise tasks` lists them all):

| Task | What it does |
|---|---|
| `mise run test` | Run the tests. Filter with `mise run test -- <name>`. |
| `mise run lint` | `cargo fmt --check`, clippy with `-D warnings`, and the `.sqlx/` freshness check. |
| `mise run fmt` | Format the code. |
| `mise run db:prepare` | Refresh `.sqlx/` after changing a SQL query. |
| `mise run db:down` | Stop the local stack. |
| `mise run docs:serve` | Preview the documentation site at <http://localhost:3001>. |
| `mise run seed` | Load the example projects of `examples/sboms/` into the running dev server. |
| `mise run db:reset` | Drop and recreate the local database. |

To try Tocsin with realistic data: run `mise run dev` in one terminal and `mise run seed` in another, then open <http://localhost:3000> (any user name, password `dev-admin-token`).

Tasks that compile the code start Postgres and apply migrations first: `sqlx::query!` macros check every query against a live database at compile time.

## Guidelines

- **Keep it small.** Tocsin aims to stay a single binary plus Postgres. Please discuss in an issue before adding a new service or a heavy dependency.
- **Tests.** Add tests for new behavior. Database tests use `#[sqlx::test]`, which gives each test its own migrated throwaway database.
- **Migrations.** Every schema change goes in a new file in `migrations/`. Never edit a migration that has already been released.
- **SQL metadata.** If you add or change a query, run `mise run db:prepare` and commit the `.sqlx/` changes. CI fails otherwise.
- **Dashboard.** Server-side rendered with [maud](https://maud.lambda.xyz/), no JavaScript. Values are escaped automatically; never use `PreEscaped` on user-supplied data.
- **Commits.** Keep commits focused, with a message that explains *why*.
- **Documentation.** The docs site lives in `docs/src/` ([mdBook](https://rust-lang.github.io/mdBook/)). Update the relevant page when you change behavior, configuration or the API.
- **Changelog.** Add a line under `Unreleased` in [CHANGELOG.md](CHANGELOG.md) for user-visible changes.

Before opening a pull request, make sure `mise run lint` and `mise run test` pass.

## License

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in Tocsin by you, as defined in the Apache-2.0 license, shall be dual licensed under MIT OR Apache-2.0, without any additional terms or conditions.
