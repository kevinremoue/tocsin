mod alerts;
mod api;
mod config;
mod coverage;
mod epss;
mod http;
mod identity;
mod jobs;
mod kev;
mod osv;
mod policies;
mod sbom;
#[cfg(test)]
mod tests;
mod vex;
mod vulns;
mod web;

use sqlx::{PgPool, postgres::PgPoolOptions};
use std::sync::Arc;

const USAGE: &str = "\
Usage: tocsin [COMMAND]

Commands:
  serve      Run the HTTP server (default)
  migrate    Apply pending database migrations, then exit
  kev-sync   Sync the CISA KEV catalog once, then exit
  epss-sync  Sync EPSS scores once, then exit
  refresh    Re-match every project against the vulnerability sources once, then exit

Configuration is read from environment variables: see the documentation.";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let command = std::env::args().nth(1).unwrap_or_else(|| "serve".into());
    if matches!(command.as_str(), "help" | "-h" | "--help") {
        println!("{USAGE}");
        return Ok(());
    }
    if !matches!(command.as_str(), "serve" | "migrate") && !jobs::JOBS.contains(&command.as_str()) {
        eprintln!("unknown command {command:?}\n\n{USAGE}");
        std::process::exit(2);
    }

    let config = config::Config::from_env()?;
    let db = PgPoolOptions::new()
        .max_connections(config.db_max_connections)
        .connect(&config.database_url)
        .await?;

    match command.as_str() {
        "migrate" => migrate(&db).await,
        "serve" => {
            if config.migrate_on_start {
                migrate(&db).await?;
            }
            serve(state(db, config)?).await
        }
        job => {
            let result = jobs::run(&state(db, config)?, job).await?;
            println!("{result}");
            Ok(())
        }
    }
}

fn state(db: PgPool, config: config::Config) -> anyhow::Result<api::AppState> {
    Ok(api::AppState {
        db,
        config: Arc::new(config),
        http: http::client()?,
    })
}

async fn migrate(db: &PgPool) -> anyhow::Result<()> {
    sqlx::migrate!().run(db).await?;
    tracing::info!("database migrations applied");
    Ok(())
}

async fn serve(st: api::AppState) -> anyhow::Result<()> {
    let config = &st.config;
    if config.admin_token_hash.is_none() {
        tracing::warn!("TOCSIN_ADMIN_TOKEN not set: admin API disabled, dashboard open");
    } else if config.dashboard_public {
        tracing::warn!("TOCSIN_DASHBOARD_PUBLIC is set: dashboard open without authentication");
    }
    if config.google_chat_webhook.is_none() {
        tracing::info!("no notification channel configured: alerts are not sent");
    }
    if config.scheduler {
        tracing::info!("in-process scheduler enabled");
        tokio::spawn(jobs::scheduler(st.clone()));
    }

    let addr = config.bind_addr.clone();
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!("listening on {addr}");
    axum::serve(listener, api::router(st))
        .with_graceful_shutdown(shutdown())
        .await?;
    Ok(())
}

/// Resolves on Ctrl-C or SIGTERM (sent by Cloud Run and other platforms before stopping).
async fn shutdown() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let term = async {
        if let Ok(mut s) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            s.recv().await;
        }
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => {},
        _ = term => {},
    }
    tracing::info!("shutting down");
}
