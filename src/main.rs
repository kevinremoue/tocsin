mod api;
mod sbom;
mod web;

use sqlx::PgPool;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let db = PgPool::connect(&std::env::var("DATABASE_URL")?).await?;
    sqlx::migrate!().run(&db).await?;

    let admin_token_hash = std::env::var("TOCSIN_ADMIN_TOKEN")
        .ok()
        .filter(|t| !t.is_empty())
        .map(|t| api::sha256_hex(&t));
    if admin_token_hash.is_none() {
        tracing::warn!("TOCSIN_ADMIN_TOKEN not set: admin API disabled");
    }

    let app = api::router(api::AppState {
        db,
        admin_token_hash,
    });

    let addr = std::env::var("BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:3000".into());
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!("listening on {addr}");
    axum::serve(listener, app).await?;
    Ok(())
}
