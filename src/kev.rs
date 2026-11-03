//! Sync of the CISA Known Exploited Vulnerabilities (KEV) catalog.
//!
//! The feed is downloaded periodically with a conditional request, and upserted into
//! `kev_entries`. Entries seen for the first time are reported as new: they will drive the
//! "new KEV entry matches a stored SBOM" alerts.
use anyhow::Context;
use reqwest::{StatusCode, header};
use serde::Deserialize;
use serde_json::Value;
use sqlx::PgPool;
use std::{collections::BTreeMap, time::Duration};

pub const DEFAULT_URL: &str =
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
const DEFAULT_SYNC_MINUTES: u64 = 6 * 60;

pub struct Config {
    pub url: String,
    pub every: Duration,
}

impl Config {
    /// Reads `TOCSIN_KEV_URL` and `TOCSIN_KEV_SYNC_MINUTES`.
    pub fn from_env() -> anyhow::Result<Self> {
        let url = std::env::var("TOCSIN_KEV_URL")
            .ok()
            .filter(|u| !u.is_empty())
            .unwrap_or_else(|| DEFAULT_URL.into());
        let minutes = match std::env::var("TOCSIN_KEV_SYNC_MINUTES") {
            Ok(m) => m.parse::<u64>().ok().filter(|&m| m > 0).with_context(|| {
                format!("TOCSIN_KEV_SYNC_MINUTES must be a positive integer, got {m:?}")
            })?,
            Err(_) => DEFAULT_SYNC_MINUTES,
        };
        Ok(Self {
            url,
            every: Duration::from_secs(minutes * 60),
        })
    }
}

pub fn http_client() -> reqwest::Result<reqwest::Client> {
    // reqwest is built without a bundled crypto provider: use ring, which sqlx already depends on.
    // Fails harmlessly when a provider is already installed (several clients, tests).
    let _ = rustls::crypto::ring::default_provider().install_default();
    reqwest::Client::builder()
        .user_agent(concat!(
            "tocsin/",
            env!("CARGO_PKG_VERSION"),
            " (+https://github.com/kevinremoue/tocsin)"
        ))
        .timeout(Duration::from_secs(60))
        .build()
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Catalog {
    catalog_version: String,
    // Kept raw: each entry is stored as published, and a malformed one is skipped, not fatal
    vulnerabilities: Vec<Value>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Entry {
    #[serde(rename = "cveID")]
    cve_id: String,
    vendor_project: String,
    product: String,
    vulnerability_name: String,
    date_added: String,
    known_ransomware_campaign_use: String,
}

#[derive(Debug, PartialEq)]
pub enum Outcome {
    /// The feed has not changed since the last sync (HTTP 304).
    NotModified,
    Synced {
        catalog_version: String,
        /// CVEs seen for the first time
        new: Vec<String>,
        /// Known CVEs whose entry changed
        updated: usize,
        /// Entries in the feed
        total: usize,
    },
}

/// Syncs forever, every `config.every`, starting now. Failures are logged and retried at the next tick.
pub async fn run(db: PgPool, client: reqwest::Client, config: Config) {
    let mut tick = tokio::time::interval(config.every);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tick.tick().await;
        match sync(&db, &client, &config.url).await {
            Ok(Outcome::NotModified) => tracing::info!("KEV catalog unchanged"),
            Ok(Outcome::Synced {
                catalog_version,
                new,
                updated,
                total,
            }) => {
                tracing::info!(
                    "KEV catalog {catalog_version} synced: {} new, {updated} updated, {total} total",
                    new.len()
                );
                if !new.is_empty() && new.len() <= 20 {
                    tracing::info!("new KEV entries: {}", new.join(", "));
                }
            }
            Err(e) => tracing::warn!("KEV sync failed: {e:#}"),
        }
    }
}

/// One sync attempt. Its result, success or error, is recorded in `kev_sync`.
pub async fn sync(db: &PgPool, client: &reqwest::Client, url: &str) -> anyhow::Result<Outcome> {
    let result = try_sync(db, client, url).await;
    if let Err(e) = &result {
        let recorded = sqlx::query!(
            "UPDATE kev_sync SET last_error = $1, last_attempt_at = now()",
            format!("{e:#}"),
        )
        .execute(db)
        .await;
        if let Err(db_err) = recorded {
            tracing::error!("cannot record KEV sync error: {db_err}");
        }
    }
    result
}

async fn try_sync(db: &PgPool, client: &reqwest::Client, url: &str) -> anyhow::Result<Outcome> {
    let previous = sqlx::query!("SELECT etag, last_modified FROM kev_sync")
        .fetch_one(db)
        .await?;

    // Both validators: cisa.gov only honors If-Modified-Since, mirrors may only honor ETags
    let mut req = client.get(url);
    if let Some(etag) = &previous.etag {
        req = req.header(header::IF_NONE_MATCH, etag);
    }
    if let Some(last_modified) = &previous.last_modified {
        req = req.header(header::IF_MODIFIED_SINCE, last_modified);
    }
    let res = req
        .send()
        .await
        .context("cannot download the KEV catalog")?;

    if res.status() == StatusCode::NOT_MODIFIED {
        sqlx::query!(
            "UPDATE kev_sync SET checked_at = now(), last_error = NULL, last_attempt_at = now()"
        )
        .execute(db)
        .await?;
        return Ok(Outcome::NotModified);
    }

    let res = res
        .error_for_status()
        .context("cannot download the KEV catalog")?;
    let validator = |name| {
        res.headers()
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(String::from)
    };
    let (etag, last_modified) = (validator(header::ETAG), validator(header::LAST_MODIFIED));
    let body = res
        .bytes()
        .await
        .context("cannot download the KEV catalog")?;
    let catalog: Catalog = serde_json::from_slice(&body).context("invalid KEV catalog document")?;

    // Keyed by CVE: a duplicate in the feed would make the upsert touch a row twice
    let mut entries = BTreeMap::new();
    for raw in catalog.vulnerabilities {
        match Entry::deserialize(&raw) {
            Ok(entry) => {
                entries.insert(entry.cve_id.clone(), (entry, raw));
            }
            Err(e) => tracing::warn!("skipping malformed KEV entry: {e}"),
        }
    }

    let total = entries.len();
    let mut cve_ids = Vec::with_capacity(total);
    let mut vendors = Vec::with_capacity(total);
    let mut products = Vec::with_capacity(total);
    let mut names = Vec::with_capacity(total);
    let mut dates = Vec::with_capacity(total);
    let mut ransomware = Vec::with_capacity(total);
    let mut data = Vec::with_capacity(total);
    for (cve_id, (entry, raw)) in entries {
        cve_ids.push(cve_id);
        vendors.push(entry.vendor_project);
        products.push(entry.product);
        names.push(entry.vulnerability_name);
        dates.push(entry.date_added);
        ransomware.push(entry.known_ransomware_campaign_use == "Known");
        data.push(raw);
    }

    let mut tx = db.begin().await?;
    // Unchanged entries are left alone; xmax = 0 tells a fresh insert from an update
    let changed = sqlx::query!(
        r#"INSERT INTO kev_entries (cve_id, vendor_project, product, name, date_added, known_ransomware, data)
           SELECT * FROM UNNEST($1::text[], $2::text[], $3::text[], $4::text[], $5::text[]::date[], $6::bool[], $7::jsonb[])
           ON CONFLICT (cve_id) DO UPDATE SET
               vendor_project = EXCLUDED.vendor_project,
               product = EXCLUDED.product,
               name = EXCLUDED.name,
               date_added = EXCLUDED.date_added,
               known_ransomware = EXCLUDED.known_ransomware,
               data = EXCLUDED.data,
               updated_at = now()
           WHERE kev_entries.data IS DISTINCT FROM EXCLUDED.data
           RETURNING cve_id, (xmax = 0) AS "inserted!""#,
        &cve_ids,
        &vendors,
        &products,
        &names,
        &dates,
        &ransomware,
        &data,
    )
    .fetch_all(&mut *tx)
    .await
    .context("cannot store the KEV catalog")?;
    sqlx::query!(
        "UPDATE kev_sync SET catalog_version = $1, etag = $2, last_modified = $3,
                             checked_at = now(), last_error = NULL, last_attempt_at = now()",
        catalog.catalog_version,
        etag,
        last_modified,
    )
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;

    let (inserted, updated): (Vec<_>, Vec<_>) = changed.into_iter().partition(|r| r.inserted);
    Ok(Outcome::Synced {
        catalog_version: catalog.catalog_version,
        new: inserted.into_iter().map(|r| r.cve_id).collect(),
        updated: updated.len(),
        total,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Router, extract::State, http::HeaderMap, response::IntoResponse, routing::get};
    use serde_json::json;
    use std::sync::{Arc, Mutex};

    /// What the fake feed serves: (Last-Modified, body), or an HTTP error status.
    type Feed = Arc<Mutex<Result<(String, Value), u16>>>;

    async fn serve_feed(State(feed): State<Feed>, headers: HeaderMap) -> axum::response::Response {
        let current = feed.lock().unwrap().clone();
        match current {
            Err(status) => axum::http::StatusCode::from_u16(status)
                .unwrap()
                .into_response(),
            // Like cisa.gov: If-Modified-Since is honored, If-None-Match is ignored
            Ok((modified, _))
                if headers
                    .get("if-modified-since")
                    .is_some_and(|v| v == &modified) =>
            {
                axum::http::StatusCode::NOT_MODIFIED.into_response()
            }
            Ok((modified, body)) => (
                [("last-modified", modified), ("etag", r#""ignored""#.into())],
                axum::Json(body),
            )
                .into_response(),
        }
    }

    /// Starts a local server standing in for cisa.gov; returns its URL.
    async fn fake_cisa(feed: Feed) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = Router::new()
            .route("/kev.json", get(serve_feed))
            .with_state(feed);
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        format!("http://{addr}/kev.json")
    }

    fn entry(cve: &str, ransomware: &str) -> Value {
        json!({
            "cveID": cve,
            "vendorProject": "Acme",
            "product": "Widget",
            "vulnerabilityName": format!("Acme Widget flaw {cve}"),
            "dateAdded": "2026-10-30",
            "shortDescription": "…",
            "knownRansomwareCampaignUse": ransomware,
            "cwes": ["CWE-79"]
        })
    }

    fn catalog(version: &str, entries: Vec<Value>) -> Value {
        json!({ "catalogVersion": version, "count": entries.len(), "vulnerabilities": entries })
    }

    #[sqlx::test]
    async fn syncs_new_and_updated_entries_conditionally(db: PgPool) {
        let feed: Feed = Arc::new(Mutex::new(Ok((
            "Fri, 30 Oct 2026 17:02:45 GMT".into(),
            catalog(
                "2026.10.30",
                vec![
                    entry("CVE-2026-0001", "Unknown"),
                    entry("CVE-2026-0002", "Known"),
                    json!({ "cveID": "CVE-2026-0003" }), // malformed: skipped
                ],
            ),
        ))));
        let url = fake_cisa(feed.clone()).await;
        let client = http_client().unwrap();

        let outcome = sync(&db, &client, &url).await.unwrap();
        assert_eq!(
            outcome,
            Outcome::Synced {
                catalog_version: "2026.10.30".into(),
                new: vec!["CVE-2026-0001".into(), "CVE-2026-0002".into()],
                updated: 0,
                total: 2,
            }
        );
        let ransomware: bool = sqlx::query_scalar(
            "SELECT known_ransomware FROM kev_entries WHERE cve_id = 'CVE-2026-0002'",
        )
        .fetch_one(&db)
        .await
        .unwrap();
        assert!(ransomware);

        // Unchanged feed: conditional request, nothing downloaded
        assert_eq!(
            sync(&db, &client, &url).await.unwrap(),
            Outcome::NotModified
        );

        // New catalog: one entry changed, one added, one unchanged
        *feed.lock().unwrap() = Ok((
            "Sat, 31 Oct 2026 17:00:00 GMT".into(),
            catalog(
                "2026.10.31",
                vec![
                    entry("CVE-2026-0001", "Unknown"),
                    entry("CVE-2026-0002", "Unknown"),
                    entry("CVE-2026-0004", "Unknown"),
                ],
            ),
        ));
        assert_eq!(
            sync(&db, &client, &url).await.unwrap(),
            Outcome::Synced {
                catalog_version: "2026.10.31".into(),
                new: vec!["CVE-2026-0004".into()],
                updated: 1,
                total: 3,
            }
        );
        let (version, modified): (String, String) =
            sqlx::query_as("SELECT catalog_version, last_modified FROM kev_sync")
                .fetch_one(&db)
                .await
                .unwrap();
        assert_eq!(
            (version.as_str(), modified.as_str()),
            ("2026.10.31", "Sat, 31 Oct 2026 17:00:00 GMT")
        );
    }

    #[sqlx::test]
    async fn records_failures_and_clears_them_on_success(db: PgPool) {
        let feed: Feed = Arc::new(Mutex::new(Err(503)));
        let url = fake_cisa(feed.clone()).await;
        let client = http_client().unwrap();

        assert!(sync(&db, &client, &url).await.is_err());
        let error: Option<String> = sqlx::query_scalar("SELECT last_error FROM kev_sync")
            .fetch_one(&db)
            .await
            .unwrap();
        assert!(error.unwrap().contains("503"));

        *feed.lock().unwrap() = Ok(("Fri, 30 Oct 2026 17:02:45 GMT".into(), catalog("1", vec![])));
        sync(&db, &client, &url).await.unwrap();
        let error: Option<String> = sqlx::query_scalar("SELECT last_error FROM kev_sync")
            .fetch_one(&db)
            .await
            .unwrap();
        assert_eq!(error, None);
    }
}
