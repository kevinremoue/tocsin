//! Configuration, read once from environment variables.
use crate::vulns::Severity;
use anyhow::{Context, bail};
use std::time::Duration;

pub const DEFAULT_KEV_URL: &str =
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
pub const DEFAULT_OSV_URL: &str = "https://api.osv.dev";
pub const DEFAULT_EPSS_URL: &str = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz";

pub struct Config {
    pub database_url: String,
    pub bind_addr: String,
    /// Connections per instance. Keep it low when many serverless instances share one database.
    pub db_max_connections: u32,
    /// Run pending migrations when `serve` starts (convenient locally; use `tocsin migrate` in deployments).
    pub migrate_on_start: bool,
    /// SHA-256 of TOCSIN_ADMIN_TOKEN; None = admin API disabled, dashboard open.
    pub admin_token_hash: Option<String>,
    /// Serve the dashboard without authentication even when an admin token is set.
    pub dashboard_public: bool,
    /// Base URL of the dashboard, used for links in alerts.
    pub public_url: Option<String>,
    /// Run the periodic jobs inside `serve`. Off by default: on serverless platforms an
    /// external scheduler calls `POST /api/jobs/...` or runs `tocsin <job>` instead.
    pub scheduler: bool,
    pub kev_url: String,
    pub kev_sync_every: Duration,
    pub osv_url: String,
    pub refresh_every: Duration,
    pub epss_url: String,
    pub epss_sync_every: Duration,
    /// Match a pushed SBOM against OSV within the push request.
    pub match_on_push: bool,
    pub google_chat_webhook: Option<String>,
    /// Alert on findings that are in the KEV catalog.
    pub alert_kev: bool,
    /// Also alert on findings at or above this severity.
    pub alert_min_severity: Option<Severity>,
    /// Also alert on findings whose EPSS score is at least this probability (0 to 1).
    pub alert_min_epss: Option<f32>,
}

fn var(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.trim().is_empty())
}

fn bool_var(name: &str, default: bool) -> anyhow::Result<bool> {
    match var(name).as_deref().map(str::to_ascii_lowercase).as_deref() {
        None => Ok(default),
        Some("1" | "true" | "yes" | "on") => Ok(true),
        Some("0" | "false" | "no" | "off") => Ok(false),
        Some(other) => bail!("{name} must be true or false, got {other:?}"),
    }
}

/// A probability: "0.5", or a percentage: "50%".
pub fn parse_probability(s: &str) -> Option<f32> {
    let s = s.trim();
    let p = match s.strip_suffix('%') {
        Some(pct) => pct.trim().parse::<f32>().ok()? / 100.0,
        None => s.parse::<f32>().ok()?,
    };
    (p > 0.0 && p <= 1.0).then_some(p)
}

fn minutes_var(name: &str, default: u64) -> anyhow::Result<Duration> {
    let minutes =
        match var(name) {
            None => default,
            Some(m) => m.parse::<u64>().ok().filter(|&m| m > 0).with_context(|| {
                format!("{name} must be a positive number of minutes, got {m:?}")
            })?,
        };
    Ok(Duration::from_secs(minutes * 60))
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        let alert_min_severity = match var("TOCSIN_ALERT_MIN_SEVERITY") {
            None => None,
            Some(s) => Some(
                Severity::parse(&s)
                    .filter(|s| *s != Severity::Unknown)
                    .with_context(|| {
                        format!("TOCSIN_ALERT_MIN_SEVERITY must be critical, high, medium or low, got {s:?}")
                    })?,
            ),
        };
        let alert_min_epss = match var("TOCSIN_ALERT_MIN_EPSS") {
            None => None,
            Some(s) => Some(parse_probability(&s).with_context(|| {
                format!("TOCSIN_ALERT_MIN_EPSS must be a probability above 0 and at most 1 (0.5) or a percentage (50%), got {s:?}")
            })?),
        };
        Ok(Self {
            database_url: var("DATABASE_URL").context("DATABASE_URL is not set")?,
            bind_addr: var("BIND_ADDR").unwrap_or_else(|| "0.0.0.0:3000".into()),
            db_max_connections: match var("TOCSIN_DB_MAX_CONNECTIONS") {
                None => 5,
                Some(n) => n.parse().ok().filter(|&n| n > 0).with_context(|| {
                    format!("TOCSIN_DB_MAX_CONNECTIONS must be a positive integer, got {n:?}")
                })?,
            },
            migrate_on_start: bool_var("TOCSIN_MIGRATE_ON_START", true)?,
            admin_token_hash: var("TOCSIN_ADMIN_TOKEN").map(|t| crate::api::sha256_hex(&t)),
            dashboard_public: bool_var("TOCSIN_DASHBOARD_PUBLIC", false)?,
            public_url: var("TOCSIN_PUBLIC_URL").map(|u| u.trim_end_matches('/').to_owned()),
            scheduler: bool_var("TOCSIN_SCHEDULER", false)?,
            kev_url: var("TOCSIN_KEV_URL").unwrap_or_else(|| DEFAULT_KEV_URL.into()),
            kev_sync_every: minutes_var("TOCSIN_KEV_SYNC_MINUTES", 6 * 60)?,
            osv_url: var("TOCSIN_OSV_URL")
                .unwrap_or_else(|| DEFAULT_OSV_URL.into())
                .trim_end_matches('/')
                .to_owned(),
            refresh_every: minutes_var("TOCSIN_REFRESH_MINUTES", 24 * 60)?,
            epss_url: var("TOCSIN_EPSS_URL").unwrap_or_else(|| DEFAULT_EPSS_URL.into()),
            epss_sync_every: minutes_var("TOCSIN_EPSS_SYNC_MINUTES", 24 * 60)?,
            match_on_push: bool_var("TOCSIN_MATCH_ON_PUSH", true)?,
            google_chat_webhook: var("TOCSIN_GOOGLE_CHAT_WEBHOOK"),
            alert_kev: bool_var("TOCSIN_ALERT_KEV", true)?,
            alert_min_severity,
            alert_min_epss,
        })
    }

    /// Settings for tests: nothing external configured, admin token "admin".
    #[cfg(test)]
    pub fn for_tests() -> Self {
        Self {
            database_url: String::new(),
            bind_addr: String::new(),
            db_max_connections: 1,
            migrate_on_start: false,
            admin_token_hash: Some(crate::api::sha256_hex("admin")),
            dashboard_public: true,
            public_url: Some("https://tocsin.example".into()),
            scheduler: false,
            kev_url: String::new(),
            kev_sync_every: Duration::from_secs(60),
            osv_url: String::new(),
            refresh_every: Duration::from_secs(60),
            epss_url: String::new(),
            epss_sync_every: Duration::from_secs(60),
            match_on_push: false,
            google_chat_webhook: None,
            alert_kev: true,
            alert_min_severity: None,
            alert_min_epss: None,
        }
    }
}
