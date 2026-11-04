//! Server-side-rendered dashboard. maud escapes every interpolated value: purls, licenses and
//! advisory texts come from CI input and external feeds.
//!
//! When `TOCSIN_ADMIN_TOKEN` is set the dashboard requires it, through HTTP Basic auth (any user
//! name, the token as password) or a bearer token, unless `TOCSIN_DASHBOARD_PUBLIC` is set.
mod admin;
mod kev;
mod projects;
mod vulns;

use crate::api::{ApiResult, AppState, internal, sha256_hex};
use crate::vulns::Severity;
use axum::{
    Router,
    extract::{Request, State},
    http::{HeaderMap, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
    routing::get,
};
use base64::Engine;
use maud::{DOCTYPE, Markup, PreEscaped, html};
use sqlx::PgPool;

pub const PAGE_SIZE: i64 = 100;

const CSS: &str = r#"
:root { --bg:#fff; --fg:#1b1f24; --muted:#656d76; --line:#d8dee4; --accent:#0969da; --row:#f6f8fa; --err:#cf222e;
        --crit:#8b0820; --high:#cf222e; --med:#bc4c00; --low:#9a6700; --unk:#6e7781; }
@media (prefers-color-scheme: dark) {
  :root { --bg:#0d1117; --fg:#e6edf3; --muted:#8d96a0; --line:#30363d; --accent:#4493f8; --row:#161b22; --err:#f85149;
          --crit:#ff7b72; --high:#f85149; --med:#f0883e; --low:#d29922; --unk:#8d96a0; }
}
* { box-sizing: border-box; }
body { margin:0; background:var(--bg); color:var(--fg); font:15px/1.5 system-ui, sans-serif; }
header { border-bottom:1px solid var(--line); padding:12px 16px; display:flex; flex-wrap:wrap; gap:24px; align-items:baseline; }
header a { color:var(--fg); text-decoration:none; }
header a.brand { font-weight:700; }
header nav { display:flex; flex-wrap:wrap; gap:16px; }
header nav a { color:var(--muted); }
header nav a:hover, header nav a.active { color:var(--fg); }
main { max-width:1200px; margin:0 auto; padding:16px; }
h1 { font-size:1.4rem; margin:8px 0 16px; }
h2 { font-size:1.1rem; margin:28px 0 8px; }
a { color:var(--accent); }
.muted { color:var(--muted); }
.error { color:var(--err); }
.status { font-size:.9rem; margin:-8px 0 16px; }
.scroll { overflow-x:auto; }
table { width:100%; border-collapse:collapse; }
th, td { text-align:left; padding:6px 10px; border-bottom:1px solid var(--line); vertical-align:top; }
th { color:var(--muted); font-weight:600; font-size:.85rem; white-space:nowrap; }
td.nowrap { white-space:nowrap; }
tbody tr:hover { background:var(--row); }
td.num, th.num { text-align:right; white-space:nowrap; }
code { font:13px ui-monospace, monospace; word-break:break-all; }
.badge { display:inline-block; padding:0 8px; border-radius:10px; font-size:.8rem; font-weight:600; color:#fff; white-space:nowrap; }
.badge.kev { background:var(--err); }
.badge.state { background:var(--unk); }
.sev { font-weight:600; white-space:nowrap; }
.sev4 { color:var(--crit); } .sev3 { color:var(--high); } .sev2 { color:var(--med); } .sev1 { color:var(--low); } .sev0 { color:var(--unk); }
.cards { display:flex; flex-wrap:wrap; gap:12px; margin:0 0 20px; }
.card { border:1px solid var(--line); border-radius:8px; padding:10px 16px; min-width:110px; }
.card .n { font-size:1.5rem; font-weight:700; }
.card .l { color:var(--muted); font-size:.85rem; }
form.filters { display:flex; flex-wrap:wrap; gap:12px; align-items:center; margin:0 0 12px; }
form.filters input[type=search] { min-width:280px; padding:5px 8px; border:1px solid var(--line); border-radius:6px; background:var(--bg); color:var(--fg); font:inherit; }
form.filters button { padding:5px 14px; border:1px solid var(--line); border-radius:6px; background:var(--row); color:var(--fg); font:inherit; cursor:pointer; }
.pager { display:flex; gap:16px; margin:12px 0; }
dl { display:grid; grid-template-columns:max-content 1fr; gap:8px 24px; margin:0; }
dt { color:var(--muted); font-weight:600; }
dd { margin:0; }
dd ul { margin:0; padding-left:18px; }
footer { max-width:1200px; margin:24px auto; padding:12px 16px; border-top:1px solid var(--line); color:var(--muted); font-size:.85rem; }
.epss-hi { color:var(--err); font-weight:600; }
.details { white-space:pre-wrap; border-left:3px solid var(--line); padding-left:12px; }
"#;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/", get(projects::index))
        .route("/projects/{name}", get(projects::project))
        .route("/vulns", get(vulns::list))
        .route("/vulns/{id}", get(vulns::detail))
        .route("/kev", get(kev::list))
        .route("/kev/{cve}", get(kev::entry))
        .route("/policies", get(admin::policies))
        .route("/alerts", get(admin::alerts))
}

/// Middleware protecting the dashboard with the admin token.
pub async fn require_auth(State(st): State<AppState>, req: Request, next: Next) -> Response {
    let Some(expected) = &st.config.admin_token_hash else {
        return next.run(req).await;
    };
    if st.config.dashboard_public
        || presented_token(req.headers()).is_some_and(|t| sha256_hex(&t) == *expected)
    {
        return next.run(req).await;
    }
    (
        StatusCode::UNAUTHORIZED,
        [(
            header::WWW_AUTHENTICATE,
            r#"Basic realm="Tocsin", charset="UTF-8""#,
        )],
        "authentication required: use the admin token as password",
    )
        .into_response()
}

/// Token from `Authorization: Basic` (the password) or `Authorization: Bearer`.
fn presented_token(headers: &HeaderMap) -> Option<String> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    if let Some(token) = value.strip_prefix("Bearer ") {
        return Some(token.to_owned());
    }
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(value.strip_prefix("Basic ")?)
        .ok()?;
    let credentials = String::from_utf8(decoded).ok()?;
    Some(credentials.split_once(':')?.1.to_owned())
}

#[derive(Clone, Copy, PartialEq)]
pub enum Nav {
    Projects,
    Vulns,
    Kev,
    Policies,
    Alerts,
}

pub fn page(title: &str, nav: Nav, body: Markup) -> Markup {
    let link = |href: &str, label: &str, item: Nav| {
        html! { a href=(href) class=[(nav == item).then_some("active")] { (label) } }
    };
    html! {
        (DOCTYPE)
        html lang="en" {
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width, initial-scale=1";
                title { (title) " · Tocsin" }
                style { (PreEscaped(CSS)) }
            }
            body {
                header {
                    a.brand href="/" { "🔔 Tocsin" }
                    nav {
                        (link("/", "Projects", Nav::Projects))
                        (link("/vulns", "Vulnerabilities", Nav::Vulns))
                        (link("/kev", "KEV catalog", Nav::Kev))
                        (link("/policies", "Policies", Nav::Policies))
                        (link("/alerts", "Alerts", Nav::Alerts))
                    }
                }
                main { (body) }
                footer {
                    "EPSS scores by " a href="https://www.first.org/epss" rel="noreferrer" { "FIRST" }
                    ". Vulnerability data from " a href="https://osv.dev" rel="noreferrer" { "OSV.dev" }
                    " and the " a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog" rel="noreferrer" { "CISA KEV catalog" } "."
                }
            }
        }
    }
}

pub fn severity(rank: i16) -> Markup {
    let s = Severity::from_rank(rank);
    html! { span class={ "sev sev" (rank) } { (s.label()) } }
}

pub fn kev_badge() -> Markup {
    html! { span.badge.kev title="In the CISA Known Exploited Vulnerabilities catalog" { "KEV" } }
}

/// An EPSS score as a percentage, highlighted from 10% (the base rate is 2-3% a month).
pub fn epss(score: Option<f32>) -> Markup {
    match score {
        Some(s) => html! {
            span class=[(s >= 0.1).then_some("epss-hi")]
                title="EPSS: probability of exploitation activity in the next 30 days" {
                (crate::epss::percent(s))
            }
        },
        None => html! { span.muted { "—" } },
    }
}

pub fn analysis_badge(state: Option<&str>) -> Markup {
    match state {
        Some(state) => html! { span.badge.state { (crate::vex::state_label(state)) } },
        None => html! { span.muted { "—" } },
    }
}

/// First purls of a finding, with the count of the others.
pub fn purl_list(purls: &[String]) -> Markup {
    html! {
        @for (i, purl) in purls.iter().take(3).enumerate() {
            @if i > 0 { br; }
            code { (purl) }
        }
        @if purls.len() > 3 { br; span.muted { "and " (purls.len() - 3) " more" } }
    }
}

pub fn card(n: impl std::fmt::Display, label: &str, class: Option<&str>) -> Markup {
    html! { div.card { div class={ "n " (class.unwrap_or("")) } { (n) } div.l { (label) } } }
}

/// URL with query parameters, empty values left out.
pub fn url(path: &str, params: &[(&str, String)]) -> String {
    let params: Vec<_> = params.iter().filter(|(_, v)| !v.is_empty()).collect();
    match serde_urlencoded::to_string(&params) {
        Ok(qs) if !qs.is_empty() => format!("{path}?{qs}"),
        _ => path.to_owned(),
    }
}

/// `%term%` for ILIKE, with the user's wildcards matched literally.
pub fn like_pattern(q: Option<&str>) -> Option<String> {
    q.map(|q| {
        let escaped = q
            .replace('\\', "\\\\")
            .replace('%', "\\%")
            .replace('_', "\\_");
        format!("%{escaped}%")
    })
}

/// Trimmed, non-empty search term.
pub fn search_term(q: &Option<String>) -> Option<&str> {
    q.as_deref().map(str::trim).filter(|q| !q.is_empty())
}

/// Previous / next links.
pub fn pager(page: i64, last_shown: i64, total: i64, link: impl Fn(i64) -> String) -> Markup {
    html! {
        div.pager {
            @if page > 1 { a href=(link(page - 1)) { "← Previous" } }
            @if last_shown < total { a href=(link(page + 1)) { "Next →" } }
        }
    }
}

/// http(s) URLs only: anything else (javascript:, data:…) from a feed must not become a link.
pub fn safe_links<'a>(candidates: impl IntoIterator<Item = &'a str>) -> Vec<&'a str> {
    let mut out: Vec<&str> = Vec::new();
    for c in candidates {
        if (c.starts_with("https://") || c.starts_with("http://")) && !out.contains(&c) {
            out.push(c);
        }
    }
    out
}

/// One-line status of the KEV catalog sync, with the last error if the latest attempt failed.
/// `link` prefixes it with a link to the catalog page (not wanted on that page itself).
pub async fn kev_status(db: &PgPool, link: bool) -> ApiResult<Markup> {
    let kev = sqlx::query!(
        r#"SELECT catalog_version,
                  to_char(checked_at, 'YYYY-MM-DD HH24:MI') AS checked_at,
                  last_error,
                  to_char(last_attempt_at, 'YYYY-MM-DD HH24:MI') AS last_attempt_at,
                  (SELECT count(*) FROM kev_entries) AS "entries!"
           FROM kev_sync"#
    )
    .fetch_one(db)
    .await
    .map_err(internal)?;

    Ok(html! {
        p.status.muted {
            @if link { a href="/kev" { "KEV catalog" } ": " }
            @match (&kev.catalog_version, &kev.checked_at) {
                (Some(version), Some(checked_at)) => {
                    (kev.entries) " entries, version " (version) ", checked " (checked_at) " UTC"
                }
                _ => @if link { "not synced yet" } @else { "Not synced yet." },
            }
            @if let Some(error) = &kev.last_error {
                br;
                span.error {
                    "Last sync failed at " (kev.last_attempt_at.as_deref().unwrap_or("?")) " UTC: " (error)
                }
            }
        }
    })
}

/// One-line status of the EPSS sync, with the last error if the latest attempt failed.
pub async fn epss_status(db: &PgPool) -> ApiResult<Markup> {
    let e = sqlx::query!(
        r#"SELECT model_version, to_char(score_date, 'YYYY-MM-DD') AS score_date,
                  to_char(checked_at, 'YYYY-MM-DD HH24:MI') AS checked_at, last_error,
                  to_char(last_attempt_at, 'YYYY-MM-DD HH24:MI') AS last_attempt_at,
                  (SELECT count(*) FROM epss_scores) AS "scores!"
           FROM epss_sync"#
    )
    .fetch_one(db)
    .await
    .map_err(internal)?;

    Ok(html! {
        p.status.muted {
            "EPSS: "
            @match (&e.score_date, &e.checked_at) {
                (Some(date), Some(checked_at)) => {
                    (e.scores) " scored CVEs, scores of " (date) " (model " (e.model_version.as_deref().unwrap_or("?"))
                    "), checked " (checked_at) " UTC"
                }
                _ => "not synced yet",
            }
            @if let Some(error) = &e.last_error {
                br;
                span.error {
                    "Last sync failed at " (e.last_attempt_at.as_deref().unwrap_or("?")) " UTC: " (error)
                }
            }
        }
    })
}

pub fn not_found(what: &str) -> (StatusCode, String) {
    (StatusCode::NOT_FOUND, format!("{what} not found"))
}
