//! Server-side-rendered dashboard. maud escapes every interpolated value: purls, licenses and
//! advisory texts come from CI input and external feeds.
//!
//! When `TOCSIN_ADMIN_TOKEN` is set the dashboard requires it, through HTTP Basic auth (any user
//! name, the token as password) or a bearer token, unless `TOCSIN_DASHBOARD_PUBLIC` is set.
//! Changes (audit, uploads, policies, jobs) always require the admin token: a public dashboard
//! is read-only. Forms are plain HTML posts that work without JavaScript; htmx, served from
//! `/static/`, turns some of them into in-place updates. Cross-site posts are refused
//! (`CsrfLayer`), and a Content-Security-Policy allows only Tocsin's own scripts and styles.
mod actions;
mod admin;
mod chart;
mod kev;
mod projects;
mod vulns;

use crate::api::{ApiResult, AppState, internal, sha256_hex};
use crate::vulns::Severity;
use axum::{
    Extension, Router,
    extract::{Path, Request, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Redirect, Response},
    routing::get,
};
use base64::Engine;
use maud::{DOCTYPE, Markup, html};
use sqlx::PgPool;
use std::sync::LazyLock;

pub const PAGE_SIZE: i64 = 100;

/// Stylesheet and htmx, embedded in the binary. Their paths change with their content, so
/// they can be cached forever.
const CSS: &str = include_str!("static/tocsin.css");
const HTMX: &str = include_str!("static/htmx-2.0.11.min.js");
const HTMX_PATH: &str = "/static/htmx-2.0.11.min.js";
static CSS_PATH: LazyLock<String> =
    LazyLock::new(|| format!("/static/tocsin-{}.css", &sha256_hex(CSS)[..12]));

/// htmx without `eval` (the CSP forbids it), and swapping error responses too, so that
/// validation messages show in place.
const HTMX_CONFIG: &str = r#"{"allowEval":false,"includeIndicatorStyles":false,"responseHandling":[{"code":"204","swap":false},{"code":"[2345]..","swap":true}]}"#;

const CSP: &str = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; \
                   frame-ancestors 'none'; form-action 'self'; base-uri 'none'";

/// Dashboard pages and actions, behind `require_auth`.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/", get(projects::index))
        .route("/login", get(login))
        .route("/projects/{name}", get(projects::project))
        .route("/projects/{name}/vex.json", get(projects::vex_download))
        .route("/vulns", get(vulns::list))
        .route("/vulns/{id}", get(vulns::detail))
        .route("/kev", get(kev::list))
        .route("/kev/{cve}", get(kev::entry))
        .route("/policies", get(admin::policies))
        .route("/alerts", get(admin::alerts))
        .merge(actions::routes())
}

/// Embedded assets, served without authentication (the login prompt needs no asset).
pub fn static_routes() -> Router<AppState> {
    Router::new().route("/static/{file}", get(asset))
}

async fn asset(Path(file): Path<String>) -> Response {
    let (body, content_type) = match format!("/static/{file}") {
        p if p == HTMX_PATH => (HTMX, "text/javascript; charset=utf-8"),
        p if p == *CSS_PATH => (CSS, "text/css; charset=utf-8"),
        _ => return StatusCode::NOT_FOUND.into_response(),
    };
    (
        [
            (header::CONTENT_TYPE, content_type),
            (header::CACHE_CONTROL, "public, max-age=31536000, immutable"),
        ],
        body,
    )
        .into_response()
}

/// Who is looking at the dashboard, set by `require_auth` for every page and action.
#[derive(Clone, Copy)]
pub struct Viewer {
    /// Presented the admin token: may audit, upload, manage policies and run jobs.
    pub can_write: bool,
    /// An admin token is configured but was not presented (public dashboard): offer to sign in.
    pub can_sign_in: bool,
}

/// Middleware protecting the dashboard with the admin token. Also sets the security headers.
pub async fn require_auth(State(st): State<AppState>, mut req: Request, next: Next) -> Response {
    let admin = st.config.admin_token_hash.as_ref().is_some_and(|expected| {
        presented_token(req.headers()).is_some_and(|t| sha256_hex(&t) == *expected)
    });
    let configured = st.config.admin_token_hash.is_some();
    if configured && !admin && !st.config.dashboard_public {
        return ask_credentials();
    }
    req.extensions_mut().insert(Viewer {
        can_write: admin,
        can_sign_in: configured && !admin,
    });
    let mut res = next.run(req).await;
    let headers = res.headers_mut();
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(CSP),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("same-origin"),
    );
    res
}

fn ask_credentials() -> Response {
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

/// Sign-in link of a public dashboard: asks the browser for the admin token, then goes home.
async fn login(Extension(viewer): Extension<Viewer>) -> Response {
    if viewer.can_sign_in {
        ask_credentials()
    } else {
        Redirect::to("/").into_response()
    }
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

pub fn page(viewer: &Viewer, title: &str, nav: Nav, body: Markup) -> Markup {
    let link = |href: &str, label: &str, item: Nav| {
        html! { a href=(href) class=[(nav == item).then_some("active")] { (label) } }
    };
    html! {
        (DOCTYPE)
        html lang="en" {
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width, initial-scale=1";
                meta name="htmx-config" content=(HTMX_CONFIG);
                title { (title) " · Tocsin" }
                // No favicon request (the CSP allows data: images)
                link rel="icon" href="data:,";
                link rel="stylesheet" href=(*CSS_PATH);
                script src=(HTMX_PATH) defer {}
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
                        @if viewer.can_sign_in { a href="/login" { "Sign in" } }
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

/// Fixed confirmation messages, chosen by the `done` query parameter after a redirect (the
/// parameter is never echoed).
pub fn flash(done: Option<&str>) -> Markup {
    let message = match done {
        Some("audited") => "Analysis saved.",
        Some("policy-created") => "Policy created.",
        Some("policy-deleted") => "Policy deleted.",
        _ => return html! {},
    };
    html! { p.flash role="status" { (message) } }
}

/// Is this request from htmx (an in-place update) rather than a plain form post?
pub fn is_htmx(headers: &HeaderMap) -> bool {
    headers.get("hx-request").is_some_and(|v| v == "true")
}

/// An error, as a page or, for htmx, as a fragment swapped where the result would go.
pub fn error_response(
    viewer: &Viewer,
    headers: &HeaderMap,
    (status, message): (StatusCode, String),
) -> Response {
    if is_htmx(headers) {
        return (status, html! { span.error role="alert" { (message) } }).into_response();
    }
    let body = html! {
        h1 { "Something went wrong" }
        p.flash.error role="alert" { (message) }
        p { a href="/" { "← Projects" } }
    };
    (status, page(viewer, "Error", Nav::Projects, body)).into_response()
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

/// "Code not reachable" for `code_not_reachable`.
pub fn justification_label(j: &str) -> String {
    let text = j.replace('_', " ");
    let mut chars = text.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().chain(chars).collect(),
        None => text,
    }
}

/// The audit state of a finding of `project`, as a badge; for admins, a badge that opens a form
/// recording the decision. `return_to` is the page to come back to after a plain form post.
/// Without JavaScript the `<details>` element still opens and the form posts normally.
pub struct AnalysisCell<'a> {
    pub project: &'a str,
    pub vuln_key: &'a str,
    pub state: Option<&'a str>,
    pub suppressed: bool,
    pub justification: Option<&'a str>,
    pub detail: Option<&'a str>,
}

pub fn analysis_cell(viewer: &Viewer, a: &AnalysisCell, return_to: &str) -> Markup {
    let badge = || {
        html! {
            (analysis_badge(a.state))
            @if matches!(a.state, Some("not_affected" | "false_positive" | "resolved")) && !a.suppressed {
                " " span.badge.error title="Rationale retained; this analysis does not suppress current evidence" { "Pending revalidation" }
            }
        }
    };
    if !viewer.can_write {
        return badge();
    }
    let action = format!("/projects/{}/analyses/{}", a.project, a.vuln_key);
    html! {
        details.audit {
            summary title="Record an analysis" {
                @if a.state.is_some() { (badge()) } @else { span.muted { "Analyze" } }
            }
            form method="post" action=(action) hx-post=(action) hx-target="closest td"
                hx-swap="innerHTML" hx-disabled-elt="find button" {
                input type="hidden" name="return_to" value=(return_to);
                select name="state" aria-label="State" {
                    option value="none" selected[a.state.is_none()] { "Not audited" }
                    @for s in crate::vex::STATES {
                        option value=(s) selected[a.state == Some(s)] { (crate::vex::state_label(s)) }
                    }
                }
                select name="justification" aria-label="Justification" {
                    option value="" selected[a.justification.is_none()] { "No justification" }
                    @for j in crate::vex::JUSTIFICATIONS {
                        option value=(j) selected[a.justification == Some(j)] { (justification_label(j)) }
                    }
                }
                textarea name="detail" aria-label="Detail" placeholder="Detail (optional)" {
                    (a.detail.unwrap_or(""))
                }
                button.primary type="submit" { "Save" }
            }
        }
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
