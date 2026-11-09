//! Dashboard actions: everything the API can change, as HTML form posts. Admin only.
//!
//! Plain posts redirect back with a fixed confirmation (`?done=…`) or render a result page;
//! htmx posts (`HX-Request`) get the HTML fragment to swap in place.
use super::{Audit, Nav, Viewer, audit_cell, error_response, is_htmx, page};
use crate::api::{self, ApiError, AppState, MAX_DOCUMENT, internal};
use axum::{
    Extension, Form, Router,
    extract::{DefaultBodyLimit, Multipart, Path, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Redirect, Response},
    routing::post,
};
use maud::html;
use serde::Deserialize;
use serde_json::Value;
use std::io::Read;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/projects", post(create_project))
        .route("/projects/{name}/analyses/{vuln}", post(audit))
        .route("/projects/{name}/sboms", post(upload_sbom))
        .route("/projects/{name}/vex", post(import_vex))
        .route("/policies", post(create_policy))
        .route("/policies/{id}/delete", post(delete_policy))
        .route("/jobs/{job}", post(run_job))
        // A document plus the multipart envelope
        .layer(DefaultBodyLimit::max(MAX_DOCUMENT + 1024 * 1024))
}

type WebResult = Result<Response, Rejection>;

/// An error page or fragment; boxed, as responses are large.
struct Rejection(Box<Response>);

impl From<Response> for Rejection {
    fn from(res: Response) -> Self {
        Self(Box::new(res))
    }
}

impl IntoResponse for Rejection {
    fn into_response(self) -> Response {
        *self.0
    }
}

/// Changes need the admin token, even on a public dashboard.
fn require_write(st: &AppState, viewer: &Viewer, headers: &HeaderMap) -> Result<(), Rejection> {
    if viewer.can_write {
        return Ok(());
    }
    if st.config.admin_token_hash.is_none() {
        return Err(error_response(
            viewer,
            headers,
            (
                StatusCode::FORBIDDEN,
                "changes are disabled: TOCSIN_ADMIN_TOKEN is not set".into(),
            ),
        )
        .into());
    }
    let mut res = error_response(
        viewer,
        headers,
        (
            StatusCode::UNAUTHORIZED,
            "sign in with the admin token to make changes".into(),
        ),
    );
    res.headers_mut().insert(
        header::WWW_AUTHENTICATE,
        header::HeaderValue::from_static(r#"Basic realm="Tocsin", charset="UTF-8""#),
    );
    Err(res.into())
}

async fn project_id(st: &AppState, name: &str) -> Result<i64, ApiError> {
    sqlx::query_scalar!("SELECT id FROM projects WHERE name = $1", name)
        .fetch_optional(&st.db)
        .await
        .map_err(internal)?
        .ok_or_else(|| super::not_found("project"))
}

/// A same-site path to come back to; anything else (absolute or protocol-relative URLs) is
/// replaced by `fallback`, so a form cannot redirect elsewhere.
fn safe_return(return_to: Option<&str>, fallback: String) -> String {
    match return_to {
        Some(p)
            if ["/projects/", "/vulns/", "/kev/"]
                .iter()
                .any(|prefix| p.starts_with(prefix))
                && !p.contains("//")
                && !p.contains('\\') =>
        {
            p.to_owned()
        }
        _ => fallback,
    }
}

fn with_done(path: &str, done: &str) -> String {
    let sep = if path.contains('?') { '&' } else { '?' };
    format!("{path}{sep}done={done}")
}

// ---------------------------------------------------------------------------------------------
// Audit

#[derive(Deserialize)]
struct AuditForm {
    state: String,
    justification: Option<String>,
    detail: Option<String>,
    return_to: Option<String>,
}

async fn audit(
    State(st): State<AppState>,
    Extension(viewer): Extension<Viewer>,
    headers: HeaderMap,
    Path((name, vuln)): Path<(String, String)>,
    Form(form): Form<AuditForm>,
) -> WebResult {
    require_write(&st, &viewer, &headers)?;
    let fail = |e| Rejection::from(error_response(&viewer, &headers, e));
    let project_id = project_id(&st, &name).await.map_err(fail)?;
    let analysis = match form.state.as_str() {
        "none" => None,
        state => Some(
            crate::vex::Analysis::validate(
                state,
                form.justification.as_deref(),
                form.detail.as_deref(),
            )
            .map_err(|e| fail(api::bad_request(e)))?,
        ),
    };
    let key = crate::vex::record(&st.db, project_id, &vuln, analysis.as_ref())
        .await
        .map_err(|e| fail(internal(e)))?;
    let return_to = safe_return(form.return_to.as_deref(), format!("/projects/{name}"));

    if !is_htmx(&headers) {
        return Ok(Redirect::to(&with_done(&return_to, "audited")).into_response());
    }
    let audit = Audit {
        project: &name,
        vuln_key: &key,
        state: analysis.as_ref().map(|a| a.state.as_str()),
        justification: analysis.as_ref().and_then(|a| a.justification.as_deref()),
        detail: analysis.as_ref().and_then(|a| a.detail.as_deref()),
    };
    Ok(audit_cell(&viewer, &audit, &return_to).into_response())
}

// ---------------------------------------------------------------------------------------------
// Projects, SBOMs, VEX

#[derive(Deserialize)]
struct NewProject {
    name: String,
}

/// Shows the new project's token once: the page is not cached and not reachable again.
async fn create_project(
    State(st): State<AppState>,
    Extension(viewer): Extension<Viewer>,
    headers: HeaderMap,
    Form(form): Form<NewProject>,
) -> WebResult {
    require_write(&st, &viewer, &headers)?;
    let name = form.name.trim().to_owned();
    let token = api::new_project(&st.db, &name)
        .await
        .map_err(|e| Rejection::from(error_response(&viewer, &headers, e)))?;
    let origin = st
        .config
        .public_url
        .as_deref()
        .unwrap_or("https://tocsin.example.com");
    let body = html! {
        p.muted { a href="/" { "← Projects" } }
        h1 { "Project " (name) " created" }
        p.flash role="status" {
            "Copy its token now: it is shown only once. Tocsin stores only its hash."
        }
        code.token { (token) }
        h2 { "Push an SBOM from CI" }
        p { "Store the token as a CI secret (for example " code { "TOCSIN_TOKEN" } "), then push each production release:" }
        pre { "curl -fsS -X POST \"" (origin) "/api/sboms?version=$VERSION\" \\\n  -H \"Authorization: Bearer $TOCSIN_TOKEN\" \\\n  -H \"Content-Type: application/json\" \\\n  --data-binary @bom.json" }
        p { "Or upload a first SBOM from the " a href={ "/projects/" (name) } { "project page" } "." }
    };
    Ok((
        StatusCode::CREATED,
        [(header::CACHE_CONTROL, "no-store")],
        page(&viewer, &name, Nav::Projects, body),
    )
        .into_response())
}

/// Reads an uploaded JSON file (gzipped or not) and the text fields of a multipart form.
async fn read_upload(mut multipart: Multipart) -> Result<(Value, Vec<(String, String)>), ApiError> {
    let mut document = None;
    let mut fields = Vec::new();
    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| api::bad_request(format!("invalid upload: {e}")))?
    {
        let name = field.name().unwrap_or_default().to_owned();
        let bytes = field
            .bytes()
            .await
            .map_err(|e| api::bad_request(format!("invalid upload: {e}")))?;
        if name == "file" {
            document = Some(bytes);
        } else {
            fields.push((name, String::from_utf8_lossy(&bytes).into_owned()));
        }
    }
    let bytes = document
        .filter(|b| !b.is_empty())
        .ok_or_else(|| api::bad_request("choose a file to upload"))?;
    let json = if bytes.starts_with(&[0x1f, 0x8b]) {
        let mut out = Vec::new();
        flate2::read::GzDecoder::new(&bytes[..])
            .take(MAX_DOCUMENT as u64 + 1)
            .read_to_end(&mut out)
            .map_err(|e| api::bad_request(format!("invalid gzip file: {e}")))?;
        if out.len() > MAX_DOCUMENT {
            return Err((
                StatusCode::PAYLOAD_TOO_LARGE,
                "the document is larger than 50 MB once decompressed".into(),
            ));
        }
        out
    } else {
        bytes.to_vec()
    };
    let doc = serde_json::from_slice(&json)
        .map_err(|e| api::bad_request(format!("the file is not valid JSON: {e}")))?;
    Ok((doc, fields))
}

fn field<'a>(fields: &'a [(String, String)], name: &str) -> Option<&'a str> {
    fields
        .iter()
        .find(|(n, _)| n == name)
        .map(|(_, v)| v.trim())
        .filter(|v| !v.is_empty())
}

async fn upload_sbom(
    State(st): State<AppState>,
    Extension(viewer): Extension<Viewer>,
    headers: HeaderMap,
    Path(name): Path<String>,
    multipart: Multipart,
) -> WebResult {
    require_write(&st, &viewer, &headers)?;
    let fail = |e| Rejection::from(error_response(&viewer, &headers, e));
    let project_id = project_id(&st, &name).await.map_err(fail)?;
    let (doc, fields) = read_upload(multipart).await.map_err(fail)?;
    let version = field(&fields, "version").map(String::from);
    let summary = api::ingest(&st, project_id, &name, version, doc)
        .await
        .map_err(fail)?;

    let n = |key: &str| summary[key].as_i64().unwrap_or(0);
    let body = html! {
        p.muted { a href={ "/projects/" (name) } { "← " (name) } }
        h1 { "Release " (summary["version"].as_str().unwrap_or("")) " uploaded" }
        div.cards {
            (super::card(n("components"), "Components", None))
            (super::card(n("findings"), "Findings", None))
            (super::card(n("kev"), "Actively exploited", Some("error")))
            (super::card(n("alerted"), "Alerts sent", None))
        }
        @match summary["matching"].as_str() {
            Some("deferred") => p.flash.error { "OSV.dev was slow or unreachable: the next refresh job completes the matching." },
            Some("disabled") => p.muted { "Matching during uploads is disabled: the next refresh job matches this release." },
            _ => {},
        }
        p { a.button href={ "/projects/" (name) } { "See the findings" } }
    };
    Ok((
        StatusCode::CREATED,
        page(&viewer, &name, Nav::Projects, body),
    )
        .into_response())
}

async fn import_vex(
    State(st): State<AppState>,
    Extension(viewer): Extension<Viewer>,
    headers: HeaderMap,
    Path(name): Path<String>,
    multipart: Multipart,
) -> WebResult {
    require_write(&st, &viewer, &headers)?;
    let fail = |e| Rejection::from(error_response(&viewer, &headers, e));
    let project_id = project_id(&st, &name).await.map_err(fail)?;
    let (doc, _) = read_upload(multipart).await.map_err(fail)?;
    let stats = api::import_vex_doc(&st.db, project_id, &doc)
        .await
        .map_err(fail)?;
    let body = html! {
        p.muted { a href={ "/projects/" (name) } { "← " (name) } }
        h1 { "VEX imported" }
        p.flash role="status" { (stats.imported) " audit decisions imported." }
        @if !stats.skipped.is_empty() {
            h2 { "Skipped " span.muted { "(" (stats.skipped.len()) ")" } }
            ul { @for s in &stats.skipped { li { (s) } } }
        }
        p { a.button href={ "/projects/" (name) } { "See the findings" } }
    };
    Ok(page(&viewer, &name, Nav::Projects, body).into_response())
}

// ---------------------------------------------------------------------------------------------
// Policies

#[derive(Deserialize)]
struct NewPolicy {
    name: String,
    kind: String,
    #[serde(default)]
    value: String,
}

async fn create_policy(
    State(st): State<AppState>,
    Extension(viewer): Extension<Viewer>,
    headers: HeaderMap,
    Form(form): Form<NewPolicy>,
) -> WebResult {
    require_write(&st, &viewer, &headers)?;
    api::new_policy(&st.db, &form.name, &form.kind, &form.value)
        .await
        .map_err(|e| Rejection::from(error_response(&viewer, &headers, e)))?;
    Ok(Redirect::to("/policies?done=policy-created").into_response())
}

async fn delete_policy(
    State(st): State<AppState>,
    Extension(viewer): Extension<Viewer>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> WebResult {
    require_write(&st, &viewer, &headers)?;
    api::remove_policy(&st.db, id)
        .await
        .map_err(|e| Rejection::from(error_response(&viewer, &headers, e)))?;
    if is_htmx(&headers) {
        // The row is replaced by nothing
        return Ok(html! {}.into_response());
    }
    Ok(Redirect::to("/policies?done=policy-deleted").into_response())
}

// ---------------------------------------------------------------------------------------------
// Jobs

async fn run_job(
    State(st): State<AppState>,
    Extension(viewer): Extension<Viewer>,
    headers: HeaderMap,
    Path(job): Path<String>,
) -> WebResult {
    require_write(&st, &viewer, &headers)?;
    let result = api::run_job_now(&st, &job)
        .await
        .map_err(|e| Rejection::from(error_response(&viewer, &headers, e)))?;
    if is_htmx(&headers) {
        return Ok(html! { span role="status" { "Done: " code { (result) } } }.into_response());
    }
    let pretty = serde_json::to_string_pretty(&result).unwrap_or_default();
    let body = html! {
        p.muted { a href="/" { "← Projects" } }
        h1 { "Job " (job) " done" }
        pre { (pretty) }
    };
    Ok(page(&viewer, &job, Nav::Projects, body).into_response())
}
