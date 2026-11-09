use crate::{config::Config, jobs, policies, sbom, vex, vulns};
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, FromRequestParts, Path, Query, State},
    http::{HeaderMap, StatusCode, request::Parts},
    middleware,
    routing::{delete, get, post, put},
};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use std::{sync::Arc, time::Duration};
use tower_http::{csrf::CsrfLayer, decompression::RequestDecompressionLayer};

/// Largest SBOM or VEX document accepted, once decompressed.
pub const MAX_DOCUMENT: usize = 50 * 1024 * 1024;
/// Time an SBOM push may spend matching against the vulnerability sources. Past it, the
/// push still succeeds and the next refresh job completes the matching.
const MATCH_ON_PUSH_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
    pub config: Arc<Config>,
    pub http: reqwest::Client,
}

impl AppState {
    #[cfg(test)]
    pub fn for_tests(db: PgPool, config: Config) -> Self {
        Self {
            db,
            config: Arc::new(config),
            http: crate::http::client().unwrap(),
        }
    }
}

pub type ApiError = (StatusCode, String);
pub type ApiResult<T> = Result<T, ApiError>;

pub fn router(state: AppState) -> Router {
    // The browser sends dashboard credentials (HTTP Basic) by itself, so the forms are
    // protected against cross-site posts. The API takes bearer tokens only: no such risk.
    let mut csrf = CsrfLayer::new();
    if let Some(url) = &state.config.public_url {
        csrf = match csrf.clone().add_trusted_origin(url) {
            Ok(layer) => layer,
            Err(e) => {
                tracing::warn!("TOCSIN_PUBLIC_URL is not a valid origin for CSRF checks: {e}");
                csrf
            }
        };
    }
    let dashboard = crate::web::routes()
        .layer(csrf)
        .layer(middleware::from_fn_with_state(
            state.clone(),
            crate::web::require_auth,
        ));
    // Uploads may be gzip-compressed (Content-Encoding: gzip): SBOMs compress very well, which
    // keeps large ones under the request size limits of serverless platforms.
    let uploads = Router::new()
        .route("/api/sboms", post(ingest_sbom))
        .route("/api/projects/{name}/vex", post(import_vex))
        .layer(DefaultBodyLimit::max(MAX_DOCUMENT))
        .layer(RequestDecompressionLayer::new());
    Router::new()
        .merge(dashboard)
        .merge(crate::web::static_routes())
        .merge(uploads)
        .route("/health", get(health))
        .route("/api/projects", post(create_project).get(list_projects))
        .route("/api/projects/{name}/findings", get(project_findings))
        .route("/api/projects/{name}/violations", get(project_violations))
        .route(
            "/api/projects/{name}/analyses/{vuln}",
            put(put_analysis).delete(delete_analysis),
        )
        .route("/api/projects/{name}/vex", get(export_vex))
        .route("/api/policies", get(list_policies).post(create_policy))
        .route("/api/policies/{id}", delete(delete_policy))
        .route("/api/jobs/{job}", post(run_job))
        .with_state(state)
}

async fn health(State(st): State<AppState>) -> StatusCode {
    match sqlx::query("SELECT 1").execute(&st.db).await {
        Ok(_) => StatusCode::OK,
        Err(_) => StatusCode::SERVICE_UNAVAILABLE,
    }
}

// ---------------------------------------------------------------------------------------------
// Authentication

fn is_admin(st: &AppState, headers: &HeaderMap) -> bool {
    match (&st.config.admin_token_hash, bearer(headers)) {
        (Some(expected), Some(token)) => *expected == sha256_hex(token),
        _ => false,
    }
}

fn require_admin(st: &AppState, headers: &HeaderMap) -> ApiResult<()> {
    if st.config.admin_token_hash.is_none() {
        return Err((
            StatusCode::FORBIDDEN,
            "admin API disabled: TOCSIN_ADMIN_TOKEN is not set".into(),
        ));
    }
    if is_admin(st, headers) {
        Ok(())
    } else {
        Err(unauthorized())
    }
}

/// Project authenticated by its bearer token.
struct Project {
    id: i64,
    name: String,
}

impl FromRequestParts<AppState> for Project {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, st: &AppState) -> ApiResult<Self> {
        let token = bearer(&parts.headers).ok_or_else(unauthorized)?;
        sqlx::query_as!(
            Project,
            "SELECT id, name FROM projects WHERE token_hash = $1",
            sha256_hex(token),
        )
        .fetch_optional(&st.db)
        .await
        .map_err(internal)?
        .ok_or_else(unauthorized)
    }
}

/// Project named in the path, accessed with the admin token or that project's own token.
async fn named_project(st: &AppState, headers: &HeaderMap, name: &str) -> ApiResult<i64> {
    let project = sqlx::query!("SELECT id, token_hash FROM projects WHERE name = $1", name)
        .fetch_optional(&st.db)
        .await
        .map_err(internal)?;
    let own_token = |hash: &str| bearer(headers).is_some_and(|t| sha256_hex(t) == hash);
    match project {
        Some(p) if is_admin(st, headers) || own_token(&p.token_hash) => Ok(p.id),
        // Unknown projects answer like forbidden ones, so names cannot be probed
        _ if bearer(headers).is_none() => Err(unauthorized()),
        _ => Err((
            StatusCode::NOT_FOUND,
            "project not found or not accessible with this token".into(),
        )),
    }
}

// ---------------------------------------------------------------------------------------------
// Projects and SBOMs

#[derive(Deserialize)]
struct NewProject {
    name: String,
}

/// Admin only. Returns the project's bearer token: it is shown once, only its hash is stored.
async fn create_project(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<NewProject>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    require_admin(&st, &headers)?;
    let token = new_project(&st.db, &body.name).await?;
    Ok((
        StatusCode::CREATED,
        Json(json!({ "name": body.name, "token": token })),
    ))
}

/// Creates a project; returns its token, to show once (only its hash is stored).
pub(crate) async fn new_project(db: &PgPool, name: &str) -> ApiResult<String> {
    let valid = !name.is_empty()
        && name.len() <= 100
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c));
    if !valid {
        return Err(bad_request(
            "project name must be 1-100 chars of [A-Za-z0-9._-]",
        ));
    }

    let token = new_token();
    let inserted = sqlx::query!(
        "INSERT INTO projects (name, token_hash) VALUES ($1, $2) ON CONFLICT (name) DO NOTHING",
        name,
        sha256_hex(&token),
    )
    .execute(db)
    .await
    .map_err(internal)?
    .rows_affected();
    if inserted == 0 {
        return Err((StatusCode::CONFLICT, "project already exists".into()));
    }
    Ok(token)
}

/// Admin only. Every project with its latest release and finding counts.
async fn list_projects(State(st): State<AppState>, headers: HeaderMap) -> ApiResult<Json<Value>> {
    require_admin(&st, &headers)?;
    let rows = sqlx::query!(
        r#"SELECT p.name, ls.version AS "version?",
                  count(f.vuln_key) FILTER (WHERE NOT f.suppressed) AS "findings!",
                  count(f.vuln_key) FILTER (WHERE NOT f.suppressed AND f.kev) AS "kev!",
                  count(f.vuln_key) FILTER (WHERE NOT f.suppressed AND f.severity = 4) AS "critical!",
                  count(f.vuln_key) FILTER (WHERE NOT f.suppressed AND f.severity = 3) AS "high!"
           FROM projects p
           LEFT JOIN latest_sboms ls ON ls.project_id = p.id
           LEFT JOIN findings f ON f.project_id = p.id
           GROUP BY p.name, ls.version ORDER BY p.name"#
    )
    .fetch_all(&st.db)
    .await
    .map_err(internal)?;
    Ok(Json(json!(
        rows.into_iter()
            .map(|r| json!({
                "name": r.name, "version": r.version, "findings": r.findings,
                "kev": r.kev, "critical": r.critical, "high": r.high,
            }))
            .collect::<Vec<_>>()
    )))
}

#[derive(Deserialize)]
struct IngestQuery {
    /// Overrides metadata.component.version
    version: Option<String>,
}

/// Called by CI on each production release. Re-pushing a version replaces its SBOM. The new
/// components are matched against the vulnerability sources right away when possible.
async fn ingest_sbom(
    State(st): State<AppState>,
    project: Project,
    Query(q): Query<IngestQuery>,
    Json(doc): Json<Value>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    let summary = ingest(&st, project.id, &project.name, q.version, doc).await?;
    Ok((StatusCode::CREATED, Json(summary)))
}

/// Stores a release's SBOM, matches its new components and alerts; returns the push summary.
pub(crate) async fn ingest(
    st: &AppState,
    project_id: i64,
    project_name: &str,
    version: Option<String>,
    doc: Value,
) -> ApiResult<Value> {
    let parsed = sbom::parse(&doc).map_err(bad_request)?;
    let version = version
        .or(parsed.version)
        .filter(|v| !v.trim().is_empty())
        .ok_or_else(|| {
            bad_request("release version missing: set metadata.component.version or ?version=")
        })?;
    let count = parsed.components.len();
    let (purls, licenses): (Vec<String>, Vec<String>) = parsed
        .components
        .into_iter()
        // One text per component: Postgres arrays of arrays must be rectangular
        .map(|(purl, l)| (purl, l.into_iter().collect::<Vec<_>>().join("\n")))
        .unzip();

    let mut tx = st.db.begin().await.map_err(internal)?;
    let sbom_id = sqlx::query_scalar!(
        "INSERT INTO sboms (project_id, version, document) VALUES ($1, $2, $3)
         ON CONFLICT (project_id, version) DO UPDATE SET document = EXCLUDED.document
         RETURNING id",
        project_id,
        version,
        doc,
    )
    .fetch_one(&mut *tx)
    .await
    .map_err(internal)?;
    sqlx::query!("DELETE FROM components WHERE sbom_id = $1", sbom_id)
        .execute(&mut *tx)
        .await
        .map_err(internal)?;
    sqlx::query!(
        "INSERT INTO components (sbom_id, purl, licenses)
         SELECT $1, purl, COALESCE(string_to_array(NULLIF(licenses, ''), E'\n'), '{}')
         FROM UNNEST($2::text[], $3::text[]) AS t (purl, licenses)",
        sbom_id,
        &purls,
        &licenses,
    )
    .execute(&mut *tx)
    .await
    .map_err(internal)?;
    tx.commit().await.map_err(internal)?;

    let matching = if !st.config.match_on_push {
        "disabled"
    } else {
        let stale = vulns::stale_purls(&st.db, project_id, st.config.refresh_every)
            .await
            .map_err(internal)?;
        let osv = jobs::osv(st);
        match tokio::time::timeout(
            MATCH_ON_PUSH_TIMEOUT,
            vulns::match_purls(&st.db, &osv, &stale),
        )
        .await
        {
            Ok(Ok(_)) => "done",
            Ok(Err(e)) => {
                tracing::warn!("matching deferred for {project_name}: {e:#}");
                "deferred"
            }
            Err(_) => {
                tracing::warn!("matching deferred for {project_name}: timed out");
                "deferred"
            }
        }
    };
    jobs::snapshot_metrics(&st.db, Some(project_id))
        .await
        .map_err(internal)?;
    let alerted = jobs::alert(st, Some(project_id)).await.unwrap_or_else(|e| {
        tracing::warn!("alerting failed for {project_name}: {e:#}");
        0
    });
    let counts = sqlx::query!(
        r#"SELECT count(*) FILTER (WHERE NOT suppressed) AS "findings!",
                  count(*) FILTER (WHERE NOT suppressed AND kev) AS "kev!"
           FROM findings WHERE project_id = $1"#,
        project_id
    )
    .fetch_one(&st.db)
    .await
    .map_err(internal)?;

    Ok(json!({
        "project": project_name, "version": version, "components": count,
        "matching": matching, "findings": counts.findings, "kev": counts.kev,
        "alerted": alerted,
    }))
}

// ---------------------------------------------------------------------------------------------
// Findings, audit, VEX

/// A REAL (32-bit) value with `digits` decimals: 0.99999 would print as 0.9999899864196777.
fn round_to(value: f32, digits: i32) -> f64 {
    let factor = 10f64.powi(digits);
    (f64::from(value) * factor).round() / factor
}

#[derive(Deserialize)]
struct FindingsQuery {
    #[serde(default)]
    suppressed: bool,
}

/// Findings of the project's latest release, KEV first, then by EPSS score and severity. Suppressed findings
/// are left out unless `?suppressed=true`.
async fn project_findings(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(name): Path<String>,
    Query(q): Query<FindingsQuery>,
) -> ApiResult<Json<Value>> {
    let project_id = named_project(&st, &headers, &name).await?;
    let rows = sqlx::query!(
        r#"SELECT vuln_key AS "vuln_key!", vuln_ids AS "vuln_ids!", severity AS "severity!",
                  cvss_score, kev AS "kev!", summary, purls AS "purls!", state, justification,
                  detail, suppressed AS "suppressed!", epss, epss_percentile
           FROM findings WHERE project_id = $1 AND ($2 OR NOT suppressed)
           ORDER BY kev DESC, epss DESC NULLS LAST, severity DESC, vuln_key"#,
        project_id,
        q.suppressed,
    )
    .fetch_all(&st.db)
    .await
    .map_err(internal)?;
    let findings: Vec<Value> = rows
        .into_iter()
        .map(|r| {
            json!({
                "id": r.vuln_key,
                "advisories": r.vuln_ids,
                "severity": vulns::Severity::from_rank(r.severity).label().to_lowercase(),
                // REAL is 32-bit: 9.8 would print as 9.800000190734863
                "cvss": r.cvss_score.map(|s| (f64::from(s) * 10.0).round() / 10.0),
                "kev": r.kev,
                "epss": r.epss.map(|score| json!({
                    "score": round_to(score, 5),
                    "percentile": r.epss_percentile.map(|p| round_to(p, 5)),
                })),
                "summary": r.summary,
                "components": r.purls,
                "analysis": r.state.map(|state| json!({
                    "state": state, "justification": r.justification, "detail": r.detail,
                })),
                "suppressed": r.suppressed,
            })
        })
        .collect();
    Ok(Json(json!({ "project": name, "findings": findings })))
}

#[derive(Deserialize)]
struct AnalysisBody {
    state: String,
    justification: Option<String>,
    detail: Option<String>,
}

/// Records an audit decision for a flaw (CVE ID, or advisory ID when it has no CVE).
async fn put_analysis(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path((name, vuln)): Path<(String, String)>,
    Json(body): Json<AnalysisBody>,
) -> ApiResult<Json<Value>> {
    let project_id = named_project(&st, &headers, &name).await?;
    let analysis = vex::Analysis::validate(
        &body.state,
        body.justification.as_deref(),
        body.detail.as_deref(),
    )
    .map_err(bad_request)?;
    let key = vex::record(&st.db, project_id, &vuln, Some(&analysis))
        .await
        .map_err(internal)?;
    Ok(Json(json!({
        "project": name, "id": key, "state": analysis.state,
        "justification": analysis.justification, "detail": analysis.detail,
    })))
}

async fn delete_analysis(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path((name, vuln)): Path<(String, String)>,
) -> ApiResult<StatusCode> {
    let project_id = named_project(&st, &headers, &name).await?;
    vex::record(&st.db, project_id, &vuln, None)
        .await
        .map_err(internal)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn export_vex(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(name): Path<String>,
) -> ApiResult<Json<Value>> {
    let project_id = named_project(&st, &headers, &name).await?;
    Ok(Json(
        vex::export(&st.db, project_id, &name)
            .await
            .map_err(internal)?,
    ))
}

async fn import_vex(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(name): Path<String>,
    Json(doc): Json<Value>,
) -> ApiResult<Json<vex::ImportStats>> {
    let project_id = named_project(&st, &headers, &name).await?;
    Ok(Json(import_vex_doc(&st.db, project_id, &doc).await?))
}

/// Imports the analyses of a VEX document, then records today's metrics.
pub(crate) async fn import_vex_doc(
    db: &PgPool,
    project_id: i64,
    doc: &Value,
) -> ApiResult<vex::ImportStats> {
    let stats = vex::import(db, project_id, doc)
        .await
        .map_err(|e| bad_request(format!("{e:#}")))?;
    jobs::snapshot_metrics(db, Some(project_id))
        .await
        .map_err(internal)?;
    Ok(stats)
}

// ---------------------------------------------------------------------------------------------
// Policies

async fn list_policies(State(st): State<AppState>, headers: HeaderMap) -> ApiResult<Json<Value>> {
    require_admin(&st, &headers)?;
    let rows = sqlx::query!("SELECT id, name, kind, value FROM policies ORDER BY id")
        .fetch_all(&st.db)
        .await
        .map_err(internal)?;
    Ok(Json(json!(
        rows.into_iter()
            .map(|r| json!({ "id": r.id, "name": r.name, "kind": r.kind, "value": r.value }))
            .collect::<Vec<_>>()
    )))
}

#[derive(Deserialize)]
struct NewPolicy {
    name: String,
    kind: String,
    #[serde(default)]
    value: String,
}

async fn create_policy(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<NewPolicy>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    require_admin(&st, &headers)?;
    let policy = new_policy(&st.db, &body.name, &body.kind, &body.value).await?;
    Ok((StatusCode::CREATED, Json(policy)))
}

/// Validates and stores a policy; returns it as the API shows it.
pub(crate) async fn new_policy(
    db: &PgPool,
    name: &str,
    kind: &str,
    value: &str,
) -> ApiResult<Value> {
    let name = name.trim();
    if name.is_empty() {
        return Err(bad_request("policy name is required"));
    }
    let value = policies::validate(kind, value).map_err(bad_request)?;
    let id = sqlx::query_scalar!(
        "INSERT INTO policies (name, kind, value) VALUES ($1, $2, $3) RETURNING id",
        name,
        kind,
        value,
    )
    .fetch_one(db)
    .await
    .map_err(internal)?;
    Ok(json!({ "id": id, "name": name, "kind": kind, "value": value }))
}

async fn delete_policy(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> ApiResult<StatusCode> {
    require_admin(&st, &headers)?;
    remove_policy(&st.db, id).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub(crate) async fn remove_policy(db: &PgPool, id: i64) -> ApiResult<()> {
    let deleted = sqlx::query!("DELETE FROM policies WHERE id = $1", id)
        .execute(db)
        .await
        .map_err(internal)?
        .rows_affected();
    if deleted == 0 {
        return Err((StatusCode::NOT_FOUND, "policy not found".into()));
    }
    Ok(())
}

async fn project_violations(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(name): Path<String>,
) -> ApiResult<Json<Vec<policies::Violation>>> {
    let project_id = named_project(&st, &headers, &name).await?;
    Ok(Json(
        policies::violations(&st.db, Some(project_id))
            .await
            .map_err(internal)?,
    ))
}

// ---------------------------------------------------------------------------------------------
// Jobs

/// Admin only. Runs a job now, for external schedulers (Cloud Scheduler, cron…).
async fn run_job(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(job): Path<String>,
) -> ApiResult<Json<Value>> {
    require_admin(&st, &headers)?;
    Ok(Json(run_job_now(&st, &job).await?))
}

/// Runs a job now; an unknown job is a 404, a failed one a 502 with its error.
pub(crate) async fn run_job_now(st: &AppState, job: &str) -> ApiResult<Value> {
    if !jobs::JOBS.contains(&job) {
        return Err((
            StatusCode::NOT_FOUND,
            format!("unknown job, expected one of {:?}", jobs::JOBS),
        ));
    }
    jobs::run(st, job).await.map_err(|e| {
        tracing::warn!("job {job} failed: {e:#}");
        (StatusCode::BAD_GATEWAY, format!("job {job} failed: {e:#}"))
    })
}

// ---------------------------------------------------------------------------------------------
// Helpers

fn bearer(headers: &HeaderMap) -> Option<&str> {
    headers
        .get("authorization")?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
}

pub fn sha256_hex(s: &str) -> String {
    hex(&Sha256::digest(s.as_bytes()))
}

fn new_token() -> String {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).expect("OS random generator unavailable");
    hex(&bytes)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unauthorized() -> ApiError {
    (
        StatusCode::UNAUTHORIZED,
        "invalid or missing bearer token".into(),
    )
}

pub(crate) fn bad_request(msg: impl Into<String>) -> ApiError {
    (StatusCode::BAD_REQUEST, msg.into())
}

pub fn internal(e: impl std::fmt::Display) -> ApiError {
    tracing::error!("{e}");
    (StatusCode::INTERNAL_SERVER_ERROR, "internal error".into())
}
