use crate::sbom;
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, FromRequestParts, Query, State},
    http::{HeaderMap, StatusCode, request::Parts},
    routing::{get, post},
};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::PgPool;

#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
    /// SHA-256 of TOCSIN_ADMIN_TOKEN; None = admin API disabled
    pub admin_token_hash: Option<String>,
}

pub type ApiError = (StatusCode, String);
pub type ApiResult<T> = Result<T, ApiError>;

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/", get(crate::web::index))
        .route("/projects/{name}", get(crate::web::project))
        .route("/kev", get(crate::web::kev_list))
        .route("/kev/{cve}", get(crate::web::kev_entry))
        .route("/health", get(health))
        .route("/api/projects", post(create_project))
        // ponytail: axum's 2 MB default is too small for large SBOMs
        .route(
            "/api/sboms",
            post(ingest_sbom).layer(DefaultBodyLimit::max(50 * 1024 * 1024)),
        )
        .with_state(state)
}

async fn health(State(st): State<AppState>) -> StatusCode {
    match sqlx::query("SELECT 1").execute(&st.db).await {
        Ok(_) => StatusCode::OK,
        Err(_) => StatusCode::SERVICE_UNAVAILABLE,
    }
}

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
    match (&st.admin_token_hash, bearer(&headers)) {
        (None, _) => {
            return Err((
                StatusCode::FORBIDDEN,
                "admin API disabled: TOCSIN_ADMIN_TOKEN is not set".into(),
            ));
        }
        (Some(expected), Some(token)) if *expected == sha256_hex(token) => {}
        _ => return Err(unauthorized()),
    }

    let name = body.name;
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
    .execute(&st.db)
    .await
    .map_err(internal)?
    .rows_affected();
    if inserted == 0 {
        return Err((StatusCode::CONFLICT, "project already exists".into()));
    }

    Ok((
        StatusCode::CREATED,
        Json(json!({ "name": name, "token": token })),
    ))
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

#[derive(Deserialize)]
struct IngestQuery {
    /// Overrides metadata.component.version
    version: Option<String>,
}

/// Called by CI on each production release. Re-pushing a version replaces its SBOM.
async fn ingest_sbom(
    State(st): State<AppState>,
    project: Project,
    Query(q): Query<IngestQuery>,
    Json(doc): Json<Value>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    let parsed = sbom::parse(&doc).map_err(bad_request)?;
    let version = q
        .version
        .or(parsed.version)
        .filter(|v| !v.trim().is_empty())
        .ok_or_else(|| {
            bad_request("release version missing: set metadata.component.version or ?version=")
        })?;
    let purls: Vec<String> = parsed.purls.into_iter().collect();

    let mut tx = st.db.begin().await.map_err(internal)?;
    let sbom_id = sqlx::query_scalar!(
        "INSERT INTO sboms (project_id, version, document) VALUES ($1, $2, $3)
         ON CONFLICT (project_id, version) DO UPDATE SET document = EXCLUDED.document
         RETURNING id",
        project.id,
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
        "INSERT INTO components (sbom_id, purl) SELECT $1, unnest($2::text[])",
        sbom_id,
        &purls,
    )
    .execute(&mut *tx)
    .await
    .map_err(internal)?;
    tx.commit().await.map_err(internal)?;

    Ok((
        StatusCode::CREATED,
        Json(json!({ "project": project.name, "version": version, "components": purls.len() })),
    ))
}

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

fn bad_request(msg: impl Into<String>) -> ApiError {
    (StatusCode::BAD_REQUEST, msg.into())
}

pub fn internal(e: impl std::fmt::Display) -> ApiError {
    tracing::error!("{e}");
    (StatusCode::INTERNAL_SERVER_ERROR, "internal error".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request};
    use tower::ServiceExt;

    async fn call(app: &Router, req: Request<Body>) -> (StatusCode, Value) {
        let res = app.clone().oneshot(req).await.unwrap();
        let status = res.status();
        let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
            .await
            .unwrap();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    fn post_json(uri: &str, token: &str, body: Value) -> Request<Body> {
        Request::post(uri)
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap()
    }

    #[sqlx::test]
    async fn project_creation_and_sbom_ingestion(db: PgPool) {
        let app = router(AppState {
            db: db.clone(),
            admin_token_hash: Some(sha256_hex("admin")),
        });

        let new = json!({ "name": "demo" });
        let (status, _) = call(&app, post_json("/api/projects", "nope", new.clone())).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);

        let (status, body) = call(&app, post_json("/api/projects", "admin", new.clone())).await;
        assert_eq!(status, StatusCode::CREATED);
        let token = body["token"].as_str().unwrap().to_owned();

        let (status, _) = call(&app, post_json("/api/projects", "admin", new)).await;
        assert_eq!(status, StatusCode::CONFLICT);

        let bom = json!({
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "metadata": { "component": { "name": "demo", "version": "1.2.0" } },
            "components": [
                { "purl": "pkg:maven/org.a/b@1.0" },
                { "purl": "pkg:npm/x@2.0", "components": [{ "purl": "pkg:npm/y@3.0" }] },
                { "purl": "pkg:npm/x@2.0" },
                { "name": "no-purl" }
            ]
        });

        let (status, _) = call(&app, post_json("/api/sboms", "wrong", bom.clone())).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);

        let (status, body) = call(&app, post_json("/api/sboms", &token, bom.clone())).await;
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(body["version"], "1.2.0");
        assert_eq!(body["components"], 3);

        // Re-push of the same release replaces it instead of duplicating
        let (status, _) = call(&app, post_json("/api/sboms", &token, bom)).await;
        assert_eq!(status, StatusCode::CREATED);
        let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM components")
            .fetch_one(&db)
            .await
            .unwrap();
        assert_eq!(rows, 3);

        let no_version = json!({ "bomFormat": "CycloneDX", "components": [] });
        let (status, _) = call(&app, post_json("/api/sboms", &token, no_version)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }
}
