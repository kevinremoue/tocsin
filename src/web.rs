//! Server-side-rendered dashboard. maud escapes every interpolated value: purls come from CI input.
use crate::api::{ApiResult, AppState, internal};
use axum::{
    extract::{Path, State},
    http::StatusCode,
};
use maud::{DOCTYPE, Markup, PreEscaped, html};

const CSS: &str = r#"
:root { --bg:#fff; --fg:#1b1f24; --muted:#656d76; --line:#d8dee4; --accent:#0969da; --row:#f6f8fa; }
@media (prefers-color-scheme: dark) {
  :root { --bg:#0d1117; --fg:#e6edf3; --muted:#8d96a0; --line:#30363d; --accent:#4493f8; --row:#161b22; }
}
* { box-sizing: border-box; }
body { margin:0; background:var(--bg); color:var(--fg); font:15px/1.5 system-ui, sans-serif; }
header { border-bottom:1px solid var(--line); padding:12px 16px; }
header a { color:var(--fg); font-weight:700; text-decoration:none; }
main { max-width:1100px; margin:0 auto; padding:16px; }
h1 { font-size:1.4rem; margin:8px 0 16px; }
h2 { font-size:1.1rem; margin:28px 0 8px; }
a { color:var(--accent); }
.muted { color:var(--muted); }
.scroll { overflow-x:auto; }
table { width:100%; border-collapse:collapse; }
th, td { text-align:left; padding:6px 10px; border-bottom:1px solid var(--line); white-space:nowrap; }
th { color:var(--muted); font-weight:600; font-size:.85rem; }
tbody tr:hover { background:var(--row); }
td.num, th.num { text-align:right; }
code { font:13px ui-monospace, monospace; }
"#;

fn page(title: &str, body: Markup) -> Markup {
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
                header { a href="/" { "🔔 Tocsin" } }
                main { (body) }
            }
        }
    }
}

pub async fn index(State(st): State<AppState>) -> ApiResult<Markup> {
    let projects = sqlx::query!(
        r#"SELECT p.name,
                  l.version AS "version?",
                  to_char(l.created_at, 'YYYY-MM-DD HH24:MI') AS "released_at?",
                  (SELECT count(*) FROM components c WHERE c.sbom_id = l.id) AS "components!",
                  (SELECT count(*) FROM sboms s WHERE s.project_id = p.id) AS "releases!"
           FROM projects p
           LEFT JOIN LATERAL (
               SELECT id, version, created_at FROM sboms
               WHERE project_id = p.id ORDER BY created_at DESC, id DESC LIMIT 1
           ) l ON true
           ORDER BY p.name"#
    )
    .fetch_all(&st.db)
    .await
    .map_err(internal)?;

    Ok(page(
        "Projects",
        html! {
            h1 { "Projects" }
            @if projects.is_empty() {
                p.muted { "No projects yet. Create one with " code { "POST /api/projects" } "." }
            } @else {
                div.scroll { table {
                    thead { tr {
                        th { "Project" } th { "Latest release" } th { "Released (UTC)" }
                        th.num { "Components" } th.num { "Releases" }
                    } }
                    tbody { @for p in &projects { tr {
                        td { a href={ "/projects/" (p.name) } { (p.name) } }
                        td { (p.version.as_deref().unwrap_or("—")) }
                        td.muted { (p.released_at.as_deref().unwrap_or("—")) }
                        td.num { (p.components) }
                        td.num { (p.releases) }
                    } } }
                } }
            }
        },
    ))
}

pub async fn project(State(st): State<AppState>, Path(name): Path<String>) -> ApiResult<Markup> {
    let project_id = sqlx::query_scalar!("SELECT id FROM projects WHERE name = $1", name)
        .fetch_optional(&st.db)
        .await
        .map_err(internal)?
        .ok_or((StatusCode::NOT_FOUND, "project not found".into()))?;

    let releases = sqlx::query!(
        r#"SELECT s.version,
                  to_char(s.created_at, 'YYYY-MM-DD HH24:MI') AS "released_at!",
                  (SELECT count(*) FROM components c WHERE c.sbom_id = s.id) AS "components!"
           FROM sboms s WHERE s.project_id = $1
           ORDER BY s.created_at DESC, s.id DESC"#,
        project_id
    )
    .fetch_all(&st.db)
    .await
    .map_err(internal)?;

    let purls = sqlx::query_scalar!(
        "SELECT purl FROM components WHERE sbom_id = (
             SELECT id FROM sboms WHERE project_id = $1 ORDER BY created_at DESC, id DESC LIMIT 1
         ) ORDER BY purl",
        project_id
    )
    .fetch_all(&st.db)
    .await
    .map_err(internal)?;

    Ok(page(
        &name,
        html! {
            h1 { (name) }
            @if releases.is_empty() {
                p.muted { "No SBOM received for this project yet." }
            } @else {
                h2 { "Releases" }
                div.scroll { table {
                    thead { tr { th { "Version" } th { "Released (UTC)" } th.num { "Components" } } }
                    tbody { @for r in &releases { tr {
                        td { (r.version) }
                        td.muted { (r.released_at) }
                        td.num { (r.components) }
                    } } }
                } }
                h2 { "Components of the latest release " span.muted { "(" (purls.len()) ")" } }
                div.scroll { table { tbody { @for purl in &purls { tr { td { code { (purl) } } } } } } }
            }
        },
    ))
}

#[cfg(test)]
mod tests {
    use crate::api::{AppState, router};
    use axum::{body::Body, http::Request, http::StatusCode};
    use sqlx::PgPool;
    use tower::ServiceExt;

    async fn get(db: &PgPool, uri: &str) -> (StatusCode, String) {
        let app = router(AppState {
            db: db.clone(),
            admin_token_hash: None,
        });
        let res = app
            .oneshot(Request::get(uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status = res.status();
        let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
            .await
            .unwrap();
        (status, String::from_utf8(bytes.to_vec()).unwrap())
    }

    #[sqlx::test]
    async fn dashboard_lists_projects_and_escapes_purls(db: PgPool) {
        sqlx::query(
            "WITH p AS (INSERT INTO projects (name, token_hash) VALUES ('demo', 'h') RETURNING id),
                  s AS (INSERT INTO sboms (project_id, version, document)
                        SELECT id, '1.2.0', '{}' FROM p RETURNING id)
             INSERT INTO components (sbom_id, purl) SELECT id, 'pkg:npm/<script>x</script>@1' FROM s",
        )
        .execute(&db)
        .await
        .unwrap();

        let (status, html) = get(&db, "/").await;
        assert_eq!(status, StatusCode::OK);
        assert!(html.contains(r#"href="/projects/demo""#) && html.contains("1.2.0"));

        let (status, html) = get(&db, "/projects/demo").await;
        assert_eq!(status, StatusCode::OK);
        assert!(html.contains("pkg:npm/&lt;script&gt;x&lt;/script&gt;@1"));
        assert!(!html.contains("<script>"));

        let (status, _) = get(&db, "/projects/unknown").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }
}
