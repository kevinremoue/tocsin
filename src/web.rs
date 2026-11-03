//! Server-side-rendered dashboard. maud escapes every interpolated value: purls come from CI input.
use crate::api::{ApiResult, AppState, internal};
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
};
use maud::{DOCTYPE, Markup, PreEscaped, html};
use serde::Deserialize;
use sqlx::PgPool;

const KEV_PAGE_SIZE: i64 = 100;

const CSS: &str = r#"
:root { --bg:#fff; --fg:#1b1f24; --muted:#656d76; --line:#d8dee4; --accent:#0969da; --row:#f6f8fa; --err:#cf222e; }
@media (prefers-color-scheme: dark) {
  :root { --bg:#0d1117; --fg:#e6edf3; --muted:#8d96a0; --line:#30363d; --accent:#4493f8; --row:#161b22; --err:#f85149; }
}
* { box-sizing: border-box; }
body { margin:0; background:var(--bg); color:var(--fg); font:15px/1.5 system-ui, sans-serif; }
header { border-bottom:1px solid var(--line); padding:12px 16px; display:flex; gap:24px; align-items:baseline; }
header a { color:var(--fg); text-decoration:none; }
header a.brand { font-weight:700; }
header nav { display:flex; gap:16px; }
header nav a { color:var(--muted); }
header nav a:hover { color:var(--fg); }
main { max-width:1100px; margin:0 auto; padding:16px; }
h1 { font-size:1.4rem; margin:8px 0 16px; }
h2 { font-size:1.1rem; margin:28px 0 8px; }
a { color:var(--accent); }
.muted { color:var(--muted); }
.error { color:var(--err); }
.status { font-size:.9rem; margin:-8px 0 16px; }
.scroll { overflow-x:auto; }
table { width:100%; border-collapse:collapse; }
th, td { text-align:left; padding:6px 10px; border-bottom:1px solid var(--line); white-space:nowrap; }
th { color:var(--muted); font-weight:600; font-size:.85rem; }
tbody tr:hover { background:var(--row); }
td.num, th.num { text-align:right; }
code { font:13px ui-monospace, monospace; }
table.kev td { white-space:normal; }
table.kev td.nowrap { white-space:nowrap; }
.badge { display:inline-block; padding:0 8px; border-radius:10px; font-size:.8rem; font-weight:600; background:var(--err); color:#fff; }
form.filters { display:flex; flex-wrap:wrap; gap:12px; align-items:center; margin:0 0 12px; }
form.filters input[type=search] { min-width:280px; padding:5px 8px; border:1px solid var(--line); border-radius:6px; background:var(--bg); color:var(--fg); font:inherit; }
form.filters button { padding:5px 14px; border:1px solid var(--line); border-radius:6px; background:var(--row); color:var(--fg); font:inherit; cursor:pointer; }
.pager { display:flex; gap:16px; margin:12px 0; }
dl { display:grid; grid-template-columns:max-content 1fr; gap:8px 24px; margin:0; }
dt { color:var(--muted); font-weight:600; }
dd { margin:0; }
dd ul { margin:0; padding-left:18px; }
"#;

fn page_html(title: &str, body: Markup) -> Markup {
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
                    nav { a href="/" { "Projects" } a href="/kev" { "KEV catalog" } }
                }
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

    let kev_status = kev_status(&st.db, true).await?;

    Ok(page_html(
        "Projects",
        html! {
            h1 { "Projects" }
            (kev_status)
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

    Ok(page_html(
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

/// One-line status of the KEV catalog sync, with the last error if the latest attempt failed.
/// `link` prefixes it with a link to the catalog page (not wanted on that page itself).
async fn kev_status(db: &PgPool, link: bool) -> ApiResult<Markup> {
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

#[derive(Deserialize)]
pub struct KevQuery {
    /// Searched in the CVE ID, vendor, product and name
    q: Option<String>,
    /// Checkbox: present ("on") to keep only entries used in ransomware campaigns
    ransomware: Option<String>,
    page: Option<i64>,
}

/// URL of a page of the KEV list, keeping the current filters.
fn kev_list_url(q: Option<&str>, ransomware: bool, page: i64) -> String {
    let mut params = Vec::new();
    if let Some(q) = q {
        params.push(("q", q.to_owned()));
    }
    if ransomware {
        params.push(("ransomware", "on".to_owned()));
    }
    if page > 1 {
        params.push(("page", page.to_string()));
    }
    match serde_urlencoded::to_string(&params) {
        Ok(qs) if !qs.is_empty() => format!("/kev?{qs}"),
        _ => "/kev".into(),
    }
}

pub async fn kev_list(
    State(st): State<AppState>,
    Query(query): Query<KevQuery>,
) -> ApiResult<Markup> {
    let q = query.q.as_deref().map(str::trim).filter(|q| !q.is_empty());
    // ILIKE wildcards typed by the user are matched literally
    let pattern = q.map(|q| {
        let escaped = q
            .replace('\\', "\\\\")
            .replace('%', "\\%")
            .replace('_', "\\_");
        format!("%{escaped}%")
    });
    let ransomware = query.ransomware.is_some();
    let page = query.page.unwrap_or(1).max(1);

    let total = sqlx::query_scalar!(
        r#"SELECT count(*) AS "total!" FROM kev_entries
           WHERE ($1::text IS NULL OR cve_id ILIKE $1 OR vendor_project ILIKE $1
                  OR product ILIKE $1 OR name ILIKE $1)
             AND (NOT $2 OR known_ransomware)"#,
        pattern,
        ransomware,
    )
    .fetch_one(&st.db)
    .await
    .map_err(internal)?;

    let entries = sqlx::query!(
        r#"SELECT cve_id, vendor_project, product, name, known_ransomware,
                  to_char(date_added, 'YYYY-MM-DD') AS "date_added!"
           FROM kev_entries
           WHERE ($1::text IS NULL OR cve_id ILIKE $1 OR vendor_project ILIKE $1
                  OR product ILIKE $1 OR name ILIKE $1)
             AND (NOT $2 OR known_ransomware)
           ORDER BY date_added DESC, cve_id DESC
           LIMIT $3 OFFSET $4"#,
        pattern,
        ransomware,
        KEV_PAGE_SIZE,
        (page - 1) * KEV_PAGE_SIZE,
    )
    .fetch_all(&st.db)
    .await
    .map_err(internal)?;

    let kev_status = kev_status(&st.db, false).await?;
    let first = (page - 1) * KEV_PAGE_SIZE + 1;
    let last = (page - 1) * KEV_PAGE_SIZE + entries.len() as i64;
    let filtered = q.is_some() || ransomware;

    Ok(page_html(
        "KEV catalog",
        html! {
            h1 { "KEV catalog" }
            (kev_status)
            form.filters method="get" action="/kev" {
                input type="search" name="q" value=(q.unwrap_or_default())
                    placeholder="CVE, vendor, product or name" aria-label="Search";
                label { input type="checkbox" name="ransomware" checked[ransomware]; " Used in ransomware" }
                button type="submit" { "Filter" }
                @if filtered { a href="/kev" { "Clear" } }
            }
            @if entries.is_empty() {
                p.muted {
                    @if filtered { "No entry matches these filters." } @else { "The catalog is empty." }
                }
            } @else {
                p.muted { "Showing " (first) "–" (last) " of " (total) }
                div.scroll { table.kev {
                    thead { tr {
                        th { "CVE" } th { "Vendor" } th { "Product" } th { "Vulnerability" }
                        th { "Added" } th { "Ransomware" }
                    } }
                    tbody { @for e in &entries { tr {
                        td.nowrap { a href={ "/kev/" (e.cve_id) } { code { (e.cve_id) } } }
                        td { (e.vendor_project) }
                        td { (e.product) }
                        td { (e.name) }
                        td.nowrap.muted { (e.date_added) }
                        td { @if e.known_ransomware { span.badge { "Known" } } }
                    } } }
                } }
                div.pager {
                    @if page > 1 { a href=(kev_list_url(q, ransomware, page - 1)) { "← Previous" } }
                    @if last < total { a href=(kev_list_url(q, ransomware, page + 1)) { "Next →" } }
                }
            }
        },
    ))
}

/// http(s) URLs found in the free-text `notes` field of a KEV entry.
fn note_links(notes: &str) -> Vec<&str> {
    notes
        .split(|c: char| c.is_whitespace() || c == ';')
        .filter(|t| t.starts_with("https://") || t.starts_with("http://"))
        .collect()
}

pub async fn kev_entry(State(st): State<AppState>, Path(cve): Path<String>) -> ApiResult<Markup> {
    let e = sqlx::query!(
        r#"SELECT cve_id, vendor_project, product, name, known_ransomware,
                  to_char(date_added, 'YYYY-MM-DD') AS "date_added!",
                  data->>'shortDescription' AS description,
                  data->>'requiredAction' AS required_action,
                  data->>'dueDate' AS due_date,
                  data->>'notes' AS notes,
                  ARRAY(SELECT jsonb_array_elements_text(
                            CASE WHEN jsonb_typeof(data->'cwes') = 'array' THEN data->'cwes' ELSE '[]' END
                        )) AS "cwes!",
                  to_char(first_seen_at, 'YYYY-MM-DD HH24:MI') AS "first_seen_at!"
           FROM kev_entries WHERE cve_id = $1"#,
        cve
    )
    .fetch_optional(&st.db)
    .await
    .map_err(internal)?
    .ok_or((StatusCode::NOT_FOUND, "CVE not in the KEV catalog".into()))?;

    let nvd = format!("https://nvd.nist.gov/vuln/detail/{}", e.cve_id);
    // CISA's notes often include the NVD page already
    let links: Vec<&str> = e
        .notes
        .as_deref()
        .map(note_links)
        .unwrap_or_default()
        .into_iter()
        .filter(|l| *l != nvd)
        .collect();

    Ok(page_html(
        &e.cve_id,
        html! {
            p.muted { a href="/kev" { "← KEV catalog" } }
            h1 { (e.cve_id) " " @if e.known_ransomware { span.badge { "Used in ransomware" } } }
            p { (e.name) }
            dl {
                dt { "Vendor" } dd { (e.vendor_project) }
                dt { "Product" } dd { (e.product) }
                @if let Some(description) = &e.description { dt { "Description" } dd { (description) } }
                @if let Some(action) = &e.required_action { dt { "Required action" } dd { (action) } }
                dt { "Added to KEV" } dd { (e.date_added) }
                @if let Some(due) = &e.due_date { dt { "Due date" } dd { (due) " " span.muted { "(for US federal agencies)" } } }
                dt { "Ransomware use" } dd { @if e.known_ransomware { "Known" } @else { "Unknown" } }
                @if !e.cwes.is_empty() {
                    dt { "Weaknesses" }
                    dd { @for (i, cwe) in e.cwes.iter().enumerate() {
                        @if i > 0 { ", " }
                        @match cwe.strip_prefix("CWE-").filter(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit())) {
                            Some(n) => { a href={ "https://cwe.mitre.org/data/definitions/" (n) ".html" } { (cwe) } }
                            None => { (cwe) }
                        }
                    } }
                }
                dt { "References" }
                dd { ul {
                    li { a href=(nvd) { "NVD" } }
                    @for link in &links { li { a href=(link) rel="noreferrer" { (link) } } }
                } }
                dt { "First seen by Tocsin" } dd.muted { (e.first_seen_at) " UTC" }
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
        assert!(html.contains(r#"<a href="/kev">KEV catalog</a>: not synced yet"#));

        sqlx::query(
            "UPDATE kev_sync SET catalog_version = '2026.10.30', checked_at = now(),
                                 last_error = '<b>boom</b>', last_attempt_at = now()",
        )
        .execute(&db)
        .await
        .unwrap();
        let (_, html) = get(&db, "/").await;
        assert!(html.contains("0 entries, version 2026.10.30"));
        assert!(html.contains("Last sync failed") && html.contains("&lt;b&gt;boom&lt;/b&gt;"));

        let (status, html) = get(&db, "/projects/demo").await;
        assert_eq!(status, StatusCode::OK);
        assert!(html.contains("pkg:npm/&lt;script&gt;x&lt;/script&gt;@1"));
        assert!(!html.contains("<script>"));

        let (status, _) = get(&db, "/projects/unknown").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    async fn insert_kev(
        db: &PgPool,
        cve: &str,
        vendor: &str,
        ransomware: bool,
        data: serde_json::Value,
    ) {
        sqlx::query(
            "INSERT INTO kev_entries (cve_id, vendor_project, product, name, date_added, known_ransomware, data)
             VALUES ($1, $2, 'Widget', $2 || ' Widget flaw', '2026-10-30', $3, $4)",
        )
        .bind(cve)
        .bind(vendor)
        .bind(ransomware)
        .bind(data)
        .execute(db)
        .await
        .unwrap();
    }

    #[sqlx::test]
    async fn kev_list_filters_and_detail(db: PgPool) {
        insert_kev(
            &db,
            "CVE-2026-0001",
            "Acme",
            true,
            serde_json::json!({
                "shortDescription": "<script>alert(1)</script>",
                "requiredAction": "Apply updates.",
                "dueDate": "2026-11-20",
                "notes": "https://acme.example/advisory ; javascript:alert(1) ; BOD: https://cisa.example/bod",
                "cwes": ["CWE-79", "NVD-CWE-noinfo"]
            }),
        )
        .await;
        insert_kev(&db, "CVE-2026-0002", "Globex", false, serde_json::json!({})).await;

        let (status, html) = get(&db, "/kev").await;
        assert_eq!(status, StatusCode::OK);
        assert!(html.contains("Showing 1–2 of 2"));
        assert!(html.contains(r#"href="/kev/CVE-2026-0001""#) && html.contains("CVE-2026-0002"));

        let (_, html) = get(&db, "/kev?q=globex").await;
        assert!(html.contains("CVE-2026-0002") && !html.contains("CVE-2026-0001"));
        let (_, html) = get(&db, "/kev?ransomware=on").await;
        assert!(html.contains("CVE-2026-0001") && !html.contains("CVE-2026-0002"));
        // LIKE wildcards are matched literally
        let (_, html) = get(&db, "/kev?q=%25").await;
        assert!(html.contains("No entry matches"));

        let (status, html) = get(&db, "/kev/CVE-2026-0001").await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            html.contains("&lt;script&gt;alert(1)&lt;/script&gt;") && !html.contains("<script>")
        );
        assert!(html.contains(r#"href="https://acme.example/advisory""#));
        assert!(html.contains(r#"href="https://cisa.example/bod""#));
        assert!(!html.contains("javascript:"));
        assert!(html.contains(r#"href="https://cwe.mitre.org/data/definitions/79.html""#));
        assert!(html.contains("NVD-CWE-noinfo"));

        // An entry with only the required fields still renders
        let (status, _) = get(&db, "/kev/CVE-2026-0002").await;
        assert_eq!(status, StatusCode::OK);
        let (status, _) = get(&db, "/kev/CVE-1999-9999").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[sqlx::test]
    async fn kev_list_paginates_and_keeps_filters(db: PgPool) {
        sqlx::query(
            "INSERT INTO kev_entries (cve_id, vendor_project, product, name, date_added, known_ransomware, data)
             SELECT 'CVE-2026-' || lpad(i::text, 4, '0'), 'Acme', 'Widget', 'flaw', '2026-10-30', true, '{}'
             FROM generate_series(1, 150) i",
        )
        .execute(&db)
        .await
        .unwrap();

        let (_, html) = get(&db, "/kev?q=acme&ransomware=on").await;
        assert!(html.contains("Showing 1–100 of 150"));
        assert!(html.contains(r#"href="/kev?q=acme&amp;ransomware=on&amp;page=2""#));
        assert!(!html.contains("Previous"));

        let (_, html) = get(&db, "/kev?q=acme&ransomware=on&page=2").await;
        assert!(html.contains("Showing 101–150 of 150"));
        assert!(html.contains("Previous") && !html.contains("Next"));
    }
}
