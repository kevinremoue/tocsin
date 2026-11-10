use super::{
    AnalysisCell, Nav, PAGE_SIZE, Viewer, analysis_cell, epss, flash, kev_badge, like_pattern,
    not_found, page, pager, purl_list, safe_links, search_term, severity, url,
};
use crate::api::{ApiResult, AppState, internal};
use axum::{
    Extension,
    extract::{Path, Query, State},
};
use maud::{Markup, html};
use serde::Deserialize;

#[derive(Deserialize)]
pub struct ListQuery {
    q: Option<String>,
    /// Present: only vulnerabilities in the KEV catalog
    kev: Option<String>,
    page: Option<i64>,
}

/// Every vulnerability affecting at least one project (unsuppressed), across the portfolio.
pub async fn list(
    State(st): State<AppState>,
    Extension(viewer): Extension<Viewer>,
    Query(query): Query<ListQuery>,
) -> ApiResult<Markup> {
    let q = search_term(&query.q);
    let pattern = like_pattern(q);
    let kev_only = query.kev.is_some();
    let page_no = query.page.unwrap_or(1).max(1);

    let rows = sqlx::query!(
        r#"SELECT vuln_key AS "vuln_key!", max(severity) AS "severity!", max(cvss_score) AS cvss_score,
                  bool_or(kev) AS "kev!", max(epss) AS epss, (array_agg(summary ORDER BY summary IS NULL))[1] AS summary,
                  array_agg(DISTINCT p.name ORDER BY p.name) AS "projects!",
                  count(*) OVER () AS "total!"
           FROM findings f JOIN projects p ON p.id = f.project_id
           WHERE NOT f.suppressed AND (NOT $1 OR f.kev)
             AND ($2::text IS NULL OR f.vuln_key ILIKE $2 OR f.summary ILIKE $2
                  OR EXISTS (SELECT 1 FROM unnest(f.purls) u WHERE u ILIKE $2))
           GROUP BY vuln_key
           ORDER BY bool_or(kev) DESC, max(epss) DESC NULLS LAST, max(severity) DESC, count(*) DESC,
                    vuln_key
           LIMIT $3 OFFSET $4"#,
        kev_only,
        pattern,
        PAGE_SIZE,
        (page_no - 1) * PAGE_SIZE,
    )
    .fetch_all(&st.db)
    .await
    .map_err(internal)?;
    let total = rows.first().map(|r| r.total).unwrap_or(0);
    let first = (page_no - 1) * PAGE_SIZE + 1;
    let last = (page_no - 1) * PAGE_SIZE + rows.len() as i64;
    let filtered = q.is_some() || kev_only;
    let link = |p: i64| {
        url(
            "/vulns",
            &[
                ("q", q.unwrap_or_default().to_owned()),
                ("kev", if kev_only { "on".into() } else { String::new() }),
                ("page", if p > 1 { p.to_string() } else { String::new() }),
            ],
        )
    };

    Ok(page(
        &viewer,
        "Vulnerabilities",
        Nav::Vulns,
        html! {
            h1 { "Vulnerabilities" }
            p.status.muted { "Known vulnerabilities affecting the latest release of your projects, suppressed findings excluded." }
            form.filters method="get" action="/vulns" {
                input type="search" name="q" value=(q.unwrap_or_default())
                    placeholder="CVE, summary or package" aria-label="Search";
                label { input type="checkbox" name="kev" checked[kev_only]; " Actively exploited (KEV)" }
                button type="submit" { "Filter" }
                @if filtered { a href="/vulns" { "Clear" } }
            }
            @if rows.is_empty() {
                p.muted { @if filtered { "No vulnerability matches these filters." } @else { "No known vulnerability affects your projects." } }
            } @else {
                p.muted { "Showing " (first) "–" (last) " of " (total) }
                div.scroll { table {
                    thead { tr {
                        th { "Vulnerability" } th { "Severity" } th.num { "CVSS" } th.num { "EPSS" } th { "Summary" } th { "Projects" }
                    } }
                    tbody { @for r in &rows { tr {
                        td.nowrap { a href={ "/vulns/" (r.vuln_key) } { code { (r.vuln_key) } } @if r.kev { " " (kev_badge()) } }
                        td { (severity(r.severity)) }
                        td.num { @if let Some(s) = r.cvss_score { (format!("{s:.1}")) } }
                        td.num { (epss(r.epss)) }
                        td { (r.summary.as_deref().unwrap_or("")) }
                        td { @for (i, p) in r.projects.iter().enumerate() {
                            @if i > 0 { ", " } a href={ "/projects/" (p) } { (p) }
                        } }
                    } } }
                } }
                (pager(page_no, last, total, link))
            }
        },
    ))
}

#[derive(Deserialize)]
pub struct DetailQuery {
    done: Option<String>,
}

/// A vulnerability: its advisories (one per source), references, and the projects it affects.
/// `id` is the current name (usually a CVE), any advisory ID or any of its CVEs.
pub async fn detail(
    State(st): State<AppState>,
    Extension(viewer): Extension<Viewer>,
    Path(id): Path<String>,
    Query(dq): Query<DetailQuery>,
) -> ApiResult<Markup> {
    let key = crate::identity::resolve(&st.db, &id)
        .await
        .map_err(internal)?
        .ok_or_else(|| not_found("vulnerability"))?;

    let advisories = sqlx::query!(
        r#"SELECT id, summary, severity, cvss_score, cvss_vector, withdrawn, cve_ids,
                  to_char(published_at, 'YYYY-MM-DD') AS published,
                  data->>'details' AS details,
                  ARRAY(SELECT r->>'url' FROM jsonb_array_elements(
                            CASE WHEN jsonb_typeof(data->'references') = 'array'
                                 THEN data->'references' ELSE '[]' END) r) AS "references!"
           FROM vulnerabilities WHERE canonical_id = $1 ORDER BY id"#,
        key
    )
    .fetch_all(&st.db)
    .await
    .map_err(internal)?;

    let kev = sqlx::query!(
        r#"SELECT k.cve_id, k.name FROM kev_entries k
           WHERE k.cve_id IN (SELECT unnest(cve_ids) FROM vulnerabilities WHERE canonical_id = $1)
           ORDER BY k.cve_id"#,
        key
    )
    .fetch_all(&st.db)
    .await
    .map_err(internal)?;

    let scores = sqlx::query!(
        r#"SELECT e.cve_id, e.score, e.percentile, to_char(e.score_date, 'YYYY-MM-DD') AS "date!"
           FROM epss_scores e
           WHERE e.cve_id IN (SELECT unnest(cve_ids) FROM vulnerabilities WHERE canonical_id = $1)
           ORDER BY e.score DESC, e.cve_id"#,
        key
    )
    .fetch_all(&st.db)
    .await
    .map_err(internal)?;

    let matched = sqlx::query!(
        r#"SELECT p.name, f.purls AS "purls!", f.state, f.justification, f.detail,
                  f.suppressed AS "suppressed!"
           FROM findings f JOIN projects p ON p.id = f.project_id
           WHERE f.vuln_key = $1 ORDER BY p.name"#,
        key
    )
    .fetch_all(&st.db)
    .await
    .map_err(internal)?;
    let (suppressed, affected): (Vec<_>, Vec<_>) = matched.into_iter().partition(|m| m.suppressed);

    let summary = advisories.iter().find_map(|a| a.summary.clone());
    let details = advisories.iter().find_map(|a| a.details.clone());
    let worst = advisories.iter().map(|a| a.severity).max().unwrap_or(0);
    let nvd = format!("https://nvd.nist.gov/vuln/detail/{key}");
    let osv_links: Vec<String> = advisories
        .iter()
        .map(|a| format!("https://osv.dev/vulnerability/{}", a.id))
        .collect();
    let references = safe_links(
        advisories
            .iter()
            .flat_map(|a| a.references.iter().map(String::as_str)),
    );

    Ok(page(
        &viewer,
        &key,
        Nav::Vulns,
        html! {
            p.muted { a href="/vulns" { "← Vulnerabilities" } }
            h1 { (key) " " (severity(worst)) " " @if !kev.is_empty() { (kev_badge()) } }
            (flash(dq.done.as_deref()))
            @if let Some(s) = &summary { p { (s) } }
            @for k in &kev {
                p.error {
                    "Actively exploited: " a href={ "/kev/" (k.cve_id) } { (k.cve_id) } " is in the CISA KEV catalog (" (k.name) ")."
                }
            }

            @for e in &scores {
                p {
                    "EPSS " (epss(Some(e.score))) ": probability of exploitation activity in the next 30 days"
                    @if scores.len() > 1 { " for " code { (e.cve_id) } }
                    ", percentile " (format!("{:.1}", f64::from(e.percentile) * 100.0)) " among all scored CVEs "
                    span.muted { "(scores of " (e.date) ")" } "."
                }
            }

            @for (title, rows) in [("Affected projects", &affected), ("Suppressed", &suppressed)] {
                @if title == "Affected projects" || !rows.is_empty() {
                    h2 { (title) " " span.muted { "(" (rows.len()) ")" } }
                }
                @if title == "Suppressed" && !rows.is_empty() {
                    p.muted { "Matched, but their analysis says they are not at risk." }
                }
                @if rows.is_empty() {
                    @if title == "Affected projects" {
                        p.muted { "No project has an unsuppressed finding for this vulnerability." }
                    }
                } @else {
                    div.scroll { table {
                        thead { tr { th { "Project" } th { "Components" } th { "Analysis" } } }
                        tbody { @for a in rows.iter() { tr {
                            td { a href={ "/projects/" (a.name) } { (a.name) } }
                            td { (purl_list(&a.purls)) }
                            td { (analysis_cell(&viewer, &AnalysisCell {
                                project: &a.name,
                                vuln_key: &key,
                                state: a.state.as_deref(),
                                suppressed: a.suppressed,
                                justification: a.justification.as_deref(),
                                detail: a.detail.as_deref(),
                            }, &format!("/vulns/{key}"))) }
                        } } }
                    } }
                }
            }

            h2 { "Advisories" }
            div.scroll { table {
                thead { tr { th { "ID" } th { "Severity" } th { "CVSS" } th { "Published" } th { "Summary" } } }
                tbody { @for (a, osv) in advisories.iter().zip(&osv_links) { tr {
                    td.nowrap { a href=(osv) rel="noreferrer" { code { (a.id) } } @if a.withdrawn { " " span.muted { "(withdrawn)" } } }
                    td { (severity(a.severity)) }
                    td { @if let Some(s) = a.cvss_score { (format!("{s:.1}")) " " } @if let Some(v) = &a.cvss_vector { br; code.muted { (v) } } }
                    td.nowrap.muted { (a.published.as_deref().unwrap_or("—")) }
                    td { (a.summary.as_deref().unwrap_or("")) }
                } } }
            } }

            @if let Some(d) = &details {
                h2 { "Details" }
                p.details { (d) }
            }

            h2 { "References" }
            ul {
                @if key.starts_with("CVE-") { li { a href=(nvd) rel="noreferrer" { "NVD" } } }
                @for r in &references { li { a href=(r) rel="noreferrer" { (r) } } }
            }
        },
    ))
}
