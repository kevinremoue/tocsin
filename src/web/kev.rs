use super::{
    Audit, Nav, PAGE_SIZE, Viewer, audit_cell, kev_status, like_pattern, not_found, page, pager,
    purl_list, safe_links, search_term, url,
};
use crate::api::{ApiResult, AppState, internal};
use axum::{
    Extension,
    extract::{Path, Query, State},
};
use maud::{Markup, html};
use serde::Deserialize;

#[derive(Deserialize)]
pub struct KevQuery {
    /// Searched in the CVE ID, vendor, product and name
    q: Option<String>,
    /// Present: only entries used in ransomware campaigns
    ransomware: Option<String>,
    /// Present: only entries affecting at least one project
    affecting: Option<String>,
    page: Option<i64>,
}

pub async fn list(
    State(st): State<AppState>,
    Extension(viewer): Extension<Viewer>,
    Query(query): Query<KevQuery>,
) -> ApiResult<Markup> {
    let q = search_term(&query.q);
    let pattern = like_pattern(q);
    let ransomware = query.ransomware.is_some();
    let affecting = query.affecting.is_some();
    let page_no = query.page.unwrap_or(1).max(1);

    // Projects whose latest release contains an advisory for the CVE (audit decisions aside)
    let entries = sqlx::query!(
        r#"WITH affected AS (
               SELECT k.cve_id, count(DISTINCT ls.project_id) AS projects
               FROM kev_entries k
               JOIN vulnerabilities v ON k.cve_id = ANY (v.cve_ids) AND NOT v.withdrawn
               JOIN component_vulns cv ON cv.vuln_id = v.id
               JOIN components c ON c.purl = cv.purl
               JOIN latest_sboms ls ON ls.id = c.sbom_id
               GROUP BY k.cve_id)
           SELECT k.cve_id, k.vendor_project, k.product, k.name, k.known_ransomware,
                  to_char(k.date_added, 'YYYY-MM-DD') AS "date_added!",
                  COALESCE(a.projects, 0) AS "projects!",
                  count(*) OVER () AS "total!"
           FROM kev_entries k LEFT JOIN affected a ON a.cve_id = k.cve_id
           WHERE ($1::text IS NULL OR k.cve_id ILIKE $1 OR k.vendor_project ILIKE $1
                  OR k.product ILIKE $1 OR k.name ILIKE $1)
             AND (NOT $2 OR k.known_ransomware)
             AND (NOT $3 OR a.projects > 0)
           ORDER BY k.date_added DESC, k.cve_id DESC
           LIMIT $4 OFFSET $5"#,
        pattern,
        ransomware,
        affecting,
        PAGE_SIZE,
        (page_no - 1) * PAGE_SIZE,
    )
    .fetch_all(&st.db)
    .await
    .map_err(internal)?;

    let total = entries.first().map(|e| e.total).unwrap_or(0);
    let kev_status = kev_status(&st.db, false).await?;
    let first = (page_no - 1) * PAGE_SIZE + 1;
    let last = (page_no - 1) * PAGE_SIZE + entries.len() as i64;
    let filtered = q.is_some() || ransomware || affecting;
    let on = |b: bool| if b { "on".to_owned() } else { String::new() };
    let link = |p: i64| {
        url(
            "/kev",
            &[
                ("q", q.unwrap_or_default().to_owned()),
                ("ransomware", on(ransomware)),
                ("affecting", on(affecting)),
                ("page", if p > 1 { p.to_string() } else { String::new() }),
            ],
        )
    };

    Ok(page(
        &viewer,
        "KEV catalog",
        Nav::Kev,
        html! {
            h1 { "KEV catalog" }
            (kev_status)
            form.filters method="get" action="/kev" {
                input type="search" name="q" value=(q.unwrap_or_default())
                    placeholder="CVE, vendor, product or name" aria-label="Search";
                label { input type="checkbox" name="ransomware" checked[ransomware]; " Used in ransomware" }
                label { input type="checkbox" name="affecting" checked[affecting]; " Affecting my projects" }
                button type="submit" { "Filter" }
                @if filtered { a href="/kev" { "Clear" } }
            }
            @if entries.is_empty() {
                p.muted {
                    @if filtered { "No entry matches these filters." } @else { "The catalog is empty." }
                }
            } @else {
                p.muted { "Showing " (first) "–" (last) " of " (total) }
                div.scroll { table {
                    thead { tr {
                        th { "CVE" } th { "Vendor" } th { "Product" } th { "Vulnerability" }
                        th { "Added" } th { "Ransomware" } th.num { "Projects" }
                    } }
                    tbody { @for e in &entries { tr {
                        td.nowrap { a href={ "/kev/" (e.cve_id) } { code { (e.cve_id) } } }
                        td { (e.vendor_project) }
                        td { (e.product) }
                        td { (e.name) }
                        td.nowrap.muted { (e.date_added) }
                        td { @if e.known_ransomware { span.badge.kev { "Known" } } }
                        td.num { @if e.projects > 0 { strong.error { (e.projects) } } @else { span.muted { "0" } } }
                    } } }
                } }
                (pager(page_no, last, total, link))
            }
        },
    ))
}

/// http(s) URLs found in the free-text `notes` field of a KEV entry.
fn note_links(notes: &str) -> Vec<&str> {
    safe_links(notes.split(|c: char| c.is_whitespace() || c == ';'))
}

pub async fn entry(
    State(st): State<AppState>,
    Extension(viewer): Extension<Viewer>,
    Path(cve): Path<String>,
) -> ApiResult<Markup> {
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
    .ok_or_else(|| not_found("CVE in the KEV catalog"))?;

    let affected = sqlx::query!(
        r#"SELECT p.name, f.vuln_key AS "vuln_key!", f.purls AS "purls!", f.state,
                  f.justification, f.detail
           FROM findings f JOIN projects p ON p.id = f.project_id
           WHERE f.vuln_ids && ARRAY(SELECT id FROM vulnerabilities WHERE $1 = ANY (cve_ids))
           ORDER BY f.suppressed, p.name"#,
        cve
    )
    .fetch_all(&st.db)
    .await
    .map_err(internal)?;

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

    Ok(page(
        &viewer,
        &e.cve_id,
        Nav::Kev,
        html! {
            p.muted { a href="/kev" { "← KEV catalog" } }
            h1 { (e.cve_id) " " @if e.known_ransomware { span.badge.kev { "Used in ransomware" } } }
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

            h2 { "Affected projects " span.muted { "(" (affected.len()) ")" } }
            @if affected.is_empty() {
                p.muted { "No project's latest release contains a component affected by this CVE." }
            } @else {
                div.scroll { table {
                    thead { tr { th { "Project" } th { "Vulnerability" } th { "Components" } th { "Analysis" } } }
                    tbody { @for a in &affected { tr {
                        td { a href={ "/projects/" (a.name) } { (a.name) } }
                        td.nowrap { a href={ "/vulns/" (a.vuln_key) } { code { (a.vuln_key) } } }
                        td { (purl_list(&a.purls)) }
                        td { (audit_cell(&viewer, &Audit {
                            project: &a.name,
                            vuln_key: &a.vuln_key,
                            state: a.state.as_deref(),
                            justification: a.justification.as_deref(),
                            detail: a.detail.as_deref(),
                        }, &format!("/kev/{}", e.cve_id))) }
                    } } }
                } }
            }
        },
    ))
}
