use super::{
    Audit, Nav, Viewer, audit_cell, card, chart, epss, epss_status, flash, kev_badge, kev_status,
    like_pattern, not_found, page, purl_list, search_term, severity, url,
};
use crate::api::{ApiResult, AppState, internal};
use crate::vulns::Severity;
use axum::{
    Extension, Json,
    extract::{Path, Query, State},
    http::header,
    response::IntoResponse,
};
use maud::{Markup, html};
use serde::Deserialize;
use std::collections::HashMap;

/// Jobs that can be run from the dashboard, with what they do.
const JOBS: [(&str, &str); 3] = [
    ("kev-sync", "Sync the CISA KEV catalog"),
    ("epss-sync", "Sync EPSS scores"),
    ("refresh", "Re-match every latest release against OSV.dev"),
];

pub async fn index(
    State(st): State<AppState>,
    Extension(viewer): Extension<Viewer>,
) -> ApiResult<Markup> {
    let projects = sqlx::query!(
        r#"SELECT p.name,
                  ls.version AS "version?",
                  to_char(ls.created_at, 'YYYY-MM-DD HH24:MI') AS "released_at?",
                  (SELECT count(*) FROM components c WHERE c.sbom_id = ls.id) AS "components!",
                  count(f.vuln_key) FILTER (WHERE NOT f.suppressed AND f.kev) AS "kev!",
                  count(f.vuln_key) FILTER (WHERE NOT f.suppressed AND f.severity = 4) AS "critical!",
                  count(f.vuln_key) FILTER (WHERE NOT f.suppressed AND f.severity = 3) AS "high!",
                  count(f.vuln_key) FILTER (WHERE NOT f.suppressed AND f.severity = 2) AS "medium!",
                  count(f.vuln_key) FILTER (WHERE NOT f.suppressed AND f.severity <= 1) AS "low!"
           FROM projects p
           LEFT JOIN latest_sboms ls ON ls.project_id = p.id
           LEFT JOIN findings f ON f.project_id = p.id
           GROUP BY p.name, ls.id, ls.version, ls.created_at
           ORDER BY p.name"#
    )
    .fetch_all(&st.db)
    .await
    .map_err(internal)?;

    let mut violations: HashMap<String, usize> = HashMap::new();
    for v in crate::policies::violations(&st.db, None)
        .await
        .map_err(internal)?
    {
        *violations.entry(v.project).or_default() += 1;
    }
    let total = |f: fn(&_) -> i64| -> i64 { projects.iter().map(f).sum() };
    let kev_status = kev_status(&st.db, true).await?;
    let epss_status = epss_status(&st.db).await?;

    Ok(page(
        &viewer,
        "Projects",
        Nav::Projects,
        html! {
            h1 { "Projects" }
            (kev_status)
            (epss_status)
            div.cards {
                (card(projects.len(), "Projects", None))
                (card(total(|p| p.kev), "Actively exploited", Some("error")))
                (card(total(|p| p.critical), "Critical", Some("sev4")))
                (card(total(|p| p.high), "High", Some("sev3")))
                (card(total(|p| p.medium), "Medium", Some("sev2")))
                (card(total(|p| p.low), "Low or unknown", Some("sev1")))
                (card(violations.values().sum::<usize>(), "Policy violations", None))
            }
            @if projects.is_empty() {
                p.muted {
                    "No projects yet."
                    @if !viewer.can_write { " Create one with " code { "POST /api/projects" } "." }
                }
            } @else {
                div.scroll { table {
                    thead { tr {
                        th { "Project" } th { "Latest release" } th { "Released (UTC)" }
                        th.num { "Components" } th.num { "KEV" } th.num { "Critical" } th.num { "High" }
                        th.num { "Medium" } th.num { "Low" } th.num { "Violations" }
                    } }
                    tbody { @for p in &projects { tr {
                        td { a href={ "/projects/" (p.name) } { (p.name) } }
                        td { (p.version.as_deref().unwrap_or("—")) }
                        td.nowrap.muted { (p.released_at.as_deref().unwrap_or("—")) }
                        td.num { (p.components) }
                        td.num { @if p.kev > 0 { span.error { strong { (p.kev) } } } @else { "0" } }
                        (count_cell(p.critical, "sev4"))
                        (count_cell(p.high, "sev3"))
                        (count_cell(p.medium, "sev2"))
                        (count_cell(p.low, "sev1"))
                        td.num { (violations.get(&p.name).copied().unwrap_or(0)) }
                    } } }
                } }
            }

            @if viewer.can_write {
                div.panel {
                    h3 { "New project" }
                    form.stack method="post" action="/projects" {
                        input type="text" name="name" required maxlength="100" pattern="[A-Za-z0-9._\\-]+"
                            placeholder="my-service" aria-label="Project name"
                            title="1-100 characters: letters, digits, dot, dash, underscore";
                        button.primary type="submit" { "Create" }
                        span.muted { "Its token, for CI, is shown once." }
                    }
                }
                div.panel {
                    h3 { "Jobs" }
                    p.muted { "They also run on their schedule. Run one now, for example after a deployment." }
                    table { tbody { @for (job, what) in JOBS { tr {
                        td.nowrap { code { (job) } }
                        td { (what) }
                        td.nowrap {
                            form.inline method="post" action={ "/jobs/" (job) } hx-post={ "/jobs/" (job) }
                                hx-target="next .job-result" hx-disabled-elt="find button" {
                                button type="submit" { "Run now" }
                                " " span.htmx-indicator.muted { "running…" }
                            }
                            " " span.job-result {}
                        }
                    } } } }
                }
            }
        },
    ))
}

/// A count, colored by severity unless it is zero.
fn count_cell(n: i64, class: &str) -> Markup {
    html! { td class={ "num " @if n > 0 { (class) } @else { "muted" } } { (n) } }
}

#[derive(Deserialize)]
pub struct ProjectQuery {
    /// Checkbox-style flag: present to include suppressed findings
    suppressed: Option<String>,
    q: Option<String>,
    /// Present: only KEV findings
    kev: Option<String>,
    /// Minimum severity: critical, high, medium or low
    severity: Option<String>,
    done: Option<String>,
}

pub async fn project(
    State(st): State<AppState>,
    Extension(viewer): Extension<Viewer>,
    Path(name): Path<String>,
    Query(query): Query<ProjectQuery>,
) -> ApiResult<Markup> {
    let project_id = sqlx::query_scalar!("SELECT id FROM projects WHERE name = $1", name)
        .fetch_optional(&st.db)
        .await
        .map_err(internal)?
        .ok_or_else(|| not_found("project"))?;
    let show_suppressed = query.suppressed.is_some();
    let q = search_term(&query.q);
    let kev_only = query.kev.is_some();
    let min_severity = query
        .severity
        .as_deref()
        .and_then(Severity::parse)
        .filter(|s| *s != Severity::Unknown);
    let filtered = q.is_some() || kev_only || min_severity.is_some();

    let findings = sqlx::query!(
        r#"SELECT vuln_key AS "vuln_key!", severity AS "severity!", cvss_score, kev AS "kev!",
                  summary, purls AS "purls!", state, justification, detail,
                  suppressed AS "suppressed!", epss
           FROM findings
           WHERE project_id = $1 AND ($2 OR NOT suppressed)
             AND ($3::text IS NULL OR vuln_key ILIKE $3 OR summary ILIKE $3
                  OR EXISTS (SELECT 1 FROM unnest(purls) u WHERE u ILIKE $3))
             AND (NOT $4 OR kev) AND severity >= $5
           ORDER BY kev DESC, epss DESC NULLS LAST, severity DESC, cvss_score DESC NULLS LAST, vuln_key"#,
        project_id,
        show_suppressed,
        like_pattern(q),
        kev_only,
        min_severity.map(Severity::rank).unwrap_or(0),
    )
    .fetch_all(&st.db)
    .await
    .map_err(internal)?;
    let counts = sqlx::query!(
        r#"SELECT count(*) FILTER (WHERE NOT suppressed AND kev) AS "kev!",
                  count(*) FILTER (WHERE NOT suppressed AND severity = 4) AS "critical!",
                  count(*) FILTER (WHERE NOT suppressed AND severity = 3) AS "high!",
                  count(*) FILTER (WHERE NOT suppressed AND severity = 2) AS "medium!",
                  count(*) FILTER (WHERE NOT suppressed AND severity <= 1) AS "low!",
                  count(*) FILTER (WHERE suppressed) AS "suppressed!"
           FROM findings WHERE project_id = $1"#,
        project_id
    )
    .fetch_one(&st.db)
    .await
    .map_err(internal)?;

    let violations = crate::policies::violations(&st.db, Some(project_id))
        .await
        .map_err(internal)?;

    let history = sqlx::query_as!(
        chart::Day,
        r#"SELECT to_char(day, 'YYYY-MM-DD') AS "day!", critical, high, medium, low, unknown, kev,
                  suppressed
           FROM (SELECT * FROM project_metrics WHERE project_id = $1 ORDER BY day DESC LIMIT 30) m
           ORDER BY day"#,
        project_id
    )
    .fetch_all(&st.db)
    .await
    .map_err(internal)?;
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

    let components = sqlx::query!(
        r#"SELECT c.purl, c.licenses,
                  (SELECT count(*) FROM component_vulns cv
                   JOIN vulnerabilities v ON v.id = cv.vuln_id AND NOT v.withdrawn
                   WHERE cv.purl = c.purl) AS "advisories!"
           FROM latest_sboms ls JOIN components c ON c.sbom_id = ls.id
           WHERE ls.project_id = $1 ORDER BY c.purl"#,
        project_id
    )
    .fetch_all(&st.db)
    .await
    .map_err(internal)?;

    let here = format!("/projects/{name}");
    // This page with its current filters, to come back to after an audit
    let return_to = url(
        &here,
        &[
            (
                "suppressed",
                query
                    .suppressed
                    .clone()
                    .map(|_| "on".into())
                    .unwrap_or_default(),
            ),
            ("q", q.unwrap_or_default().to_owned()),
            ("kev", if kev_only { "on".into() } else { String::new() }),
            (
                "severity",
                min_severity
                    .map(|s| s.label().to_lowercase())
                    .unwrap_or_default(),
            ),
        ],
    );

    Ok(page(
        &viewer,
        &name,
        Nav::Projects,
        html! {
            p.muted { a href="/" { "← Projects" } }
            h1 { (name) " " @if let Some(r) = releases.first() { span.muted { (r.version) } } }
            (flash(query.done.as_deref()))
            @if releases.is_empty() {
                p.muted { "No SBOM received for this project yet." }
            } @else {
                div.cards {
                    (card(counts.kev, "Actively exploited", Some("error")))
                    (card(counts.critical, "Critical", Some("sev4")))
                    (card(counts.high, "High", Some("sev3")))
                    (card(counts.medium, "Medium", Some("sev2")))
                    (card(counts.low, "Low or unknown", Some("sev1")))
                    (card(counts.suppressed, "Suppressed", None))
                    (card(violations.len(), "Policy violations", None))
                }

                h2 { "Vulnerabilities " span.muted { "(" (findings.len()) ")" } }
                form.filters method="get" action=(here) {
                    input type="search" name="q" value=(q.unwrap_or_default())
                        placeholder="CVE, summary or package" aria-label="Search";
                    select name="severity" aria-label="Minimum severity" {
                        option value="" { "Any severity" }
                        @for s in [Severity::Critical, Severity::High, Severity::Medium, Severity::Low] {
                            option value=(s.label().to_lowercase()) selected[min_severity == Some(s)] {
                                (s.label()) " or higher"
                            }
                        }
                    }
                    label { input type="checkbox" name="kev" checked[kev_only]; " KEV only" }
                    label { input type="checkbox" name="suppressed" checked[show_suppressed]; " Include suppressed" }
                    button type="submit" { "Filter" }
                    @if filtered || show_suppressed { a href=(here) { "Clear" } }
                }
                @if !show_suppressed && counts.suppressed > 0 {
                    p.muted { (counts.suppressed) " suppressed findings hidden." }
                }
                @if findings.is_empty() {
                    p.muted {
                        @if filtered { "No vulnerability matches these filters." }
                        @else { "No known vulnerability in the latest release." }
                    }
                } @else {
                    div.scroll { table {
                        thead { tr {
                            th { "Vulnerability" } th { "Severity" } th.num { "CVSS" } th.num { "EPSS" }
                            th { "Summary" } th { "Components" } th { "Analysis" }
                        } }
                        tbody { @for f in &findings { tr {
                            td.nowrap {
                                a href={ "/vulns/" (f.vuln_key) } { code { (f.vuln_key) } }
                                @if f.kev { " " (kev_badge()) }
                            }
                            td { (severity(f.severity)) }
                            td.num { @if let Some(s) = f.cvss_score { (format!("{s:.1}")) } }
                            td.num { (epss(f.epss)) }
                            td { (f.summary.as_deref().unwrap_or("")) }
                            td { (purl_list(&f.purls)) }
                            td { (audit_cell(&viewer, &Audit {
                                project: &name,
                                vuln_key: &f.vuln_key,
                                state: f.state.as_deref(),
                                justification: f.justification.as_deref(),
                                detail: f.detail.as_deref(),
                            }, &return_to)) }
                        } } }
                    } }
                    @if !viewer.can_write {
                        p.muted {
                            "Record an audit decision with " code { "PUT /api/projects/" (name) "/analyses/{id}" }
                            ", or import a CycloneDX VEX document."
                        }
                    }
                }

                @if !violations.is_empty() {
                    h2 { "Policy violations " span.muted { "(" (violations.len()) ")" } }
                    div.scroll { table {
                        thead { tr { th { "Policy" } th { "Subject" } th { "Detail" } } }
                        tbody { @for v in &violations { tr {
                            td { (v.policy) }
                            td { @if v.kind == "license" { code { (v.subject) } } @else {
                                a href={ "/vulns/" (v.subject) } { code { (v.subject) } } } }
                            td { (v.detail) }
                        } } }
                    } }
                }

                @if !history.is_empty() {
                    h2 { "History" }
                    (chart::history(&history))
                    details {
                        summary.muted { "Daily counts" }
                        div.scroll { table {
                            thead { tr {
                                th { "Day" } th.num { "KEV" } th.num { "Critical" } th.num { "High" }
                                th.num { "Medium" } th.num { "Low" } th.num { "Unknown" } th.num { "Suppressed" }
                            } }
                            tbody { @for h in history.iter().rev() { tr {
                                td.nowrap { (h.day) } td.num { (h.kev) } td.num { (h.critical) } td.num { (h.high) }
                                td.num { (h.medium) } td.num { (h.low) } td.num { (h.unknown) }
                                td.num { (h.suppressed) }
                            } } }
                        } }
                    }
                }
            }

            @if viewer.can_write {
                div.panel {
                    h3 { "Upload a release" }
                    p.muted { "A CycloneDX JSON SBOM, gzipped or not. Uploading an existing version replaces it." }
                    form.stack method="post" action={ (here) "/sboms" } enctype="multipart/form-data" {
                        input type="file" name="file" required accept=".json,.gz,application/json,application/gzip"
                            aria-label="SBOM file";
                        input type="text" name="version" placeholder="Version (default: from the SBOM)"
                            aria-label="Version";
                        button.primary type="submit" { "Upload" }
                    }
                }
            }
            @if !releases.is_empty() {
                div.panel {
                    h3 { "VEX" }
                    p {
                        a.button href={ (here) "/vex.json" } download { "Download VEX" }
                        " " span.muted { "The findings and their audit decisions, as CycloneDX 1.6." }
                    }
                    @if viewer.can_write {
                        form.stack method="post" action={ (here) "/vex" } enctype="multipart/form-data" {
                            input type="file" name="file" required accept=".json,.gz,application/json,application/gzip"
                                aria-label="VEX file";
                            button type="submit" { "Import VEX" }
                            span.muted { "Imports the audit decisions of a CycloneDX VEX document." }
                        }
                    }
                }

                h2 { "Releases" }
                div.scroll { table {
                    thead { tr { th { "Version" } th { "Released (UTC)" } th.num { "Components" } } }
                    tbody { @for r in &releases { tr {
                        td { (r.version) }
                        td.nowrap.muted { (r.released_at) }
                        td.num { (r.components) }
                    } } }
                } }

                h2 { "Components of the latest release " span.muted { "(" (components.len()) ")" } }
                div.scroll { table {
                    thead { tr { th { "Package URL" } th { "Licenses" } th.num { "Advisories" } } }
                    tbody { @for c in &components { tr {
                        td { code { (c.purl) } }
                        td { (c.licenses.join(", ")) }
                        td.num { @if c.advisories > 0 { strong { (c.advisories) } } @else { span.muted { "0" } } }
                    } } }
                } }
            }
        },
    ))
}

/// The project's VEX document, as a download.
pub async fn vex_download(
    State(st): State<AppState>,
    Path(name): Path<String>,
) -> ApiResult<impl IntoResponse> {
    let project_id = sqlx::query_scalar!("SELECT id FROM projects WHERE name = $1", name)
        .fetch_optional(&st.db)
        .await
        .map_err(internal)?
        .ok_or_else(|| not_found("project"))?;
    let doc = crate::vex::export(&st.db, project_id, &name)
        .await
        .map_err(internal)?;
    // The name is [A-Za-z0-9._-]: safe in the header
    let disposition = format!("attachment; filename=\"{name}-vex.json\"");
    Ok(([(header::CONTENT_DISPOSITION, disposition)], Json(doc)))
}
