use super::{
    Nav, analysis_badge, card, epss, epss_status, kev_badge, kev_status, not_found, page,
    purl_list, severity, url,
};
use crate::api::{ApiResult, AppState, internal};
use axum::extract::{Path, Query, State};
use maud::{Markup, html};
use serde::Deserialize;
use std::collections::HashMap;

pub async fn index(State(st): State<AppState>) -> ApiResult<Markup> {
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
                p.muted { "No projects yet. Create one with " code { "POST /api/projects" } "." }
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
}

pub async fn project(
    State(st): State<AppState>,
    Path(name): Path<String>,
    Query(query): Query<ProjectQuery>,
) -> ApiResult<Markup> {
    let project_id = sqlx::query_scalar!("SELECT id FROM projects WHERE name = $1", name)
        .fetch_optional(&st.db)
        .await
        .map_err(internal)?
        .ok_or_else(|| not_found("project"))?;
    let show_suppressed = query.suppressed.is_some();

    let findings = sqlx::query!(
        r#"SELECT vuln_key AS "vuln_key!", severity AS "severity!", cvss_score, kev AS "kev!",
                  summary, purls AS "purls!", state, suppressed AS "suppressed!", epss
           FROM findings WHERE project_id = $1 AND ($2 OR NOT suppressed)
           ORDER BY kev DESC, epss DESC NULLS LAST, severity DESC, cvss_score DESC NULLS LAST, vuln_key"#,
        project_id,
        show_suppressed,
    )
    .fetch_all(&st.db)
    .await
    .map_err(internal)?;
    let suppressed_count = sqlx::query_scalar!(
        r#"SELECT count(*) AS "n!" FROM findings WHERE project_id = $1 AND suppressed"#,
        project_id
    )
    .fetch_one(&st.db)
    .await
    .map_err(internal)?;

    let violations = crate::policies::violations(&st.db, Some(project_id))
        .await
        .map_err(internal)?;

    let history = sqlx::query!(
        r#"SELECT to_char(day, 'YYYY-MM-DD') AS "day!", critical, high, medium, low, unknown,
                  kev, suppressed
           FROM project_metrics WHERE project_id = $1 ORDER BY day DESC LIMIT 30"#,
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

    let kev_count = findings.iter().filter(|f| f.kev && !f.suppressed).count();
    let count = |rank: i16| {
        findings
            .iter()
            .filter(|f| !f.suppressed && f.severity == rank)
            .count()
    };

    Ok(page(
        &name,
        Nav::Projects,
        html! {
            p.muted { a href="/" { "← Projects" } }
            h1 { (name) " " @if let Some(r) = releases.first() { span.muted { (r.version) } } }
            @if releases.is_empty() {
                p.muted { "No SBOM received for this project yet." }
            } @else {
                div.cards {
                    (card(kev_count, "Actively exploited", Some("error")))
                    (card(count(4), "Critical", Some("sev4")))
                    (card(count(3), "High", Some("sev3")))
                    (card(count(2), "Medium", Some("sev2")))
                    (card(count(1) + count(0), "Low or unknown", Some("sev1")))
                    (card(suppressed_count, "Suppressed", None))
                    (card(violations.len(), "Policy violations", None))
                }

                h2 { "Vulnerabilities " span.muted { "(" (findings.len()) ")" } }
                p.muted {
                    @if show_suppressed {
                        "Including suppressed findings. " a href={ "/projects/" (name) } { "Hide them" }
                    } @else if suppressed_count > 0 {
                        (suppressed_count) " suppressed findings hidden. "
                        a href=(url(&format!("/projects/{name}"), &[("suppressed", "on".into())])) { "Show them" }
                    }
                }
                @if findings.is_empty() {
                    p.muted { "No known vulnerability in the latest release." }
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
                            td { (analysis_badge(f.state.as_deref())) }
                        } } }
                    } }
                    p.muted {
                        "Record an audit decision with " code { "PUT /api/projects/" (name) "/analyses/{id}" }
                        ", or import a CycloneDX VEX document."
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
                    div.scroll { table {
                        thead { tr {
                            th { "Day" } th.num { "KEV" } th.num { "Critical" } th.num { "High" }
                            th.num { "Medium" } th.num { "Low" } th.num { "Unknown" } th.num { "Suppressed" }
                        } }
                        tbody { @for h in &history { tr {
                            td.nowrap { (h.day) } td.num { (h.kev) } td.num { (h.critical) } td.num { (h.high) }
                            td.num { (h.medium) } td.num { (h.low) } td.num { (h.unknown) } td.num { (h.suppressed) }
                        } } }
                    } }
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
