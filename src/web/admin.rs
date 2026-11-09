use super::{Nav, Viewer, flash, kev_badge, page, severity};
use crate::api::{ApiResult, AppState, internal};
use axum::{
    Extension,
    extract::{Query, State},
};
use maud::{Markup, html};

#[derive(serde::Deserialize)]
pub struct DoneQuery {
    done: Option<String>,
}

/// What each policy kind's value means, for the form.
const KIND_HINTS: [(&str, &str, &str); 4] = [
    ("license", "License", "SPDX license ID, e.g. GPL-3.0-only"),
    ("severity", "Severity", "critical, high, medium or low"),
    ("kev", "KEV", "no value"),
    ("epss", "EPSS", "probability (0.5) or percentage (50%)"),
];

pub async fn policies(
    State(st): State<AppState>,
    Extension(viewer): Extension<Viewer>,
    Query(dq): Query<DoneQuery>,
) -> ApiResult<Markup> {
    let policies = sqlx::query!("SELECT id, name, kind, value FROM policies ORDER BY id")
        .fetch_all(&st.db)
        .await
        .map_err(internal)?;
    let violations = crate::policies::violations(&st.db, None)
        .await
        .map_err(internal)?;

    Ok(page(
        &viewer,
        "Policies",
        Nav::Policies,
        html! {
            h1 { "Policies" }
            p.status.muted {
                "Rules checked against each project's latest release."
                @if !viewer.can_write {
                    " Manage them with " code { "POST /api/policies" } " and "
                    code { "DELETE /api/policies/{id}" } "."
                }
            }
            (flash(dq.done.as_deref()))
            @if policies.is_empty() {
                p.muted { "No policy defined." }
            } @else {
                div.scroll { table {
                    thead { tr {
                        th { "Policy" } th { "Rule" } th.num { "Violations" }
                        @if viewer.can_write { th {} }
                    } }
                    tbody { @for p in &policies { tr {
                        td { (p.name) }
                        td { @match p.kind.as_str() {
                            "license" => { "Component declares license " code { (p.value) } }
                            "severity" => { "Vulnerability of severity " strong { (p.value) } " or higher" }
                            "epss" => { "Vulnerability with an EPSS score of " strong { (p.value.parse::<f32>().map(crate::epss::percent).unwrap_or_else(|_| p.value.clone())) } " or higher" }
                            _ => { "Vulnerability in the KEV catalog" }
                        } }
                        td.num { (violations.iter().filter(|v| v.policy_id == p.id).count()) }
                        @if viewer.can_write {
                            td.num {
                                form.inline method="post" action={ "/policies/" (p.id) "/delete" }
                                    hx-post={ "/policies/" (p.id) "/delete" } hx-target="closest tr"
                                    hx-swap="outerHTML" hx-confirm={ "Delete the policy “" (p.name) "”?" } {
                                    button.danger type="submit" { "Delete" }
                                }
                            }
                        }
                    } } }
                } }
            }
            @if viewer.can_write {
                div.panel {
                    h3 { "New policy" }
                    form.stack method="post" action="/policies" {
                        input type="text" name="name" required placeholder="Name, e.g. No AGPL" aria-label="Policy name";
                        select name="kind" aria-label="Kind" {
                            @for (kind, label, _) in KIND_HINTS { option value=(kind) { (label) } }
                        }
                        input type="text" name="value" placeholder="Value" aria-label="Value";
                        button.primary type="submit" { "Create" }
                    }
                    ul.muted { @for (_, label, hint) in KIND_HINTS { li { strong { (label) } ": " (hint) } } }
                }
            }
            @if !violations.is_empty() {
                h2 { "Violations " span.muted { "(" (violations.len()) ")" } }
                div.scroll { table {
                    thead { tr { th { "Project" } th { "Policy" } th { "Subject" } th { "Detail" } } }
                    tbody { @for v in &violations { tr {
                        td { a href={ "/projects/" (v.project) } { (v.project) } }
                        td { (v.policy) }
                        td { @if v.kind == "license" { code { (v.subject) } } @else {
                            a href={ "/vulns/" (v.subject) } { code { (v.subject) } } } }
                        td { (v.detail) }
                    } } }
                } }
            }
        },
    ))
}

pub async fn alerts(
    State(st): State<AppState>,
    Extension(viewer): Extension<Viewer>,
) -> ApiResult<Markup> {
    let alerts = sqlx::query!(
        r#"SELECT to_char(a.sent_at, 'YYYY-MM-DD HH24:MI') AS "sent_at!", p.name, a.vuln_key,
                  a.rule, a.severity, a.kev
           FROM alerts a JOIN projects p ON p.id = a.project_id
           ORDER BY a.sent_at DESC, p.name, a.vuln_key LIMIT 500"#
    )
    .fetch_all(&st.db)
    .await
    .map_err(internal)?;
    let channel = st.config.google_chat_webhook.is_some();

    Ok(page(
        &viewer,
        "Alerts",
        Nav::Alerts,
        html! {
            h1 { "Alerts" }
            p.status.muted {
                @if channel { "Alerts are posted to Google Chat. " }
                @else { span.error { "No notification channel is configured: alerts are not sent. " } }
                "Rules: "
                @if st.config.alert_kev { "vulnerabilities in the KEV catalog" } @else { "KEV alerts off" }
                @if let Some(s) = st.config.alert_min_severity { ", severity " (s.label().to_lowercase()) " or higher" }
                @if let Some(e) = st.config.alert_min_epss { ", EPSS score of " (crate::epss::percent(e)) " or higher" }
                ". Each project and vulnerability is notified once."
            }
            @if alerts.is_empty() {
                p.muted { "No alert sent yet." }
            } @else {
                div.scroll { table {
                    thead { tr { th { "Sent (UTC)" } th { "Project" } th { "Vulnerability" } th { "Severity" } th { "Rule" } } }
                    tbody { @for a in &alerts { tr {
                        td.nowrap.muted { (a.sent_at) }
                        td { a href={ "/projects/" (a.name) } { (a.name) } }
                        td.nowrap { a href={ "/vulns/" (a.vuln_key) } { code { (a.vuln_key) } } @if a.kev { " " (kev_badge()) } }
                        td { (severity(a.severity)) }
                        td { @match a.rule.as_str() { "kev" => "KEV", "epss" => "EPSS", _ => "Severity" } }
                    } } }
                } }
            }
        },
    ))
}
