//! Coverage describes evidence limits, independently of request processing status.
use serde_json::{Value, json};
use sqlx::PgPool;

pub async fn project(db: &PgPool, project: i64) -> sqlx::Result<Value> {
    let release: Option<(String, Value)> = sqlx::query_as(
        "SELECT ls.version, s.document FROM latest_sboms ls JOIN sboms s ON s.id=ls.id WHERE ls.project_id = $1",
    ).bind(project).fetch_optional(db).await?;
    let Some((version, document)) = release else {
        return Ok(json!(null));
    };
    let scans: Vec<(String, Option<String>, bool)> = sqlx::query_as(
        "SELECT c.purl, s.scanned_at::text, COALESCE(s.scanned_at >= a.attempted_at, s.scanned_at IS NOT NULL) FROM latest_sboms ls JOIN components c ON c.sbom_id=ls.id LEFT JOIN purl_scans s ON s.purl=c.purl LEFT JOIN matching_attempts a ON a.purl=c.purl WHERE ls.project_id=$1",
    ).bind(project).fetch_all(db).await?;
    let mut total = 0;
    let mut usable = 0;
    let mut evaluated = 0;
    let mut license_gaps = 0;
    let mut gaps = Vec::new();
    fn visit<'a>(doc: &'a Value, out: &mut Vec<&'a Value>) {
        for c in doc["components"].as_array().into_iter().flatten() {
            out.push(c);
            visit(c, out);
        }
    }
    let mut components = Vec::new();
    visit(&document, &mut components);
    for c in components {
        total += 1;
        if !c["licenses"].as_array().is_some_and(|choices| {
            choices.iter().any(|choice| {
                // Same fallback order and trimming as intake's license extraction.
                choice["license"]["id"]
                    .as_str()
                    .or_else(|| choice["license"]["name"].as_str())
                    .or_else(|| choice["expression"].as_str())
                    .is_some_and(|value| !value.trim().is_empty())
            })
        }) {
            license_gaps += 1;
        }
        let purl = c["purl"].as_str();
        let reason = match purl {
            None => Some("missing_identifier"),
            Some(p) if !crate::vulns::is_matchable(p) => Some("unusable_or_unversioned_identifier"),
            Some(p) => {
                usable += 1;
                if scans.iter().any(|(s, _, complete)| s == p && *complete) {
                    evaluated += 1;
                    None
                } else {
                    Some("not_successfully_evaluated")
                }
            }
        };
        if let Some(reason) = reason {
            gaps.push(json!({"purl": purl, "reason": reason}));
        }
    }
    let complete: bool = sqlx::query_scalar("SELECT matching_complete($1)")
        .bind(project)
        .fetch_one(db)
        .await?;
    let last_complete: Option<Value> = sqlx::query_scalar(
        "SELECT to_jsonb(e) - 'project_id' FROM project_evaluations e WHERE project_id=$1",
    )
    .bind(project)
    .fetch_optional(db)
    .await?;
    Ok(json!({
        "complete": complete, "last_complete_evaluation": last_complete,
        "release": version, "total_supplied": total, "usable_versioned_identifiers": usable,
        "evaluated": evaluated, "gaps": gaps, "license_gaps": license_gaps,
        "identifier_evaluations": scans.into_iter().map(|(purl, at, complete)| json!({"purl":purl,"last_successful_evaluation":at,"current":complete})).collect::<Vec<_>>(),
        "qualification": "Known matches only; coverage is not a safety assessment."
    }))
}
