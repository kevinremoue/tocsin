//! Analysis states and CycloneDX VEX export/import.
use serde_json::{Value, json};
use sqlx::PgPool;

/// CycloneDX `analysis.state` values Tocsin stores (`resolved_with_pedigree` maps to `resolved`).
pub const STATES: [&str; 5] = [
    "in_triage",
    "exploitable",
    "not_affected",
    "false_positive",
    "resolved",
];

pub const JUSTIFICATIONS: [&str; 9] = [
    "code_not_present",
    "code_not_reachable",
    "requires_configuration",
    "requires_dependency",
    "requires_environment",
    "protected_by_compiler",
    "protected_at_runtime",
    "protected_at_perimeter",
    "protected_by_mitigating_control",
];

pub fn state_label(state: &str) -> &'static str {
    match state {
        "in_triage" => "In triage",
        "exploitable" => "Exploitable",
        "not_affected" => "Not affected",
        "false_positive" => "False positive",
        "resolved" => "Resolved",
        _ => "Not audited",
    }
}

pub struct Analysis {
    pub state: String,
    pub justification: Option<String>,
    pub detail: Option<String>,
}

impl Analysis {
    pub fn validate(
        state: &str,
        justification: Option<&str>,
        detail: Option<&str>,
    ) -> Result<Self, String> {
        let state = if state == "resolved_with_pedigree" {
            "resolved"
        } else {
            state
        };
        if !STATES.contains(&state) {
            return Err(format!(
                "invalid state {state:?}, expected one of {STATES:?}"
            ));
        }
        let justification = justification.filter(|j| !j.is_empty());
        if let Some(j) = justification
            && !JUSTIFICATIONS.contains(&j)
        {
            return Err(format!(
                "invalid justification {j:?}, expected one of {JUSTIFICATIONS:?}"
            ));
        }
        Ok(Self {
            state: state.to_owned(),
            justification: justification.map(String::from),
            detail: detail.filter(|d| !d.trim().is_empty()).map(String::from),
        })
    }
}

/// Records (`Some`) or removes (`None`) the analysis of a vulnerability, named by its current
/// name, any advisory ID or any of its CVEs, then records today's metrics. Returns the canonical ID.
pub async fn record(
    db: &PgPool,
    project_id: i64,
    vuln: &str,
    analysis: Option<&Analysis>,
) -> sqlx::Result<String> {
    // An advisory ID (GHSA-…) is recorded against the vulnerability it describes
    let key = crate::identity::resolve(db, vuln)
        .await?
        .unwrap_or_else(|| vuln.to_owned());
    match analysis {
        Some(a) => upsert(db, project_id, &key, a).await?,
        None => {
            sqlx::query!(
                "DELETE FROM analyses WHERE project_id = $1 AND vuln_key = $2",
                project_id,
                key
            )
            .execute(db)
            .await?;
        }
    }
    crate::jobs::snapshot_metrics(db, Some(project_id)).await?;
    Ok(key)
}

pub async fn upsert(
    db: &PgPool,
    project_id: i64,
    vuln_key: &str,
    a: &Analysis,
) -> sqlx::Result<()> {
    sqlx::query!(
        "INSERT INTO analyses (project_id, vuln_key, state, justification, detail)
         VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (project_id, vuln_key) DO UPDATE SET state = EXCLUDED.state,
             justification = EXCLUDED.justification, detail = EXCLUDED.detail, updated_at = now()",
        project_id,
        vuln_key,
        a.state,
        a.justification,
        a.detail,
    )
    .execute(db)
    .await?;
    sqlx::query("UPDATE analyses SET evidence = finding_evidence(project_id, vuln_key) WHERE project_id = $1 AND vuln_key = $2")
        .bind(project_id).bind(vuln_key).execute(db).await?;
    Ok(())
}

/// The project's findings as a CycloneDX 1.6 VEX document.
pub async fn export(db: &PgPool, project_id: i64, project: &str) -> sqlx::Result<Value> {
    let meta = sqlx::query!(
        r#"SELECT (SELECT version FROM latest_sboms WHERE project_id = $1) AS version,
                  to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS "now!""#,
        project_id
    )
    .fetch_one(db)
    .await?;
    let findings = sqlx::query!(
        r#"SELECT vuln_key AS "vuln_key!", severity AS "severity!", purls AS "purls!",
                  summary, state, justification, detail, suppressed AS "suppressed!",
                  finding_evidence(project_id, vuln_key) AS evidence
           FROM findings WHERE project_id = $1 ORDER BY vuln_key"#,
        project_id
    )
    .fetch_all(db)
    .await?;

    let vulnerabilities: Vec<Value> = findings
        .into_iter()
        .map(|f| {
            let mut v = json!({
                "id": f.vuln_key,
                "source": if f.vuln_key.starts_with("CVE-") {
                    json!({ "name": "NVD", "url": format!("https://nvd.nist.gov/vuln/detail/{}", f.vuln_key) })
                } else {
                    json!({ "name": "OSV", "url": format!("https://osv.dev/vulnerability/{}", f.vuln_key) })
                },
                "ratings": [{ "severity": crate::vulns::Severity::from_rank(f.severity).label().to_lowercase() }],
                "affects": f.purls.iter().map(|p| json!({ "ref": p })).collect::<Vec<_>>(),
            });
            if let Some(summary) = f.summary {
                v["description"] = json!(summary);
            }
            v["properties"] = json!([{ "name": "tocsin:evidence", "value": f.evidence.map(|e| e.to_string()) }]);
            if let Some(state) = f.state {
                let state = if matches!(state.as_str(), "not_affected" | "false_positive" | "resolved") && !f.suppressed { "in_triage" } else { &state };
                let mut analysis = json!({ "state": state });
                if let Some(j) = f.justification {
                    analysis["justification"] = json!(j);
                }
                if let Some(d) = f.detail {
                    analysis["detail"] = json!(d);
                }
                v["analysis"] = analysis;
            }
            v
        })
        .collect();

    let mut component = json!({ "type": "application", "name": project, "bom-ref": project });
    if let Some(version) = meta.version {
        component["version"] = json!(version);
    }
    Ok(json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "timestamp": meta.now,
            "tools": { "components": [{ "type": "application", "name": "tocsin", "version": env!("CARGO_PKG_VERSION") }] },
            "component": component,
        },
        "vulnerabilities": vulnerabilities,
    }))
}

#[derive(Debug, PartialEq, serde::Serialize)]
pub struct ImportStats {
    pub imported: usize,
    pub skipped: Vec<String>,
}

/// Applies the `analysis` of each vulnerability of a CycloneDX VEX document. Advisory IDs are
/// mapped to the vulnerability they describe (e.g. GHSA-… to its CVE), so either form works.
pub async fn import(db: &PgPool, project_id: i64, doc: &Value) -> anyhow::Result<ImportStats> {
    let Some(vulns) = doc["vulnerabilities"].as_array() else {
        anyhow::bail!("not a VEX document: no vulnerabilities array");
    };
    let mut stats = ImportStats {
        imported: 0,
        skipped: Vec::new(),
    };
    let mut accepted = Vec::new();
    for v in vulns {
        let Some(id) = v["id"].as_str() else {
            stats.skipped.push("(vulnerability without id)".into());
            continue;
        };
        let Some(state) = v["analysis"]["state"].as_str() else {
            stats.skipped.push(format!("{id}: no analysis.state"));
            continue;
        };
        let analysis = match Analysis::validate(
            state,
            v["analysis"]["justification"].as_str(),
            v["analysis"]["detail"].as_str(),
        ) {
            Ok(a) => a,
            Err(e) => {
                stats.skipped.push(format!("{id}: {e}"));
                continue;
            }
        };
        let key = crate::identity::resolve(db, id)
            .await?
            .unwrap_or_else(|| id.to_owned());
        if matches!(
            analysis.state.as_str(),
            "not_affected" | "false_positive" | "resolved"
        ) {
            let evidence: Option<Value> = sqlx::query_scalar("SELECT finding_evidence($1, $2)")
                .bind(project_id)
                .bind(&key)
                .fetch_one(db)
                .await?;
            let supplied = v["properties"]
                .as_array()
                .and_then(|p| p.iter().find(|p| p["name"] == "tocsin:evidence"))
                .and_then(|p| p["value"].as_str())
                .and_then(|s| serde_json::from_str::<Value>(s).ok());
            let current: Vec<String> = sqlx::query_scalar(
                "SELECT unnest(purls) FROM findings WHERE project_id = $1 AND vuln_key = $2",
            )
            .bind(project_id)
            .bind(&key)
            .fetch_all(db)
            .await?;
            let mut refs: Vec<String> = v["affects"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|a| a["ref"].as_str().map(String::from))
                .collect();
            refs.sort();
            if evidence.is_none() || supplied != evidence || refs != current {
                anyhow::bail!("{id}: suppression does not unambiguously match current evidence");
            }
        }
        accepted.push((key, analysis));
    }
    for (key, analysis) in accepted {
        upsert(db, project_id, &key, &analysis).await?;
        stats.imported += 1;
    }
    Ok(stats)
}
