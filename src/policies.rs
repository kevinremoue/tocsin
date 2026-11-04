//! Policies, evaluated against each project's latest release.
use serde::Serialize;
use sqlx::PgPool;

pub const KINDS: [&str; 4] = ["license", "severity", "kev", "epss"];

#[derive(Debug, Serialize)]
pub struct Violation {
    pub project: String,
    pub policy_id: i64,
    pub policy: String,
    pub kind: String,
    /// The component purl (license policies) or the vulnerability (other kinds)
    pub subject: String,
    /// Licenses of the component, or severity (and KEV, EPSS) of the finding
    pub detail: String,
}

/// Validates a new policy; returns the normalized value.
pub fn validate(kind: &str, value: &str) -> Result<String, String> {
    match kind {
        "license" if !value.trim().is_empty() => Ok(value.trim().to_owned()),
        "license" => Err("a license policy needs a value: the SPDX license ID".into()),
        "severity" => crate::vulns::Severity::parse(value)
            .filter(|s| *s != crate::vulns::Severity::Unknown)
            .map(|s| s.label().to_lowercase())
            .ok_or_else(|| "a severity policy needs a value: critical, high, medium or low".into()),
        "kev" => Ok(String::new()),
        "epss" => crate::config::parse_probability(value)
            .map(|p| p.to_string())
            .ok_or_else(|| {
                "an EPSS policy needs a value: a probability above 0 and at most 1 (0.5), or a percentage (50%)".into()
            }),
        _ => Err(format!("invalid kind {kind:?}, expected one of {KINDS:?}")),
    }
}

/// Current violations, for one project or all.
pub async fn violations(db: &PgPool, project_id: Option<i64>) -> sqlx::Result<Vec<Violation>> {
    sqlx::query_as!(
        Violation,
        r#"SELECT p.name AS "project!", pol.id AS "policy_id!", pol.name AS "policy!",
                  pol.kind AS "kind!", c.purl AS "subject!",
                  array_to_string(c.licenses, ', ') AS "detail!"
           FROM policies pol
           JOIN latest_sboms ls ON $1::bigint IS NULL OR ls.project_id = $1
           JOIN projects p ON p.id = ls.project_id
           JOIN components c ON c.sbom_id = ls.id
           WHERE pol.kind = 'license' AND EXISTS (
               -- Matches an SPDX ID alone or inside an expression ("GPL-2.0-only OR MIT")
               SELECT 1 FROM unnest(c.licenses) l,
                    regexp_split_to_table(lower(l), '[\s()]+') token
               WHERE token = lower(pol.value))
           UNION ALL
           SELECT p.name, pol.id, pol.name, pol.kind, f.vuln_key,
                  CASE f.severity WHEN 4 THEN 'Critical' WHEN 3 THEN 'High' WHEN 2 THEN 'Medium'
                                  WHEN 1 THEN 'Low' ELSE 'Unknown' END
                  || CASE WHEN f.kev THEN ', KEV' ELSE '' END
                  || CASE WHEN f.epss IS NOT NULL
                          THEN ', EPSS ' || round((f.epss * 100)::numeric, 1) || '%' ELSE '' END
           FROM policies pol
           JOIN findings f ON NOT f.suppressed AND ($1::bigint IS NULL OR f.project_id = $1)
                AND ((pol.kind = 'kev' AND f.kev)
                     -- CASE: the value is only a number for EPSS policies
                     OR (pol.kind = 'epss' AND f.epss >= CASE WHEN pol.kind = 'epss'
                                                          THEN pol.value::real END)
                     OR (pol.kind = 'severity' AND f.severity >= CASE pol.value
                             WHEN 'critical' THEN 4 WHEN 'high' THEN 3
                             WHEN 'medium' THEN 2 ELSE 1 END))
           JOIN projects p ON p.id = f.project_id
           ORDER BY 1, 2, 5"#,
        project_id
    )
    .fetch_all(db)
    .await
}
