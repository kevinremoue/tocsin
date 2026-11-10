//! Vulnerability matching: package URLs → advisories, stored in `component_vulns`.
//!
//! Advisories use the [OSV schema](https://ossf.github.io/osv-schema/) as the common format,
//! whatever the source. Several advisories often describe the same vulnerability (GHSA-…, PYSEC-…,
//! CVE-…): they share a `canonical_id`, which groups them into one vulnerability (see
//! `identity`).
use futures_util::{StreamExt, TryStreamExt, stream};
use serde_json::Value;
use sqlx::PgPool;
use std::collections::{BTreeSet, HashMap};

/// Advisories fetched in parallel from a source.
const FETCH_CONCURRENCY: usize = 8;

/// Severity of a vulnerability, stored as a SMALLINT rank (0 = unknown … 4 = critical).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Unknown = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

impl Severity {
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "critical" => Some(Self::Critical),
            "high" => Some(Self::High),
            "medium" | "moderate" => Some(Self::Medium),
            "low" => Some(Self::Low),
            "unknown" | "none" => Some(Self::Unknown),
            _ => None,
        }
    }

    pub fn from_rank(rank: i16) -> Self {
        match rank {
            4 => Self::Critical,
            3 => Self::High,
            2 => Self::Medium,
            1 => Self::Low,
            _ => Self::Unknown,
        }
    }

    pub fn rank(self) -> i16 {
        self as i16
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Critical => "Critical",
            Self::High => "High",
            Self::Medium => "Medium",
            Self::Low => "Low",
            Self::Unknown => "Unknown",
        }
    }

    /// Qualitative rating of a CVSS base score.
    pub fn from_cvss(score: f64) -> Self {
        match score {
            s if s >= 9.0 => Self::Critical,
            s if s >= 7.0 => Self::High,
            s if s >= 4.0 => Self::Medium,
            s if s > 0.0 => Self::Low,
            _ => Self::Unknown,
        }
    }
}

/// Base score of a CVSS v3.0/v3.1 vector such as `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`.
pub fn cvss3_base_score(vector: &str) -> Option<f64> {
    let mut parts = vector.split('/');
    if !matches!(parts.next(), Some("CVSS:3.0" | "CVSS:3.1")) {
        return None;
    }
    let metrics: HashMap<&str, &str> = parts.filter_map(|p| p.split_once(':')).collect();
    let get = |k| metrics.get(k).copied();
    let changed = match get("S")? {
        "U" => false,
        "C" => true,
        _ => return None,
    };
    let av = match get("AV")? {
        "N" => 0.85,
        "A" => 0.62,
        "L" => 0.55,
        "P" => 0.2,
        _ => return None,
    };
    let ac = match get("AC")? {
        "L" => 0.77,
        "H" => 0.44,
        _ => return None,
    };
    let pr = match (get("PR")?, changed) {
        ("N", _) => 0.85,
        ("L", false) => 0.62,
        ("L", true) => 0.68,
        ("H", false) => 0.27,
        ("H", true) => 0.5,
        _ => return None,
    };
    let ui = match get("UI")? {
        "N" => 0.85,
        "R" => 0.62,
        _ => return None,
    };
    let cia = |k| match get(k)? {
        "H" => Some(0.56),
        "L" => Some(0.22),
        "N" => Some(0.0),
        _ => None,
    };
    let iss = 1.0 - (1.0 - cia("C")?) * (1.0 - cia("I")?) * (1.0 - cia("A")?);
    let impact = if changed {
        7.52 * (iss - 0.029) - 3.25 * (iss - 0.02f64).powi(15)
    } else {
        6.42 * iss
    };
    if impact <= 0.0 {
        return Some(0.0);
    }
    let exploitability = 8.22 * av * ac * pr * ui;
    let raw = if changed {
        1.08 * (impact + exploitability)
    } else {
        impact + exploitability
    };
    Some(roundup(raw.min(10.0)))
}

/// CVSS v3.1 "Roundup": smallest number with one decimal that is >= the input.
fn roundup(x: f64) -> f64 {
    let int = (x * 100_000.0).round() as i64;
    if int % 10_000 == 0 {
        int as f64 / 100_000.0
    } else {
        ((int / 10_000) + 1) as f64 / 10.0
    }
}

/// An advisory reduced to what Tocsin queries; the full document is kept in `data`.
#[derive(Debug, PartialEq)]
pub struct Advisory {
    pub id: String,
    pub cve_ids: Vec<String>,
    pub canonical_id: String,
    pub summary: Option<String>,
    pub severity: Severity,
    pub cvss_score: Option<f64>,
    pub cvss_vector: Option<String>,
    pub published: Option<String>,
    pub modified: String,
    pub withdrawn: bool,
}

impl Advisory {
    pub fn from_osv(doc: &Value) -> Option<Self> {
        let id = doc["id"].as_str()?.to_owned();
        let strings = |key: &str| -> Vec<&str> {
            doc[key]
                .as_array()
                .map(|a| a.iter().filter_map(Value::as_str).collect())
                .unwrap_or_default()
        };
        // CVE IDs: the advisory's own ID, its aliases, and `upstream` (used by Debian, Ubuntu…)
        let cve_ids: BTreeSet<String> = std::iter::once(id.as_str())
            .chain(strings("aliases"))
            .chain(strings("upstream"))
            .filter(|i| i.starts_with("CVE-"))
            .map(String::from)
            .collect();
        let cve_ids: Vec<String> = cve_ids.into_iter().collect();

        let cvss_vector = doc["severity"].as_array().and_then(|s| {
            s.iter()
                .filter(|e| e["type"] == "CVSS_V3")
                .find_map(|e| e["score"].as_str().map(String::from))
        });
        let cvss_score = cvss_vector.as_deref().and_then(cvss3_base_score);
        // GitHub advisories carry a reviewed rating; otherwise rate the CVSS score
        let severity = doc["database_specific"]["severity"]
            .as_str()
            .and_then(Severity::parse)
            .filter(|s| *s != Severity::Unknown)
            .or(cvss_score.map(Severity::from_cvss))
            .unwrap_or(Severity::Unknown);

        Some(Self {
            // A first name; `identity::regroup` settles it among the other advisories
            canonical_id: cve_ids
                .iter()
                .min_by_key(|c| crate::identity::cve_order(c))
                .cloned()
                .unwrap_or_else(|| id.clone()),
            summary: doc["summary"]
                .as_str()
                .filter(|s| !s.is_empty())
                .map(String::from),
            severity,
            cvss_score,
            cvss_vector,
            published: doc["published"].as_str().map(String::from),
            modified: doc["modified"].as_str().unwrap_or_default().to_owned(),
            withdrawn: doc["withdrawn"].is_string(),
            cve_ids,
            id,
        })
    }
}

/// An advisory affecting a package, as listed by a source.
#[derive(Clone, Debug)]
pub struct VulnRef {
    pub id: String,
    /// Last modification as reported by the source: unchanged = no need to fetch again.
    pub modified: String,
}

/// A vulnerability database that can be queried by package URL.
pub(crate) trait VulnSource {
    /// Advisories affecting each of `purls` (every purl is a key of the result).
    async fn affected(&self, purls: &[String]) -> anyhow::Result<HashMap<String, Vec<VulnRef>>>;
    /// Full advisory, in the OSV format.
    async fn advisory(&self, id: &str) -> anyhow::Result<Value>;
}

/// Only purls with a version can be matched against advisories.
pub fn is_matchable(purl: &str) -> bool {
    let Some(package) = purl
        .strip_prefix("pkg:")
        .and_then(|p| p.split(['?', '#']).next())
    else {
        return false;
    };
    let Some((kind, name_version)) = package.split_once('/') else {
        return false;
    };
    let Some((name, version)) = name_version.rsplit_once('@') else {
        return false;
    };
    !kind.is_empty() && !name.is_empty() && !version.is_empty() && !version.contains('/')
}

#[derive(Debug, Default, PartialEq)]
pub struct MatchStats {
    pub purls: usize,
    /// (purl, advisory) links found
    pub links: usize,
    /// Advisories downloaded (new or modified)
    pub fetched: usize,
}

/// Queries `source` for `purls` and replaces their stored advisory links.
pub(crate) async fn match_purls(
    db: &PgPool,
    source: &impl VulnSource,
    purls: &[String],
) -> anyhow::Result<MatchStats> {
    let purls: Vec<String> = purls
        .iter()
        .filter(|p| is_matchable(p))
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    if purls.is_empty() {
        return Ok(MatchStats::default());
    }
    sqlx::query("INSERT INTO matching_attempts (purl) SELECT unnest($1::text[]) ON CONFLICT (purl) DO UPDATE SET attempted_at = now()")
        .bind(&purls).execute(db).await?;
    let affected = source.affected(&purls).await?;
    // Omitted identifiers were rejected or incompletely evaluated, not proven absent.
    let purls: Vec<String> = purls
        .into_iter()
        .filter(|p| affected.contains_key(p))
        .collect();

    // Fetch only advisories that are new or were modified since they were stored
    let mut latest: HashMap<&str, &str> = HashMap::new();
    for r in affected.values().flatten() {
        latest.insert(&r.id, &r.modified);
    }
    let ids: Vec<String> = latest.keys().map(|s| s.to_string()).collect();
    let known: HashMap<String, String> = sqlx::query!(
        "SELECT id, modified FROM vulnerabilities WHERE id = ANY($1)",
        &ids
    )
    .fetch_all(db)
    .await?
    .into_iter()
    .map(|r| (r.id, r.modified))
    .collect();
    let to_fetch: Vec<String> = latest
        .iter()
        .filter(|(id, modified)| known.get(**id).map(String::as_str) != Some(**modified))
        .map(|(id, _)| id.to_string())
        .collect();

    let expected: BTreeSet<_> = to_fetch.iter().cloned().collect();
    // Owned IDs: a stream of futures borrowing &str trips rustc's Send inference in axum handlers
    let docs: Vec<Value> = stream::iter(to_fetch)
        .map(|id| async move { source.advisory(&id).await })
        .buffer_unordered(FETCH_CONCURRENCY)
        .try_collect()
        .await?;
    let received: BTreeSet<_> = docs
        .iter()
        .filter_map(|doc| Advisory::from_osv(doc).map(|a| a.id))
        .collect();
    if received != expected || docs.iter().any(|doc| Advisory::from_osv(doc).is_none()) {
        anyhow::bail!("incomplete matching: invalid or mismatched advisory");
    }
    let fetched = docs.len();
    store_advisories(db, &docs, &latest).await?;
    if fetched > 0 {
        crate::identity::regroup(db).await?;
    }

    let mut link_purls = Vec::new();
    let mut link_ids = Vec::new();
    for (purl, refs) in &affected {
        for r in refs {
            link_purls.push(purl.clone());
            link_ids.push(r.id.clone());
        }
    }

    let mut tx = db.begin().await?;
    sqlx::query!("DELETE FROM component_vulns WHERE purl = ANY($1)", &purls)
        .execute(&mut *tx)
        .await?;
    // Joined on vulnerabilities: an advisory that could not be parsed is not linked
    let links = sqlx::query!(
        "INSERT INTO component_vulns (purl, vuln_id)
         SELECT l.purl, l.vuln_id FROM UNNEST($1::text[], $2::text[]) AS l (purl, vuln_id)
         JOIN vulnerabilities v ON v.id = l.vuln_id
         ON CONFLICT DO NOTHING",
        &link_purls,
        &link_ids,
    )
    .execute(&mut *tx)
    .await?
    .rows_affected() as usize;
    sqlx::query!(
        "INSERT INTO purl_scans (purl, scanned_at) SELECT unnest($1::text[]), now()
         ON CONFLICT (purl) DO UPDATE SET scanned_at = now()",
        &purls,
    )
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;

    Ok(MatchStats {
        purls: purls.len(),
        links,
        fetched,
    })
}

/// `reported` holds the modification times the source listed. They are stored instead of the
/// advisory's own: OSV's batch endpoint truncates them to microseconds while advisories carry
/// nanoseconds, and the next comparison is against the batch value.
async fn store_advisories(
    db: &PgPool,
    docs: &[Value],
    reported: &HashMap<&str, &str>,
) -> anyhow::Result<()> {
    let mut ids = Vec::new();
    let mut cve_ids = Vec::new();
    let mut canonical = Vec::new();
    let mut summaries = Vec::new();
    let mut severities = Vec::new();
    let mut scores = Vec::new();
    let mut vectors = Vec::new();
    let mut published = Vec::new();
    let mut modified = Vec::new();
    let mut withdrawn = Vec::new();
    let mut data = Vec::new();
    for doc in docs {
        let Some(a) = Advisory::from_osv(doc) else {
            tracing::warn!("skipping advisory without an id");
            continue;
        };
        let modified_at = reported
            .get(a.id.as_str())
            .map(|m| m.to_string())
            .unwrap_or(a.modified);
        ids.push(a.id);
        // Postgres has no array of arrays of different lengths: joined, split back in SQL
        cve_ids.push(a.cve_ids.join(","));
        canonical.push(a.canonical_id);
        summaries.push(a.summary);
        severities.push(a.severity.rank());
        scores.push(a.cvss_score.map(|s| s as f32));
        vectors.push(a.cvss_vector);
        published.push(a.published);
        modified.push(modified_at);
        withdrawn.push(a.withdrawn);
        data.push(doc.clone());
    }
    if ids.is_empty() {
        return Ok(());
    }
    sqlx::query!(
        "INSERT INTO vulnerabilities (id, cve_ids, canonical_id, summary, severity, cvss_score,
                                      cvss_vector, published_at, modified, withdrawn, data)
         SELECT id, COALESCE(string_to_array(NULLIF(cves, ''), ','), '{}'), canonical, summary, severity, score,
                vector, published::timestamptz, modified, withdrawn, data
         FROM UNNEST($1::text[], $2::text[], $3::text[], $4::text[], $5::smallint[], $6::real[],
                     $7::text[], $8::text[], $9::text[], $10::bool[], $11::jsonb[])
              AS t (id, cves, canonical, summary, severity, score, vector, published, modified, withdrawn, data)
         ON CONFLICT (id) DO UPDATE SET
             cve_ids = EXCLUDED.cve_ids,
             summary = EXCLUDED.summary, severity = EXCLUDED.severity,
             cvss_score = EXCLUDED.cvss_score, cvss_vector = EXCLUDED.cvss_vector,
             published_at = EXCLUDED.published_at, modified = EXCLUDED.modified,
             withdrawn = EXCLUDED.withdrawn, data = EXCLUDED.data, fetched_at = now()",
        &ids as &[String],
        &cve_ids,
        &canonical,
        &summaries as &[Option<String>],
        &severities,
        &scores as &[Option<f32>],
        &vectors as &[Option<String>],
        &published as &[Option<String>],
        &modified,
        &withdrawn,
        &data,
    )
    .execute(db)
    .await?;
    Ok(())
}

/// Purls of the latest release of `project_id` that were never matched, or not since `max_age`.
pub async fn stale_purls(
    db: &PgPool,
    project_id: i64,
    max_age: std::time::Duration,
) -> sqlx::Result<Vec<String>> {
    sqlx::query_scalar!(
        r#"SELECT c.purl AS "purl!" FROM latest_sboms ls
           JOIN components c ON c.sbom_id = ls.id
           LEFT JOIN purl_scans s ON s.purl = c.purl
           WHERE ls.project_id = $1
             AND (s.scanned_at IS NULL OR s.scanned_at < now() - make_interval(secs => $2))"#,
        project_id,
        max_age.as_secs_f64(),
    )
    .fetch_all(db)
    .await
}

/// Re-matches every purl of every project's latest release, then forgets purls no project uses.
pub(crate) async fn refresh_all(
    db: &PgPool,
    source: &impl VulnSource,
) -> anyhow::Result<MatchStats> {
    let purls = sqlx::query_scalar!(
        r#"SELECT DISTINCT c.purl AS "purl!" FROM latest_sboms ls
           JOIN components c ON c.sbom_id = ls.id ORDER BY 1"#
    )
    .fetch_all(db)
    .await?;
    let mut total = MatchStats::default();
    for chunk in purls.chunks(1000) {
        let stats = match_purls(db, source, chunk).await?;
        total.purls += stats.purls;
        total.links += stats.links;
        total.fetched += stats.fetched;
    }
    sqlx::query!(
        "DELETE FROM component_vulns cv WHERE NOT EXISTS (
             SELECT 1 FROM latest_sboms ls JOIN components c ON c.sbom_id = ls.id
             WHERE c.purl = cv.purl)"
    )
    .execute(db)
    .await?;
    // Also settles names stored before regrouping existed
    crate::identity::regroup(db).await?;
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn cvss3_scores_match_the_reference_calculator() {
        // Log4Shell
        assert_eq!(
            cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"),
            Some(10.0)
        );
        // lodash command injection (GHSA-35jh-r3h4-6jhm)
        assert_eq!(
            cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"),
            Some(7.2)
        );
        // OpenSSL infinite loop (CVE-2022-0778)
        assert_eq!(
            cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"),
            Some(7.5)
        );
        assert_eq!(
            cvss3_base_score("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N"),
            Some(3.1)
        );
        assert_eq!(
            cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"),
            Some(0.0)
        );
        // Temporal metrics are ignored; malformed or other versions give None
        assert_eq!(
            cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:H"),
            Some(10.0)
        );
        assert_eq!(cvss3_base_score("CVSS:3.1/AV:N/AC:L"), None);
        assert_eq!(cvss3_base_score("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N"), None);
    }

    #[test]
    fn advisory_from_osv() {
        let ghsa = Advisory::from_osv(&json!({
            "id": "GHSA-jfh8-c2jp-5v3q",
            "aliases": ["CVE-2021-44228"],
            "summary": "Remote code injection in Log4j",
            "modified": "2026-01-01T00:00:00Z",
            "published": "2021-12-10T00:40:56Z",
            "severity": [{ "type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H" }],
            "database_specific": { "severity": "CRITICAL" }
        }))
        .unwrap();
        assert_eq!(ghsa.canonical_id, "CVE-2021-44228");
        assert_eq!(ghsa.severity, Severity::Critical);
        assert_eq!(ghsa.cvss_score, Some(10.0));

        // Debian lists the CVE in `upstream`; severity comes from the CVSS score
        let debian = Advisory::from_osv(&json!({
            "id": "DEBIAN-CVE-2022-0778",
            "upstream": ["CVE-2022-0778"],
            "modified": "2026-01-01T00:00:00Z",
            "severity": [{ "type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" }]
        }))
        .unwrap();
        assert_eq!(debian.cve_ids, ["CVE-2022-0778"]);
        assert_eq!(debian.canonical_id, "CVE-2022-0778");
        assert_eq!(debian.severity, Severity::High);

        let no_cve = Advisory::from_osv(&json!({
            "id": "RUSTSEC-2020-0001", "modified": "x", "withdrawn": "2026-01-01T00:00:00Z"
        }))
        .unwrap();
        assert_eq!(no_cve.canonical_id, "RUSTSEC-2020-0001");
        assert_eq!(no_cve.severity, Severity::Unknown);
        assert!(no_cve.withdrawn);
    }

    #[test]
    fn only_versioned_purls_are_matchable() {
        assert!(is_matchable("pkg:npm/lodash@4.17.20"));
        assert!(is_matchable("pkg:deb/debian/openssl@3.0.11?arch=amd64"));
        assert!(!is_matchable("pkg:npm/left-pad"));
        assert!(!is_matchable("pkg:npm/left-pad?x=a@b"));
        assert!(!is_matchable("not-a-purl@1"));
    }
}
