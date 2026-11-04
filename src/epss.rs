//! Sync of EPSS scores (Exploit Prediction Scoring System, by FIRST: https://www.first.org/epss).
//!
//! FIRST asks tools keeping a local copy to use the daily file, not the API. The file
//! (~3 MB gzipped, every scored CVE) is downloaded with a conditional request and only the
//! CVEs of stored advisories are kept. When advisories were stored since the last download,
//! the file is downloaded again even if unchanged, so their CVEs get a score.
use anyhow::{Context, bail};
use reqwest::{StatusCode, header};
use sqlx::PgPool;
use std::collections::{BTreeMap, HashSet};
use std::io::{BufRead, BufReader, Read};

#[derive(Debug, PartialEq)]
pub enum Outcome {
    /// The file has not changed and no CVE awaits a score (HTTP 304).
    NotModified,
    Synced {
        model_version: String,
        score_date: String,
        /// CVEs of stored advisories that have a score
        scored: usize,
        /// Scores in the file
        total: usize,
    },
}

#[derive(Debug, PartialEq)]
pub struct Score {
    pub score: f32,
    pub percentile: f32,
}

#[derive(Debug, PartialEq)]
struct Parsed {
    model_version: Option<String>,
    score_date: Option<String>,
    total: usize,
    scores: BTreeMap<String, Score>,
}

/// One sync attempt. Its result, success or error, is recorded in `epss_sync`.
pub async fn sync(db: &PgPool, client: &reqwest::Client, url: &str) -> anyhow::Result<Outcome> {
    let result = try_sync(db, client, url).await;
    if let Err(e) = &result {
        let recorded = sqlx::query!(
            "UPDATE epss_sync SET last_error = $1, last_attempt_at = now()",
            format!("{e:#}"),
        )
        .execute(db)
        .await;
        if let Err(db_err) = recorded {
            tracing::error!("cannot record EPSS sync error: {db_err}");
        }
    }
    result
}

async fn try_sync(db: &PgPool, client: &reqwest::Client, url: &str) -> anyhow::Result<Outcome> {
    // Timestamps travel as text: there is no chrono/time dependency
    let previous = sqlx::query!(
        r#"SELECT etag, last_modified, now()::text AS "started!",
                  downloaded_at IS NULL OR EXISTS (
                      SELECT 1 FROM vulnerabilities WHERE fetched_at >= downloaded_at
                  ) AS "new_cves!"
           FROM epss_sync"#
    )
    .fetch_one(db)
    .await?;

    let mut req = client.get(url);
    if !previous.new_cves {
        if let Some(etag) = &previous.etag {
            req = req.header(header::IF_NONE_MATCH, etag);
        }
        if let Some(last_modified) = &previous.last_modified {
            req = req.header(header::IF_MODIFIED_SINCE, last_modified);
        }
    }
    let res = req.send().await.context("cannot download EPSS scores")?;

    if res.status() == StatusCode::NOT_MODIFIED {
        sqlx::query!(
            "UPDATE epss_sync SET checked_at = now(), last_error = NULL, last_attempt_at = now()"
        )
        .execute(db)
        .await?;
        return Ok(Outcome::NotModified);
    }

    let res = res
        .error_for_status()
        .context("cannot download EPSS scores")?;
    let validator = |name| {
        res.headers()
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(String::from)
    };
    let (etag, last_modified) = (validator(header::ETAG), validator(header::LAST_MODIFIED));
    let body = res.bytes().await.context("cannot download EPSS scores")?;

    let tracked: HashSet<String> =
        sqlx::query_scalar!(r#"SELECT DISTINCT unnest(cve_ids) AS "cve!" FROM vulnerabilities"#)
            .fetch_all(db)
            .await?
            .into_iter()
            .collect();
    // Decompressing and parsing ~400k lines is CPU work: off the async workers
    let parsed = tokio::task::spawn_blocking(move || parse(&body, &tracked)).await??;

    let model_version = parsed.model_version.unwrap_or_else(|| "unknown".into());
    let mut cve_ids = Vec::with_capacity(parsed.scores.len());
    let mut scores = Vec::with_capacity(parsed.scores.len());
    let mut percentiles = Vec::with_capacity(parsed.scores.len());
    for (cve, s) in parsed.scores {
        cve_ids.push(cve);
        scores.push(s.score);
        percentiles.push(s.percentile);
    }
    let scored = cve_ids.len();

    let mut tx = db.begin().await?;
    // A few hundred rows: replacing them is simpler than diffing, and drops untracked CVEs
    sqlx::query!("DELETE FROM epss_scores")
        .execute(&mut *tx)
        .await?;
    let score_date = sqlx::query_scalar!(
        r#"WITH d AS (SELECT COALESCE($4::text::date, current_date) AS day),
           ins AS (
               INSERT INTO epss_scores (cve_id, score, percentile, score_date, model_version)
               SELECT u.cve, u.score, u.percentile, d.day, $5
               FROM UNNEST($1::text[], $2::real[], $3::real[]) AS u (cve, score, percentile), d
           )
           UPDATE epss_sync SET model_version = $5, score_date = (SELECT day FROM d),
                  etag = $6, last_modified = $7, downloaded_at = $8::text::timestamptz,
                  checked_at = now(), last_error = NULL, last_attempt_at = now()
           RETURNING to_char(score_date, 'YYYY-MM-DD') AS "day!""#,
        &cve_ids,
        &scores,
        &percentiles,
        parsed.score_date,
        model_version,
        etag,
        last_modified,
        previous.started,
    )
    .fetch_one(&mut *tx)
    .await
    .context("cannot store EPSS scores")?;
    tx.commit().await?;

    Ok(Outcome::Synced {
        model_version,
        score_date,
        scored,
        total: parsed.total,
    })
}

/// Parses the EPSS file (gzipped or plain CSV), keeping the scores of `tracked` CVEs.
///
/// ```text
/// #model_version:v2026.06.15,score_date:2026-11-04T12:03:12Z
/// cve,epss,percentile
/// CVE-1999-0001,0.04753,0.91909
/// ```
fn parse(body: &[u8], tracked: &HashSet<String>) -> anyhow::Result<Parsed> {
    let reader: Box<dyn Read + '_> = if body.starts_with(&[0x1f, 0x8b]) {
        Box::new(flate2::read::GzDecoder::new(body))
    } else {
        Box::new(body)
    };
    let mut parsed = Parsed {
        model_version: None,
        score_date: None,
        total: 0,
        scores: BTreeMap::new(),
    };
    let mut malformed = 0;
    for line in BufReader::new(reader).lines() {
        let line = line.context("invalid EPSS file")?;
        let line = line.trim();
        if let Some(meta) = line.strip_prefix('#') {
            for field in meta.split(',') {
                match field.split_once(':') {
                    Some(("model_version", v)) => parsed.model_version = Some(v.trim().into()),
                    // An RFC 3339 timestamp: its date part
                    Some(("score_date", v)) => {
                        parsed.score_date = v.trim().get(..10).map(String::from)
                    }
                    _ => {}
                }
            }
            continue;
        }
        if line.is_empty() || line.starts_with("cve,") {
            continue;
        }
        let mut cols = line.split(',');
        let row = (|| {
            let cve = cols.next()?;
            let score: f32 = cols.next()?.parse().ok()?;
            let percentile: f32 = cols.next()?.parse().ok()?;
            ((0.0..=1.0).contains(&score) && (0.0..=1.0).contains(&percentile))
                .then_some((cve, score, percentile))
        })();
        let Some((cve, score, percentile)) = row else {
            malformed += 1;
            continue;
        };
        parsed.total += 1;
        if tracked.contains(cve) {
            parsed
                .scores
                .insert(cve.to_owned(), Score { score, percentile });
        }
    }
    if malformed > 0 {
        tracing::warn!("skipped {malformed} malformed EPSS rows");
    }
    if parsed.total == 0 {
        bail!("the EPSS file has no scores");
    }
    Ok(parsed)
}

/// "97%", "4.2%", "<0.1%": the score as a percentage, with a decimal below 10%.
pub fn percent(score: f32) -> String {
    let p = f64::from(score) * 100.0;
    if p < 0.05 {
        "<0.1%".into()
    } else if p >= 10.0 {
        format!("{p:.0}%")
    } else {
        format!("{p:.1}%")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FILE: &str = "#model_version:v2026.06.15,score_date:2026-11-04T12:03:12Z\n\
                        cve,epss,percentile\n\
                        CVE-2021-44228,0.99999,1.00000\n\
                        CVE-2020-0001,0.00042,0.10000\n\
                        CVE-2022-22965,not-a-number,0.5\n\
                        CVE-2019-0001,0.5,0.9\n";

    fn gzip(text: &str) -> Vec<u8> {
        use std::io::Write;
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(text.as_bytes()).unwrap();
        enc.finish().unwrap()
    }

    #[test]
    fn parses_gzipped_and_plain_files_keeping_tracked_cves() {
        let tracked: HashSet<String> = ["CVE-2021-44228", "CVE-2022-22965", "CVE-2030-0001"]
            .map(String::from)
            .into();
        let expected = Parsed {
            model_version: Some("v2026.06.15".into()),
            score_date: Some("2026-11-04".into()),
            // The malformed row is not counted
            total: 3,
            scores: BTreeMap::from([(
                "CVE-2021-44228".into(),
                Score {
                    score: 0.99999,
                    percentile: 1.0,
                },
            )]),
        };
        assert_eq!(parse(&gzip(FILE), &tracked).unwrap(), expected);
        assert_eq!(parse(FILE.as_bytes(), &tracked).unwrap(), expected);
        assert!(parse(b"cve,epss,percentile\n", &tracked).is_err());
    }

    #[test]
    fn formats_percentages() {
        assert_eq!(percent(0.99999), "100%");
        assert_eq!(percent(0.4567), "46%");
        assert_eq!(percent(0.042), "4.2%");
        assert_eq!(percent(0.0004), "<0.1%");
    }
}
