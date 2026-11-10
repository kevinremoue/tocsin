//! Periodic jobs. On serverless platforms an external scheduler triggers them, through
//! `POST /api/jobs/{job}` or by running `tocsin <job>`; `TOCSIN_SCHEDULER=true` runs them
//! inside `tocsin serve` instead (local use, always-on servers).
use crate::{alerts, api::AppState, epss, kev, osv::Osv, vulns};
use serde_json::{Value, json};
use sqlx::PgPool;
use std::time::Duration;

pub const JOBS: [&str; 3] = ["kev-sync", "epss-sync", "refresh"];

pub fn osv(st: &AppState) -> Osv {
    Osv::new(st.http.clone(), &st.config.osv_url)
}

pub async fn run(st: &AppState, job: &str) -> anyhow::Result<Value> {
    match job {
        "kev-sync" => kev_sync(st).await,
        "epss-sync" => epss_sync(st).await,
        "refresh" => refresh(st).await,
        other => anyhow::bail!("unknown job {other:?}, expected one of {JOBS:?}"),
    }
}

/// Syncs the KEV catalog, then alerts on findings that just became KEV.
pub async fn kev_sync(st: &AppState) -> anyhow::Result<Value> {
    let outcome = kev::sync(&st.db, &st.http, &st.config.kev_url).await?;
    let result = match &outcome {
        kev::Outcome::NotModified => json!({ "catalog": "unchanged" }),
        kev::Outcome::Synced {
            catalog_version,
            new,
            updated,
            total,
        } => json!({
            "catalog": "synced", "version": catalog_version,
            "new": new.len(), "updated": updated, "total": total,
        }),
    };
    let alerted = if outcome == kev::Outcome::NotModified {
        0
    } else {
        snapshot_metrics(&st.db, None).await?;
        alert(st, None).await?
    };
    Ok(json!({ "kev": result, "alerted": alerted }))
}

/// Syncs EPSS scores, then alerts on findings that reached the EPSS threshold.
pub async fn epss_sync(st: &AppState) -> anyhow::Result<Value> {
    let outcome = epss::sync(&st.db, &st.http, &st.config.epss_url).await?;
    let result = match &outcome {
        epss::Outcome::NotModified => json!({ "scores": "unchanged" }),
        epss::Outcome::Synced {
            model_version,
            score_date,
            scored,
            total,
        } => json!({
            "scores": "synced", "model": model_version, "date": score_date,
            "scored": scored, "total": total,
        }),
    };
    let alerted = if outcome == epss::Outcome::NotModified {
        0
    } else {
        alert(st, None).await?
    };
    Ok(json!({ "epss": result, "alerted": alerted }))
}

/// Re-matches every project's latest release against the vulnerability sources.
pub async fn refresh(st: &AppState) -> anyhow::Result<Value> {
    let stats = vulns::refresh_all(&st.db, &osv(st)).await?;
    snapshot_metrics(&st.db, None).await?;
    let alerted = alert(st, None).await?;
    Ok(json!({
        "purls": stats.purls, "links": stats.links, "fetched": stats.fetched, "alerted": alerted,
    }))
}

pub async fn alert(st: &AppState, project_id: Option<i64>) -> anyhow::Result<usize> {
    let notifier = alerts::notifier(&st.config, &st.http);
    alerts::evaluate(&st.db, &st.config, notifier.as_ref(), project_id).await
}

/// Records today's finding counts, for one project or all.
pub async fn snapshot_metrics(db: &PgPool, project_id: Option<i64>) -> sqlx::Result<()> {
    let mut tx = db.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(alerts::LOCK_KEY)
        .execute(&mut *tx)
        .await?;
    sqlx::query("SELECT reconcile_findings()")
        .execute(&mut *tx)
        .await?;
    sqlx::query("SELECT capture_evaluations($1)")
        .bind(project_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    sqlx::query!(
        "INSERT INTO project_metrics (project_id, day, critical, high, medium, low, unknown,
                                      kev, suppressed, components)
         SELECT p.id, current_date,
                count(f.vuln_key) FILTER (WHERE NOT f.suppressed AND f.severity = 4),
                count(f.vuln_key) FILTER (WHERE NOT f.suppressed AND f.severity = 3),
                count(f.vuln_key) FILTER (WHERE NOT f.suppressed AND f.severity = 2),
                count(f.vuln_key) FILTER (WHERE NOT f.suppressed AND f.severity = 1),
                count(f.vuln_key) FILTER (WHERE NOT f.suppressed AND f.severity = 0),
                count(f.vuln_key) FILTER (WHERE NOT f.suppressed AND f.kev),
                count(f.vuln_key) FILTER (WHERE f.suppressed),
                (SELECT count(*) FROM latest_sboms ls JOIN components c ON c.sbom_id = ls.id
                 WHERE ls.project_id = p.id)
         FROM projects p
         LEFT JOIN findings f ON f.project_id = p.id
         WHERE $1::bigint IS NULL OR p.id = $1
         GROUP BY p.id
         ON CONFLICT (project_id, day) DO UPDATE SET
             critical = EXCLUDED.critical, high = EXCLUDED.high, medium = EXCLUDED.medium,
             low = EXCLUDED.low, unknown = EXCLUDED.unknown, kev = EXCLUDED.kev,
             suppressed = EXCLUDED.suppressed, components = EXCLUDED.components",
        project_id,
    )
    .execute(db)
    .await?;
    Ok(())
}

/// In-process scheduler: each job at its own interval, starting now. Failures are logged and
/// retried at the next tick.
pub async fn scheduler(st: AppState) {
    let every = |d: Duration| {
        let mut i = tokio::time::interval(d);
        i.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        i
    };
    let mut kev_tick = every(st.config.kev_sync_every);
    let mut refresh_tick = every(st.config.refresh_every);
    let mut epss_tick = every(st.config.epss_sync_every);
    loop {
        // Biased, in this order: at startup, advisories are refreshed before EPSS scores them
        let job = tokio::select! {
            biased;
            _ = kev_tick.tick() => "kev-sync",
            _ = refresh_tick.tick() => "refresh",
            _ = epss_tick.tick() => "epss-sync",
        };
        match run(&st, job).await {
            Ok(result) => tracing::info!("job {job}: {result}"),
            Err(e) => tracing::warn!("job {job} failed: {e:#}"),
        }
    }
}
