//! Alerts: findings matching an alert rule are notified once per (project, vulnerability, rule).
//!
//! Rules: `kev` (the finding is in the CISA KEV catalog), `severity` (the finding is at
//! least `TOCSIN_ALERT_MIN_SEVERITY`) and `epss` (its EPSS score is at least
//! `TOCSIN_ALERT_MIN_EPSS`). Suppressed findings (audited as not affected, false
//! positive or resolved) never alert. Without a notifier, nothing is evaluated or recorded,
//! so configuring a channel later sends what is pending.
use crate::{config::Config, vulns::Severity};
use anyhow::Context;
use serde_json::json;
use sqlx::PgPool;
use std::collections::BTreeMap;

/// Advisory-lock key serializing alert evaluation across instances (b"tocsin_a" as i64).
pub(crate) const LOCK_KEY: i64 = 0x746f_6373_696e_5f61;

#[derive(Debug, Clone)]
pub struct Finding {
    pub vuln_key: String,
    pub summary: Option<String>,
    pub severity: Severity,
    pub kev: bool,
    pub epss: Option<f32>,
    pub purls: Vec<String>,
}

/// A finding to notify, with the rules it matched (each is recorded once sent).
type PendingAlert = (Finding, Vec<String>);

/// A delivery channel for alerts.
pub(crate) trait Notifier {
    /// Sends one message about the new findings of `project`.
    async fn send(&self, project: &str, findings: &[Finding]) -> anyhow::Result<()>;
}

pub struct GoogleChat {
    client: reqwest::Client,
    webhook: String,
    public_url: Option<String>,
}

impl GoogleChat {
    pub fn new(client: reqwest::Client, webhook: String, public_url: Option<String>) -> Self {
        Self {
            client,
            webhook,
            public_url,
        }
    }

    pub fn message(&self, project: &str, findings: &[Finding]) -> String {
        let link = |path: String, text: &str| match &self.public_url {
            Some(base) => format!("<{base}{path}|{text}>"),
            None => text.to_owned(),
        };
        let mut text = format!(
            "🔔 *{}* is affected by {} new {}:\n",
            link(format!("/projects/{project}"), project),
            findings.len(),
            if findings.len() == 1 {
                "vulnerability"
            } else {
                "vulnerabilities"
            }
        );
        for f in findings {
            text.push_str(&format!(
                "• {} · {}{}",
                link(format!("/vulns/{}", f.vuln_key), &f.vuln_key),
                f.severity.label(),
                if f.kev {
                    " · *actively exploited (KEV)*"
                } else {
                    ""
                },
            ));
            if let Some(epss) = f.epss {
                text.push_str(&format!(" · EPSS {}", crate::epss::percent(epss)));
            }
            if let Some(summary) = &f.summary {
                text.push_str(&format!(" · {summary}"));
            }
            let shown: Vec<&str> = f.purls.iter().take(3).map(String::as_str).collect();
            text.push_str(&format!("\n   in `{}`", shown.join("`, `")));
            if f.purls.len() > shown.len() {
                text.push_str(&format!(" and {} more", f.purls.len() - shown.len()));
            }
            text.push('\n');
        }
        text
    }
}

impl Notifier for GoogleChat {
    async fn send(&self, project: &str, findings: &[Finding]) -> anyhow::Result<()> {
        self.client
            .post(&self.webhook)
            .json(&json!({ "text": self.message(project, findings) }))
            .send()
            .await
            .and_then(|r| r.error_for_status())
            .context("cannot post to Google Chat")?;
        Ok(())
    }
}

/// The notifier configured, if any.
pub fn notifier(config: &Config, client: &reqwest::Client) -> Option<GoogleChat> {
    config
        .google_chat_webhook
        .as_ref()
        .map(|webhook| GoogleChat::new(client.clone(), webhook.clone(), config.public_url.clone()))
}

/// Sends the pending alerts, for one project or all. Returns the number of findings notified.
pub(crate) async fn evaluate(
    db: &PgPool,
    config: &Config,
    notifier: Option<&impl Notifier>,
    project_id: Option<i64>,
) -> anyhow::Result<usize> {
    let mut tx = db.begin().await?;
    // Serialize reconciliation, identity merges and delivery history across instances.
    sqlx::query!("SELECT pg_advisory_xact_lock($1)", LOCK_KEY)
        .execute(&mut *tx)
        .await?;
    sqlx::query("SELECT reconcile_findings()")
        .execute(&mut *tx)
        .await?;
    sqlx::query("SELECT capture_evaluations($1)")
        .bind(project_id)
        .execute(&mut *tx)
        .await?;
    let Some(notifier) = notifier else {
        tx.commit().await?;
        return Ok(0);
    };
    if !config.alert_kev && config.alert_min_severity.is_none() && config.alert_min_epss.is_none() {
        tx.commit().await?;
        return Ok(0);
    }
    let rows = sqlx::query!(
        r#"SELECT f.project_id AS "project_id!", p.name, f.vuln_key AS "vuln_key!",
                  f.severity AS "severity!", f.kev AS "kev!", f.epss, f.summary,
                  f.purls AS "purls!",
                  r.rule AS "rule!"
           FROM findings f
           JOIN projects p ON p.id = f.project_id
           CROSS JOIN LATERAL (VALUES
               ('kev', $1 AND f.kev),
               ('severity', $2::smallint IS NOT NULL AND f.severity >= $2),
               ('epss', $4::real IS NOT NULL AND f.epss IS NOT NULL AND f.epss >= $4)
           ) AS r (rule, applies)
           WHERE r.applies AND NOT f.suppressed
             AND ($3::bigint IS NULL OR f.project_id = $3)
             AND NOT EXISTS (SELECT 1 FROM alerts a WHERE a.project_id = f.project_id
                             AND a.vuln_key = f.vuln_key AND a.rule = r.rule
                              AND a.episode = (SELECT episode FROM finding_episodes e
                                  WHERE e.project_id = f.project_id AND e.vuln_key = f.vuln_key))
           ORDER BY p.name, f.kev DESC, f.epss DESC NULLS LAST, f.severity DESC, f.vuln_key"#,
        config.alert_kev,
        config.alert_min_severity.map(Severity::rank),
        project_id,
        config.alert_min_epss,
    )
    .fetch_all(&mut *tx)
    .await?;

    // Per project: findings (one per vulnerability, even if several rules apply) and the rules to record
    let mut by_project: BTreeMap<(String, i64), Vec<PendingAlert>> = BTreeMap::new();
    for r in rows {
        let findings = by_project.entry((r.name, r.project_id)).or_default();
        match findings.iter_mut().find(|(f, _)| f.vuln_key == r.vuln_key) {
            Some((_, rules)) => rules.push(r.rule),
            None => findings.push((
                Finding {
                    vuln_key: r.vuln_key,
                    summary: r.summary,
                    severity: Severity::from_rank(r.severity),
                    kev: r.kev,
                    epss: r.epss,
                    purls: r.purls,
                },
                vec![r.rule],
            )),
        }
    }

    let mut sent = 0;
    for ((project, project_id), findings) in by_project {
        let list: Vec<Finding> = findings.iter().map(|(f, _)| f.clone()).collect();
        if let Err(e) = notifier.send(&project, &list).await {
            // Not recorded: retried at the next evaluation
            tracing::warn!("alert for project {project} not sent: {e:#}");
            continue;
        }
        for (f, rules) in &findings {
            for rule in rules {
                sqlx::query!(
                    "INSERT INTO alerts (project_id, vuln_key, rule, severity, kev, episode)
                     VALUES ($1, $2, $3, $4, $5, (SELECT episode FROM finding_episodes
                         WHERE project_id = $1 AND vuln_key = $2)) ON CONFLICT DO NOTHING",
                    project_id,
                    f.vuln_key,
                    rule,
                    f.severity.rank(),
                    f.kev,
                )
                .execute(&mut *tx)
                .await?;
            }
        }
        tracing::info!("alert sent for project {project}: {} findings", list.len());
        sent += list.len();
    }
    tx.commit().await?;
    Ok(sent)
}
