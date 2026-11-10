//! Vulnerability identity (see `docs/adr/0001-vulnerability-identity.md`).
//!
//! A vulnerability is a group of advisories sharing a CVE, transitively: an advisory listing
//! CVE-1 and CVE-2 joins the advisories of both. Its name (`canonical_id`) is one of the group's
//! CVEs, or the ID of an advisory without CVE. Names change when sources change: an advisory
//! gains a CVE, or a new advisory links two groups. Analyses and sent alerts belong to the
//! vulnerability, not to its name: [`regroup`] renames the groups and moves them along.
use sqlx::PgPool;
use std::collections::HashMap;

/// Serializes regroupings across instances: "regroup" in ASCII, unique to this lock.
const LOCK: i64 = 0x0072_6567_726f_7570;

/// States that suppress a finding (see `findings` view).
const SUPPRESSING: [&str; 3] = ["not_affected", "false_positive", "resolved"];

pub struct Member<'a> {
    pub id: &'a str,
    pub cve_ids: &'a [String],
    pub canonical_id: &'a str,
}

/// The name each advisory should carry. A group keeps the name most of its members already
/// carry when it is one of its CVEs, so names stay stable; otherwise it takes its oldest CVE.
pub fn names(members: &[Member]) -> Vec<String> {
    // Union-find over advisories, linked through the CVEs they share
    let mut parent: Vec<usize> = (0..members.len()).collect();
    fn root(parent: &mut [usize], mut i: usize) -> usize {
        while parent[i] != i {
            parent[i] = parent[parent[i]];
            i = parent[i];
        }
        i
    }
    let mut by_cve: HashMap<&str, usize> = HashMap::new();
    for (i, m) in members.iter().enumerate() {
        for cve in m.cve_ids {
            match by_cve.get(cve.as_str()) {
                Some(&j) => {
                    let (a, b) = (root(&mut parent, i), root(&mut parent, j));
                    parent[a] = b;
                }
                None => {
                    by_cve.insert(cve, i);
                }
            }
        }
    }
    let mut groups: HashMap<usize, Vec<usize>> = HashMap::new();
    for i in 0..members.len() {
        groups.entry(root(&mut parent, i)).or_default().push(i);
    }

    let mut out: Vec<String> = members.iter().map(|m| m.canonical_id.to_owned()).collect();
    for indexes in groups.values() {
        let mut cves: Vec<&str> = indexes
            .iter()
            .flat_map(|&i| members[i].cve_ids.iter().map(String::as_str))
            .collect();
        if cves.is_empty() {
            // Without CVE, an advisory is its own vulnerability
            for &i in indexes {
                out[i] = members[i].id.to_owned();
            }
            continue;
        }
        cves.sort_by_key(|c| cve_order(c));
        cves.dedup();
        let mut votes: HashMap<&str, usize> = HashMap::new();
        for &i in indexes {
            if cves.contains(&members[i].canonical_id) {
                *votes.entry(members[i].canonical_id).or_default() += 1;
            }
        }
        // Most carried name; ties and no vote go to the oldest CVE
        let name = cves
            .iter()
            .max_by_key(|c| {
                (
                    votes.get(*c).copied().unwrap_or(0),
                    std::cmp::Reverse(cve_order(c)),
                )
            })
            .copied()
            .unwrap_or(cves[0]);
        for &i in indexes {
            out[i] = name.to_owned();
        }
    }
    out
}

/// CVE-2021-44228 → (2021, 44228): numeric order, so CVE-2021-9999 comes before CVE-2021-10000.
pub(crate) fn cve_order(cve: &str) -> (u32, u64, String) {
    let mut parts = cve.trim_start_matches("CVE-").splitn(2, '-');
    let year = parts
        .next()
        .and_then(|y| y.parse().ok())
        .unwrap_or(u32::MAX);
    let number = parts
        .next()
        .and_then(|n| n.parse().ok())
        .unwrap_or(u64::MAX);
    (year, number, cve.to_owned())
}

#[derive(Clone, Debug, PartialEq)]
pub struct Decision {
    pub state: String,
    pub justification: Option<String>,
    pub detail: Option<String>,
    /// Seconds since the epoch
    pub updated_at: f64,
}

impl Decision {
    fn suppresses(&self) -> bool {
        SUPPRESSING.contains(&self.state.as_str())
    }

    fn summary(&self, name: &str) -> String {
        let mut s = format!("Merged: analysis under {name} was {}", self.state);
        if let Some(j) = &self.justification {
            s.push_str(&format!(" ({j})"));
        }
        if let Some(d) = self.detail.as_deref().filter(|d| !d.is_empty()) {
            s.push_str(&format!(": {d}"));
        }
        s
    }
}

/// Two analyses of one project now apply to the same vulnerability. The one that does not
/// suppress the finding wins, so a merge never hides it; otherwise the most recent. The other
/// is noted in the winner's detail.
pub fn merge(kept: Decision, kept_name: &str, incoming: Decision, incoming_name: &str) -> Decision {
    let incoming_wins = match (kept.suppresses(), incoming.suppresses()) {
        (true, false) => true,
        (false, true) => false,
        _ => incoming.updated_at > kept.updated_at,
    };
    let (mut winner, loser, loser_name) = if incoming_wins {
        (incoming, kept, kept_name)
    } else {
        (kept, incoming, incoming_name)
    };
    let note = loser.summary(loser_name);
    winner.detail = Some(match winner.detail.take().filter(|d| !d.is_empty()) {
        Some(d) => format!("{d}\n{note}"),
        None => note,
    });
    winner
}

/// The current name of the vulnerability called `name`: its current name, any of its
/// advisory IDs, or any of its CVEs (a name it may have carried before a merge).
pub async fn resolve(db: &PgPool, name: &str) -> sqlx::Result<Option<String>> {
    sqlx::query_scalar!(
        "SELECT canonical_id FROM vulnerabilities
         WHERE canonical_id = $1 OR id = $1 OR $1 = ANY (cve_ids)
         ORDER BY canonical_id = $1 DESC, id = $1 DESC, withdrawn, id
         LIMIT 1",
        name
    )
    .fetch_optional(db)
    .await
}

/// Recomputes every vulnerability's name, then moves analyses and sent alerts from old names
/// to new ones. Returns the number of advisories renamed.
pub async fn regroup(db: &PgPool) -> sqlx::Result<usize> {
    let mut tx = db.begin().await?;
    sqlx::query!("SELECT pg_advisory_xact_lock($1)", LOCK)
        .execute(&mut *tx)
        .await?;
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(crate::alerts::LOCK_KEY)
        .execute(&mut *tx)
        .await?;
    // Withdrawn advisories are left out: they match nothing, and must not link groups
    let rows = sqlx::query!(
        "SELECT id, cve_ids, canonical_id FROM vulnerabilities WHERE NOT withdrawn ORDER BY id"
    )
    .fetch_all(&mut *tx)
    .await?;
    let members: Vec<Member> = rows
        .iter()
        .map(|r| Member {
            id: &r.id,
            cve_ids: &r.cve_ids,
            canonical_id: &r.canonical_id,
        })
        .collect();
    let new_names = names(&members);

    let mut ids = Vec::new();
    let mut renamed = Vec::new();
    let mut moves: Vec<(String, String)> = Vec::new();
    for (m, name) in members.iter().zip(new_names) {
        if m.canonical_id != name {
            let pair = (m.canonical_id.to_owned(), name.clone());
            if !moves.contains(&pair) {
                moves.push(pair);
            }
            ids.push(m.id.to_owned());
            renamed.push(name);
        }
    }
    if ids.is_empty() {
        return Ok(0);
    }
    sqlx::query!(
        "UPDATE vulnerabilities v SET canonical_id = r.name
         FROM UNNEST($1::text[], $2::text[]) AS r (id, name) WHERE v.id = r.id",
        &ids,
        &renamed,
    )
    .execute(&mut *tx)
    .await?;

    for (old, new) in &moves {
        tracing::info!(from = %old, to = %new, "vulnerability renamed");
        let old_rows = sqlx::query!(
            r#"SELECT project_id, state, justification, detail, evidence,
                      extract(epoch FROM updated_at)::float8 AS "updated_at!"
               FROM analyses WHERE vuln_key = $1"#,
            old
        )
        .fetch_all(&mut *tx)
        .await?;
        for o in old_rows {
            let incoming = Decision {
                state: o.state,
                justification: o.justification,
                detail: o.detail,
                updated_at: o.updated_at,
            };
            let kept = sqlx::query!(
                r#"SELECT state, justification, detail,
                          extract(epoch FROM updated_at)::float8 AS "updated_at!"
                   FROM analyses WHERE project_id = $1 AND vuln_key = $2"#,
                o.project_id,
                new
            )
            .fetch_optional(&mut *tx)
            .await?
            .map(|k| Decision {
                state: k.state,
                justification: k.justification,
                detail: k.detail,
                updated_at: k.updated_at,
            });
            let d = match kept {
                Some(kept) => merge(kept, new, incoming, old),
                None => incoming,
            };
            sqlx::query!(
                "INSERT INTO analyses (project_id, vuln_key, state, justification, detail, updated_at)
                 VALUES ($1, $2, $3, $4, $5, to_timestamp($6))
                 ON CONFLICT (project_id, vuln_key) DO UPDATE SET state = EXCLUDED.state,
                     justification = EXCLUDED.justification, detail = EXCLUDED.detail,
                     updated_at = EXCLUDED.updated_at",
                o.project_id,
                new,
                d.state,
                d.justification,
                d.detail,
                d.updated_at,
            )
            .execute(&mut *tx)
            .await?;
            sqlx::query("UPDATE analyses SET evidence = $3 WHERE project_id = $1 AND vuln_key = $2 AND evidence IS NULL AND $3 = finding_evidence($1, $2)")
                .bind(o.project_id).bind(new).bind(o.evidence).execute(&mut *tx).await?;
        }
        sqlx::query("SELECT merge_finding_episodes($1, $2)")
            .bind(old)
            .bind(new)
            .execute(&mut *tx)
            .await?;
    }

    // Old names no advisory carries any more (a split keeps them for the other part)
    let olds: Vec<String> = moves.iter().map(|(o, _)| o.clone()).collect();
    sqlx::query!(
        "DELETE FROM analyses WHERE vuln_key = ANY($1)
             AND NOT EXISTS (SELECT 1 FROM vulnerabilities WHERE canonical_id = vuln_key)",
        &olds
    )
    .execute(&mut *tx)
    .await?;
    sqlx::query!(
        "DELETE FROM alerts WHERE vuln_key = ANY($1)
             AND NOT EXISTS (SELECT 1 FROM vulnerabilities WHERE canonical_id = vuln_key)",
        &olds
    )
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(ids.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn member<'a>(id: &'a str, cves: &'a [String], canonical: &'a str) -> Member<'a> {
        Member {
            id,
            cve_ids: cves,
            canonical_id: canonical,
        }
    }

    fn cves(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn advisories_sharing_a_cve_transitively_form_one_vulnerability() {
        let a = cves(&["CVE-2026-1", "CVE-2026-2"]);
        let b = cves(&["CVE-2026-2"]);
        let c = cves(&[]);
        let names = names(&[
            member("GHSA-a", &a, "CVE-2026-1"),
            member("GHSA-b", &b, "CVE-2026-2"),
            member("RUSTSEC-c", &c, "RUSTSEC-c"),
        ]);
        assert_eq!(names, ["CVE-2026-1", "CVE-2026-1", "RUSTSEC-c"]);
    }

    #[test]
    fn names_stay_stable_and_new_cves_rename() {
        // Two members already named CVE-2026-20000: kept, although CVE-2026-9999 is older
        let a = cves(&["CVE-2026-9999", "CVE-2026-20000"]);
        let b = cves(&["CVE-2026-20000"]);
        let c = cves(&["CVE-2026-20000"]);
        let stable = names(&[
            member("A", &a, "CVE-2026-20000"),
            member("B", &b, "CVE-2026-20000"),
            member("C", &c, "CVE-2026-20000"),
        ]);
        assert!(stable.iter().all(|n| n == "CVE-2026-20000"));

        // An advisory without CVE gains one: named by it, the oldest in numeric order
        let gained = cves(&["CVE-2026-10000", "CVE-2026-9999"]);
        assert_eq!(
            names(&[member("GHSA-x", &gained, "GHSA-x")]),
            ["CVE-2026-9999"]
        );
    }

    fn decision(state: &str, detail: Option<&str>, at: f64) -> Decision {
        Decision {
            state: state.into(),
            justification: None,
            detail: detail.map(String::from),
            updated_at: at,
        }
    }

    #[test]
    fn merging_never_hides_a_finding() {
        // The unsuppressed analysis wins even when older
        let kept = decision("exploitable", Some("reachable from the API"), 1.0);
        let incoming = decision("not_affected", Some("not used"), 2.0);
        let d = merge(kept, "CVE-2026-1", incoming, "GHSA-aaaa");
        assert_eq!(d.state, "exploitable");
        assert_eq!(
            d.detail.as_deref(),
            Some(
                "reachable from the API\nMerged: analysis under GHSA-aaaa was not_affected: not used"
            )
        );

        let kept = decision("resolved", None, 1.0);
        let incoming = decision("in_triage", None, 0.5);
        let d = merge(kept, "CVE-2026-1", incoming, "GHSA-bbbb");
        assert_eq!(d.state, "in_triage");
        assert_eq!(
            d.detail.as_deref(),
            Some("Merged: analysis under CVE-2026-1 was resolved")
        );

        // Both suppress: the most recent wins
        let d = merge(
            decision("resolved", None, 3.0),
            "CVE-2026-1",
            decision("false_positive", None, 4.0),
            "GHSA-cccc",
        );
        assert_eq!(d.state, "false_positive");
    }
}
