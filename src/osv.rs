//! [OSV.dev](https://osv.dev) client. OSV aggregates many databases (GitHub Advisories, PyPI,
//! RustSec, Go, Debian, Alpine, …) in one schema, which is also Tocsin's internal format.
use crate::vulns::{VulnRef, VulnSource};
use anyhow::{Context, bail};
use reqwest::StatusCode;
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::HashMap;

/// OSV's limit of queries per batch request.
const BATCH_SIZE: usize = 1000;

#[derive(Clone)]
pub struct Osv {
    client: reqwest::Client,
    base_url: String,
}

#[derive(Deserialize)]
struct BatchResponse {
    results: Vec<BatchResult>,
}

#[derive(Deserialize)]
struct BatchResult {
    #[serde(default)]
    vulns: Vec<BatchVuln>,
    next_page_token: Option<String>,
}

#[derive(Deserialize)]
struct BatchVuln {
    id: String,
    #[serde(default)]
    modified: String,
}

impl Osv {
    pub fn new(client: reqwest::Client, base_url: &str) -> Self {
        Self {
            client,
            base_url: base_url.trim_end_matches('/').to_owned(),
        }
    }

    /// One `querybatch` call. OSV rejects the whole batch when one purl is invalid and names
    /// its index: that purl is dropped (with a warning) and the batch is retried.
    async fn query_batch(
        &self,
        queries: &mut Vec<(String, Option<String>)>,
    ) -> anyhow::Result<Vec<BatchResult>> {
        loop {
            let body = json!({
                "queries": queries.iter().map(|(purl, page_token)| {
                    let mut q = json!({ "package": { "purl": purl } });
                    if let Some(token) = page_token {
                        q["page_token"] = json!(token);
                    }
                    q
                }).collect::<Vec<_>>()
            });
            let res = self
                .client
                .post(format!("{}/v1/querybatch", self.base_url))
                .json(&body)
                .send()
                .await
                .context("OSV query failed")?;
            if res.status() == StatusCode::BAD_REQUEST {
                let message = res.text().await.unwrap_or_default();
                let index = message
                    .split("error in query at index ")
                    .nth(1)
                    .and_then(|rest| rest.split(|c: char| !c.is_ascii_digit()).next())
                    .and_then(|i| i.parse::<usize>().ok())
                    .filter(|&i| i < queries.len());
                match index {
                    Some(i) => {
                        let (purl, _) = queries.remove(i);
                        tracing::warn!("OSV rejected purl {purl:?}: skipped");
                        if queries.is_empty() {
                            return Ok(Vec::new());
                        }
                        continue;
                    }
                    None => bail!("OSV rejected the query: {message}"),
                }
            }
            let res: BatchResponse = res
                .error_for_status()
                .context("OSV query failed")?
                .json()
                .await
                .context("invalid OSV response")?;
            if res.results.len() != queries.len() {
                bail!(
                    "OSV returned {} results for {} queries",
                    res.results.len(),
                    queries.len()
                );
            }
            return Ok(res.results);
        }
    }
}

impl VulnSource for Osv {
    async fn affected(&self, purls: &[String]) -> anyhow::Result<HashMap<String, Vec<VulnRef>>> {
        let mut out: HashMap<String, Vec<VulnRef>> =
            purls.iter().map(|p| (p.clone(), Vec::new())).collect();
        for chunk in purls.chunks(BATCH_SIZE) {
            let mut queries: Vec<(String, Option<String>)> =
                chunk.iter().map(|p| (p.clone(), None)).collect();
            // A purl with many advisories is paginated: query again with its page token
            while !queries.is_empty() {
                let requested: Vec<String> = queries.iter().map(|(p, _)| p.clone()).collect();
                let results = self.query_batch(&mut queries).await?;
                for p in requested {
                    if !queries.iter().any(|(q, _)| *q == p) {
                        out.remove(&p);
                    }
                }
                let mut next = Vec::new();
                for ((purl, _), result) in queries.iter().zip(results) {
                    out.get_mut(purl).expect("queried purls are keys").extend(
                        result.vulns.into_iter().map(|v| VulnRef {
                            id: v.id,
                            modified: v.modified,
                        }),
                    );
                    if let Some(token) = result.next_page_token {
                        next.push((purl.clone(), Some(token)));
                    }
                }
                queries = next;
            }
        }
        Ok(out)
    }

    async fn advisory(&self, id: &str) -> anyhow::Result<Value> {
        self.client
            .get(format!("{}/v1/vulns/{id}", self.base_url))
            .send()
            .await
            .and_then(|r| r.error_for_status())
            .with_context(|| format!("cannot fetch advisory {id} from OSV"))?
            .json()
            .await
            .with_context(|| format!("invalid advisory {id} from OSV"))
    }
}
