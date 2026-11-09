//! Tests across modules: API and dashboard flows against fake OSV, CISA, EPSS and Google Chat
//! servers.
use crate::{api::AppState, config::Config, jobs};
use axum::{
    Json, Router,
    body::Body,
    extract::{Path, State},
    http::{Request, StatusCode},
    response::IntoResponse,
    routing::{get, post},
};
use serde_json::{Value, json};
use sqlx::PgPool;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};
use tower::ServiceExt;

const LOG4J: &str = "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1";
const LODASH: &str = "pkg:npm/lodash@4.17.20";

/// Advisories served by the fake OSV, in the OSV schema.
fn advisory(id: &str) -> Value {
    match id {
        // Two advisories for Log4Shell: grouped into one finding, CVE-2021-44228
        "GHSA-jfh8-c2jp-5v3q" => json!({
            "id": id, "aliases": ["CVE-2021-44228"], "modified": "2026-01-01T00:00:00Z",
            "summary": "Remote code injection in Log4j",
            "database_specific": { "severity": "CRITICAL" },
            "references": [{ "url": "https://logging.apache.org/security.html" }, { "url": "javascript:alert(1)" }]
        }),
        "CVE-2021-44228" => json!({
            "id": id, "aliases": ["GHSA-jfh8-c2jp-5v3q"], "modified": "2026-01-01T00:00:00Z",
            "details": "Apache Log4j2 <script>JNDI</script> features…",
            "severity": [{ "type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H" }]
        }),
        "GHSA-35jh-r3h4-6jhm" => json!({
            "id": id, "aliases": ["CVE-2021-23337"], "modified": "2026-01-01T00:00:00Z",
            "summary": "Command Injection in lodash", "database_specific": { "severity": "HIGH" }
        }),
        "GHSA-29mw-wpgm-hmr9" => json!({
            "id": id, "aliases": ["CVE-2020-28500"], "modified": "2026-01-01T00:00:00Z",
            "summary": "ReDoS in lodash", "database_specific": { "severity": "MODERATE" }
        }),
        _ => Value::Null,
    }
}

#[derive(Default)]
struct Calls {
    batches: AtomicUsize,
    fetches: AtomicUsize,
    chat: Mutex<Vec<String>>,
    chat_fails: std::sync::atomic::AtomicBool,
    kev: Mutex<Value>,
    /// EPSS file served, as CSV text (gzipped on the wire)
    epss: Mutex<String>,
    epss_downloads: AtomicUsize,
}

async fn querybatch(
    State(calls): State<Arc<Calls>>,
    Json(body): Json<Value>,
) -> axum::response::Response {
    calls.batches.fetch_add(1, Ordering::SeqCst);
    let mut results = Vec::new();
    for (i, q) in body["queries"].as_array().unwrap().iter().enumerate() {
        let purl = q["package"]["purl"].as_str().unwrap();
        let page = q["page_token"].as_str();
        if purl.starts_with("pkg:bad/") {
            return (
                StatusCode::BAD_REQUEST,
                format!(r#"{{"code":3,"message":"error in query at index {i}: invalid purl"}}"#),
            )
                .into_response();
        }
        let vuln = |id: &str| json!({ "id": id, "modified": "2026-01-01T00:00:00Z" });
        results.push(match (purl, page) {
            (LOG4J, _) => json!({ "vulns": [vuln("GHSA-jfh8-c2jp-5v3q"), vuln("CVE-2021-44228")] }),
            // Paginated: the second advisory comes with the page token
            (LODASH, None) => {
                json!({ "vulns": [vuln("GHSA-35jh-r3h4-6jhm")], "next_page_token": "p2" })
            }
            (LODASH, Some("p2")) => json!({ "vulns": [vuln("GHSA-29mw-wpgm-hmr9")] }),
            _ => json!({}),
        });
    }
    Json(json!({ "results": results })).into_response()
}

async fn vuln(State(calls): State<Arc<Calls>>, Path(id): Path<String>) -> axum::response::Response {
    calls.fetches.fetch_add(1, Ordering::SeqCst);
    match advisory(&id) {
        Value::Null => StatusCode::NOT_FOUND.into_response(),
        mut doc => {
            // Like OSV: advisories carry nanoseconds, the batch endpoint microseconds
            doc["modified"] = json!("2026-01-01T00:00:00.000000123Z");
            Json(doc).into_response()
        }
    }
}

async fn chat(State(calls): State<Arc<Calls>>, Json(body): Json<Value>) -> StatusCode {
    if calls.chat_fails.load(Ordering::SeqCst) {
        return StatusCode::INTERNAL_SERVER_ERROR;
    }
    calls
        .chat
        .lock()
        .unwrap()
        .push(body["text"].as_str().unwrap().to_owned());
    StatusCode::OK
}

async fn kev_feed(State(calls): State<Arc<Calls>>) -> Json<Value> {
    Json(calls.kev.lock().unwrap().clone())
}

/// Like the EPSS server: a gzipped CSV with an ETag, honoring If-None-Match.
async fn epss_feed(
    State(calls): State<Arc<Calls>>,
    headers: axum::http::HeaderMap,
) -> axum::response::Response {
    use std::io::Write;
    let text = calls.epss.lock().unwrap().clone();
    let etag = format!("\"{}\"", crate::api::sha256_hex(&text));
    if headers
        .get("if-none-match")
        .is_some_and(|v| v == etag.as_str())
    {
        return StatusCode::NOT_MODIFIED.into_response();
    }
    calls.epss_downloads.fetch_add(1, Ordering::SeqCst);
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gz.write_all(text.as_bytes()).unwrap();
    (
        [("etag", etag), ("content-type", "application/gzip".into())],
        gz.finish().unwrap(),
    )
        .into_response()
}

fn epss_file(rows: &[(&str, f32, f32)]) -> String {
    let mut text =
        "#model_version:v2026.06.15,score_date:2026-11-04T12:03:12Z\ncve,epss,percentile\n"
            .to_owned();
    for (cve, score, percentile) in rows {
        text.push_str(&format!("{cve},{score},{percentile}\n"));
    }
    text
}

fn kev_catalog(cves: &[&str]) -> Value {
    json!({
        "catalogVersion": format!("v{}", cves.len()),
        "vulnerabilities": cves.iter().map(|cve| json!({
            "cveID": cve, "vendorProject": "Apache", "product": "Lib", "vulnerabilityName": "flaw",
            "dateAdded": "2026-10-30", "knownRansomwareCampaignUse": "Known"
        })).collect::<Vec<_>>()
    })
}

/// Fake external services, and the app wired to them.
struct Harness {
    app: Router,
    st: AppState,
    calls: Arc<Calls>,
}

async fn harness(db: PgPool, tweak: impl FnOnce(&mut Config)) -> Harness {
    let calls = Arc::new(Calls::default());
    *calls.kev.lock().unwrap() = kev_catalog(&[]);
    let fakes = Router::new()
        .route("/v1/querybatch", post(querybatch))
        .route("/v1/vulns/{id}", get(vuln))
        .route("/chat", post(chat))
        .route("/kev.json", get(kev_feed))
        .route("/epss.csv.gz", get(epss_feed))
        .with_state(calls.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, fakes).await.unwrap() });

    let mut config = Config::for_tests();
    config.osv_url = base.clone();
    config.kev_url = format!("{base}/kev.json");
    config.epss_url = format!("{base}/epss.csv.gz");
    config.google_chat_webhook = Some(format!("{base}/chat"));
    config.match_on_push = true;
    tweak(&mut config);
    let st = AppState::for_tests(db, config);
    Harness {
        app: crate::api::router(st.clone()),
        st,
        calls,
    }
}

impl Harness {
    async fn call(
        &self,
        method: &str,
        uri: &str,
        token: Option<&str>,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        let (status, text) = self.raw(method, uri, token, body).await;
        (
            status,
            serde_json::from_str(&text).unwrap_or(Value::String(text)),
        )
    }

    async fn raw(
        &self,
        method: &str,
        uri: &str,
        token: Option<&str>,
        body: Option<Value>,
    ) -> (StatusCode, String) {
        let mut req = Request::builder().method(method).uri(uri);
        if let Some(t) = token {
            req = req.header("authorization", format!("Bearer {t}"));
        }
        let req = match body {
            Some(b) => req
                .header("content-type", "application/json")
                .body(Body::from(b.to_string())),
            None => req.body(Body::empty()),
        }
        .unwrap();
        self.send(req).await
    }

    async fn send(&self, req: Request<Body>) -> (StatusCode, String) {
        let res = self.app.clone().oneshot(req).await.unwrap();
        let status = res.status();
        let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
            .await
            .unwrap();
        (status, String::from_utf8(bytes.to_vec()).unwrap())
    }

    /// Creates a project; returns its token.
    async fn project(&self, name: &str) -> String {
        let (status, body) = self
            .call(
                "POST",
                "/api/projects",
                Some("admin"),
                Some(json!({ "name": name })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        body["token"].as_str().unwrap().to_owned()
    }

    async fn push(&self, token: &str, version: &str, purls: &[&str]) -> Value {
        let (status, body) = self
            .call(
                "POST",
                &format!("/api/sboms?version={version}"),
                Some(token),
                Some(bom(purls)),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        body
    }

    fn chat(&self) -> Vec<String> {
        self.calls.chat.lock().unwrap().clone()
    }
}

fn bom(purls: &[&str]) -> Value {
    json!({
        "bomFormat": "CycloneDX", "specVersion": "1.6",
        "components": purls.iter().map(|p| json!({ "purl": p, "licenses": [{ "license": { "id": "Apache-2.0" } }] })).collect::<Vec<_>>()
    })
}

#[sqlx::test]
async fn project_creation_and_sbom_ingestion(db: PgPool) {
    let h = harness(db.clone(), |c| c.match_on_push = false).await;

    let new = json!({ "name": "demo" });
    let (status, _) = h
        .call("POST", "/api/projects", Some("nope"), Some(new.clone()))
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let token = h.project("demo").await;
    let (status, _) = h
        .call("POST", "/api/projects", Some("admin"), Some(new))
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
    let (status, _) = h
        .call(
            "POST",
            "/api/projects",
            Some("admin"),
            Some(json!({ "name": "a/b" })),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let doc = json!({
        "bomFormat": "CycloneDX",
        "metadata": { "component": { "name": "demo", "version": "1.2.0" } },
        "components": [
            { "purl": "pkg:maven/org.a/b@1.0" },
            { "purl": "pkg:npm/x@2.0", "components": [{ "purl": "pkg:npm/y@3.0" }] },
            { "purl": "pkg:npm/x@2.0" },
            { "name": "no-purl" }
        ]
    });
    let (status, _) = h
        .call("POST", "/api/sboms", Some("wrong"), Some(doc.clone()))
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, body) = h
        .call("POST", "/api/sboms", Some(&token), Some(doc.clone()))
        .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(
        (body["version"].as_str(), body["components"].as_i64()),
        (Some("1.2.0"), Some(3))
    );
    assert_eq!(body["matching"], "disabled");

    // Re-push of the same release replaces it instead of duplicating
    h.call("POST", "/api/sboms", Some(&token), Some(doc)).await;
    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM components")
        .fetch_one(&db)
        .await
        .unwrap();
    assert_eq!(rows, 3);

    let (status, _) = h
        .call(
            "POST",
            "/api/sboms",
            Some(&token),
            Some(json!({ "bomFormat": "CycloneDX", "components": [] })),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[sqlx::test]
async fn push_matches_groups_advisories_and_alerts_once(db: PgPool) {
    let h = harness(db.clone(), |_| {}).await;
    sqlx::query("INSERT INTO kev_entries (cve_id, vendor_project, product, name, date_added, known_ransomware, data)
                 VALUES ('CVE-2021-44228', 'Apache', 'Log4j2', 'Log4Shell', '2021-12-10', true, '{}')")
        .execute(&db).await.unwrap();
    let token = h.project("shop").await;

    let body = h
        .push(
            &token,
            "1.0.0",
            &[LOG4J, LODASH, "pkg:npm/left-pad", "pkg:bad/x@1"],
        )
        .await;
    assert_eq!(body["matching"], "done");
    // Log4Shell (two advisories, one finding) + two lodash flaws (one on the second OSV page)
    assert_eq!(
        (
            body["findings"].as_i64(),
            body["kev"].as_i64(),
            body["alerted"].as_i64()
        ),
        (Some(3), Some(1), Some(1))
    );

    let chat = h.chat();
    assert_eq!(chat.len(), 1);
    assert!(chat[0].contains("CVE-2021-44228") && chat[0].contains("actively exploited"));
    assert!(chat[0].contains("<https://tocsin.example/projects/shop|shop>"));
    assert!(
        !chat[0].contains("CVE-2021-23337"),
        "only KEV alerts by default"
    );

    let (status, findings) = h
        .call("GET", "/api/projects/shop/findings", Some(&token), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    let f = &findings["findings"][0];
    assert_eq!(
        (f["id"].as_str(), f["severity"].as_str(), f["kev"].as_bool()),
        (Some("CVE-2021-44228"), Some("critical"), Some(true))
    );
    assert_eq!(
        f["advisories"],
        json!(["CVE-2021-44228", "GHSA-jfh8-c2jp-5v3q"])
    );
    assert_eq!(f["cvss"].as_f64(), Some(10.0));
    assert_eq!(findings["findings"][1]["id"], "CVE-2021-23337");
    assert_eq!(findings["findings"][2]["severity"], "medium");

    // Same release again: purls were just matched, nothing re-queried, nothing re-alerted
    let batches = h.calls.batches.load(Ordering::SeqCst);
    let body = h.push(&token, "1.0.1", &[LOG4J, LODASH]).await;
    assert_eq!(body["alerted"], 0);
    assert_eq!(h.calls.batches.load(Ordering::SeqCst), batches);
    assert_eq!(h.chat().len(), 1);

    // A refresh re-queries, but advisories that did not change are not downloaded again
    let fetches = h.calls.fetches.load(Ordering::SeqCst);
    let (status, result) = h
        .call("POST", "/api/jobs/refresh", Some("admin"), None)
        .await;
    assert_eq!(status, StatusCode::OK, "{result}");
    assert_eq!(h.calls.fetches.load(Ordering::SeqCst), fetches);
    assert_eq!(result["alerted"], 0);

    // Another project with the same component gets its own alert
    let other = h.project("blog").await;
    assert_eq!(h.push(&other, "2.0", &[LOG4J]).await["alerted"], 1);

    let metrics: (i32, i32, i32) = sqlx::query_as(
        "SELECT critical, high, kev FROM project_metrics m JOIN projects p ON p.id = m.project_id WHERE p.name = 'shop'")
        .fetch_one(&db).await.unwrap();
    assert_eq!(metrics, (1, 1, 1));
}

#[sqlx::test]
async fn new_kev_entry_and_severity_rule_alert(db: PgPool) {
    let h = harness(db.clone(), |c| {
        c.alert_min_severity = Some(crate::vulns::Severity::Critical)
    })
    .await;
    let token = h.project("shop").await;

    // Log4Shell is critical: alerted by the severity rule, though not (yet) in KEV
    assert_eq!(h.push(&token, "1.0", &[LOG4J, LODASH]).await["alerted"], 1);
    assert!(h.chat()[0].contains("CVE-2021-44228") && !h.chat()[0].contains("KEV"));

    // lodash's CVE enters the KEV catalog: the sync job alerts on it
    *h.calls.kev.lock().unwrap() = kev_catalog(&["CVE-2021-23337"]);
    let result = jobs::kev_sync(&h.st).await.unwrap();
    assert_eq!(result["alerted"], 1);
    let last = h.chat().pop().unwrap();
    assert!(last.contains("CVE-2021-23337") && last.contains("KEV"));

    // Delivery failure: not recorded, retried later
    *h.calls.kev.lock().unwrap() = kev_catalog(&["CVE-2021-23337", "CVE-2020-28500"]);
    h.calls.chat_fails.store(true, Ordering::SeqCst);
    assert_eq!(jobs::kev_sync(&h.st).await.unwrap()["alerted"], 0);
    h.calls.chat_fails.store(false, Ordering::SeqCst);
    assert_eq!(jobs::alert(&h.st, None).await.unwrap(), 1);
    assert!(h.chat().pop().unwrap().contains("CVE-2020-28500"));
}

#[sqlx::test]
async fn epss_scores_findings_policies_and_alerts(db: PgPool) {
    let h = harness(db.clone(), |c| c.alert_min_epss = Some(0.5)).await;
    let token = h.project("shop").await;
    assert_eq!(h.push(&token, "1.0", &[LOG4J, LODASH]).await["alerted"], 0);

    *h.calls.epss.lock().unwrap() = epss_file(&[
        ("CVE-2021-44228", 0.94, 0.999),
        ("CVE-2021-23337", 0.02, 0.8),
        ("CVE-2099-0001", 0.9, 0.99), // affects no project: not kept
    ]);
    let result = jobs::epss_sync(&h.st).await.unwrap();
    assert_eq!(
        result,
        json!({
            "epss": { "scores": "synced", "model": "v2026.06.15", "date": "2026-11-04",
                      "scored": 2, "total": 3 },
            "alerted": 1,
        })
    );
    let chat = h.chat();
    assert_eq!(chat.len(), 1);
    assert!(chat[0].contains("CVE-2021-44228") && chat[0].contains("EPSS 94%"));
    assert!(!chat[0].contains("CVE-2021-23337"), "below the threshold");

    // Unchanged file, no new advisory: conditional request, nothing downloaded or re-alerted
    assert_eq!(
        jobs::epss_sync(&h.st).await.unwrap(),
        json!({ "epss": { "scores": "unchanged" }, "alerted": 0 })
    );
    assert_eq!(h.calls.epss_downloads.load(Ordering::SeqCst), 1);
    // Advisories stored since the download: the file is downloaded again for their CVEs
    sqlx::query("UPDATE vulnerabilities SET fetched_at = now()")
        .execute(&db)
        .await
        .unwrap();
    assert_eq!(jobs::epss_sync(&h.st).await.unwrap()["alerted"], 0);
    assert_eq!(h.calls.epss_downloads.load(Ordering::SeqCst), 2);

    // Findings: KEV, then EPSS, then severity
    let (_, findings) = h
        .call("GET", "/api/projects/shop/findings", Some(&token), None)
        .await;
    let ids: Vec<&str> = findings["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, ["CVE-2021-44228", "CVE-2021-23337", "CVE-2020-28500"]);
    assert_eq!(
        findings["findings"][0]["epss"],
        json!({ "score": 0.94, "percentile": 0.999 })
    );
    assert_eq!(findings["findings"][2]["epss"], Value::Null);

    // EPSS policy: "50%" is stored as 0.5
    let (status, policy) = h
        .call(
            "POST",
            "/api/policies",
            Some("admin"),
            Some(json!({ "name": "Likely exploited", "kind": "epss", "value": "50%" })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{policy}");
    assert_eq!(policy["value"], "0.5");
    let (status, _) = h
        .call(
            "POST",
            "/api/policies",
            Some("admin"),
            Some(json!({ "name": "Bad", "kind": "epss", "value": "1.5" })),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (_, violations) = h
        .call("GET", "/api/projects/shop/violations", Some(&token), None)
        .await;
    let violations = violations.as_array().unwrap();
    assert_eq!(violations.len(), 1, "{violations:?}");
    assert_eq!(violations[0]["subject"], "CVE-2021-44228");
    assert_eq!(violations[0]["detail"], "Critical, EPSS 94.0%");

    // Dashboard
    let (_, html) = h.raw("GET", "/projects/shop", None, None).await;
    assert!(html.contains("94%") && html.contains("https://www.first.org/epss"));
    let (_, html) = h.raw("GET", "/vulns/CVE-2021-44228", None, None).await;
    assert!(html.contains("percentile 99.9"));
    let (_, html) = h.raw("GET", "/", None, None).await;
    assert!(html.contains("2 scored CVEs, scores of 2026-11-04"));
    let (_, html) = h.raw("GET", "/alerts", None, None).await;
    assert!(html.contains("EPSS score of 50% or higher") && html.contains(">EPSS<"));
}

#[sqlx::test]
async fn audit_suppresses_and_vex_round_trips(db: PgPool) {
    let h = harness(db.clone(), |c| c.google_chat_webhook = None).await;
    let shop = h.project("shop").await;
    let blog = h.project("blog").await;
    h.push(&shop, "1.0", &[LOG4J, LODASH]).await;
    h.push(&blog, "1.0", &[LOG4J]).await;

    // Recorded against an advisory ID: mapped to the flaw's CVE
    let (status, body) = h
        .call("PUT", "/api/projects/shop/analyses/GHSA-jfh8-c2jp-5v3q", Some(&shop),
              Some(json!({ "state": "not_affected", "justification": "code_not_reachable", "detail": "JNDI disabled" })))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["id"], "CVE-2021-44228");
    let (status, _) = h
        .call(
            "PUT",
            "/api/projects/shop/analyses/CVE-2021-23337",
            Some(&shop),
            Some(json!({ "state": "nope" })),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    // A project token cannot audit another project
    let (status, _) = h
        .call(
            "PUT",
            "/api/projects/blog/analyses/CVE-2021-44228",
            Some(&shop),
            Some(json!({ "state": "resolved" })),
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let ids = |v: &Value| {
        v["findings"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| f["id"].as_str().unwrap().to_owned())
            .collect::<Vec<_>>()
    };
    let (_, findings) = h
        .call("GET", "/api/projects/shop/findings", Some(&shop), None)
        .await;
    assert_eq!(ids(&findings), ["CVE-2021-23337", "CVE-2020-28500"]);
    let (_, all) = h
        .call(
            "GET",
            "/api/projects/shop/findings?suppressed=true",
            Some("admin"),
            None,
        )
        .await;
    assert_eq!(ids(&all).len(), 3);

    let (status, vex) = h
        .call("GET", "/api/projects/shop/vex", Some(&shop), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(vex["bomFormat"], "CycloneDX");
    let log4shell = vex["vulnerabilities"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["id"] == "CVE-2021-44228")
        .unwrap();
    assert_eq!(log4shell["analysis"]["state"], "not_affected");
    assert_eq!(log4shell["affects"][0]["ref"], LOG4J);

    // Importing shop's VEX into blog applies the same decision
    let (status, stats) = h
        .call("POST", "/api/projects/blog/vex", Some(&blog), Some(vex))
        .await;
    assert_eq!(status, StatusCode::OK, "{stats}");
    assert_eq!(stats["imported"], 1);
    let (_, findings) = h
        .call("GET", "/api/projects/blog/findings", Some(&blog), None)
        .await;
    assert!(ids(&findings).is_empty());

    let (status, _) = h
        .call(
            "DELETE",
            "/api/projects/blog/analyses/CVE-2021-44228",
            Some(&blog),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (_, findings) = h
        .call("GET", "/api/projects/blog/findings", Some(&blog), None)
        .await;
    assert_eq!(ids(&findings), ["CVE-2021-44228"]);
}

#[sqlx::test]
async fn policies_report_violations(db: PgPool) {
    let h = harness(db.clone(), |c| c.google_chat_webhook = None).await;
    let token = h.project("shop").await;
    let doc = json!({
        "bomFormat": "CycloneDX",
        "components": [
            { "purl": LOG4J, "licenses": [{ "license": { "id": "Apache-2.0" } }] },
            { "purl": "pkg:npm/gpl-thing@1", "licenses": [{ "expression": "(GPL-3.0-only OR MIT)" }] }
        ]
    });
    h.call("POST", "/api/sboms?version=1", Some(&token), Some(doc))
        .await;

    for (name, kind, value) in [
        ("No GPL-3", "license", "gpl-3.0-only"),
        ("No critical", "severity", "Critical"),
        ("No KEV", "kev", ""),
    ] {
        let (status, body) = h
            .call(
                "POST",
                "/api/policies",
                Some("admin"),
                Some(json!({ "name": name, "kind": kind, "value": value })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
    }
    let (status, _) = h
        .call(
            "POST",
            "/api/policies",
            Some("admin"),
            Some(json!({ "name": "x", "kind": "severity", "value": "huge" })),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = h
        .call(
            "POST",
            "/api/policies",
            Some(&token),
            Some(json!({ "name": "x", "kind": "kev" })),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let (_, violations) = h
        .call("GET", "/api/projects/shop/violations", Some(&token), None)
        .await;
    let v: Vec<(String, String)> = violations
        .as_array()
        .unwrap()
        .iter()
        .map(|v| {
            (
                v["policy"].as_str().unwrap().into(),
                v["subject"].as_str().unwrap().into(),
            )
        })
        .collect();
    // Log4Shell is critical but not in KEV here; the license matches inside the expression
    assert_eq!(
        v,
        [
            ("No GPL-3".to_owned(), "pkg:npm/gpl-thing@1".to_owned()),
            ("No critical".into(), "CVE-2021-44228".into())
        ]
    );

    let (_, list) = h.call("GET", "/api/policies", Some("admin"), None).await;
    let id = list[0]["id"].as_i64().unwrap();
    let (status, _) = h
        .call(
            "DELETE",
            &format!("/api/policies/{id}"),
            Some("admin"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (_, violations) = h
        .call("GET", "/api/projects/shop/violations", Some("admin"), None)
        .await;
    assert_eq!(violations.as_array().unwrap().len(), 1);
}

#[sqlx::test]
async fn gzip_upload_jobs_and_dashboard_auth(db: PgPool) {
    let h = harness(db.clone(), |c| {
        c.dashboard_public = false;
        c.google_chat_webhook = None;
    })
    .await;
    let token = h.project("shop").await;

    // Compressed upload
    use flate2::{Compression, write::GzEncoder};
    use std::io::Write;
    let mut gz = GzEncoder::new(Vec::new(), Compression::default());
    gz.write_all(bom(&[LODASH]).to_string().as_bytes()).unwrap();
    let req = Request::post("/api/sboms?version=1")
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .header("content-encoding", "gzip")
        .body(Body::from(gz.finish().unwrap()))
        .unwrap();
    let (status, body) = h.send(req).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert!(body.contains(r#""components":1"#));

    // Jobs: admin only
    let (status, _) = h
        .call("POST", "/api/jobs/kev-sync", Some(&token), None)
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = h.call("POST", "/api/jobs/nope", Some("admin"), None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, result) = h
        .call("POST", "/api/jobs/kev-sync", Some("admin"), None)
        .await;
    assert_eq!(status, StatusCode::OK, "{result}");
    assert_eq!(result["kev"]["catalog"], "synced");

    // Dashboard: admin token required, as Basic password or bearer; health stays open
    let (status, _) = h.raw("GET", "/", None, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = h.raw("GET", "/", Some(&token), None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = h.raw("GET", "/", Some("admin"), None).await;
    assert_eq!(status, StatusCode::OK);
    let basic = Request::get("/projects/shop")
        .header("authorization", "Basic dXNlcjphZG1pbg==")
        .body(Body::empty())
        .unwrap(); // user:admin
    assert_eq!(h.send(basic).await.0, StatusCode::OK);
    let (status, _) = h.raw("GET", "/health", None, None).await;
    assert_eq!(status, StatusCode::OK);
}

#[sqlx::test]
async fn dashboard_pages_render_and_escape(db: PgPool) {
    let h = harness(db.clone(), |c| c.google_chat_webhook = None).await;
    sqlx::query("INSERT INTO kev_entries (cve_id, vendor_project, product, name, date_added, known_ransomware, data)
                 VALUES ('CVE-2021-44228', 'Apache', 'Log4j2', 'Log4Shell', '2021-12-10', true,
                         '{\"notes\": \"https://logging.apache.org ; javascript:alert(1)\", \"cwes\": [\"CWE-917\"]}')")
        .execute(&db).await.unwrap();
    let token = h.project("shop").await;
    h.push(
        &token,
        "1.0",
        &[LOG4J, LODASH, "pkg:npm/<script>x</script>@1"],
    )
    .await;
    h.call(
        "POST",
        "/api/policies",
        Some("admin"),
        Some(json!({ "name": "No KEV", "kind": "kev" })),
    )
    .await;

    let (status, html) = h.raw("GET", "/", None, None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains(r#"href="/projects/shop""#) && html.contains("Actively exploited"));

    let (status, html) = h.raw("GET", "/projects/shop", None, None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains(r#"href="/vulns/CVE-2021-44228""#) && html.contains("Policy violations"));
    assert!(
        html.contains("pkg:npm/&lt;script&gt;x&lt;/script&gt;@1") && !html.contains("<script>")
    );

    let (status, html) = h.raw("GET", "/vulns?kev=on", None, None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("CVE-2021-44228") && !html.contains("CVE-2021-23337"));

    // By CVE or by advisory ID; feed texts escaped, only http(s) links
    for id in ["CVE-2021-44228", "GHSA-jfh8-c2jp-5v3q"] {
        let (status, html) = h.raw("GET", &format!("/vulns/{id}"), None, None).await;
        assert_eq!(status, StatusCode::OK);
        assert!(html.contains("GHSA-jfh8-c2jp-5v3q") && html.contains("Log4Shell"));
        assert!(html.contains("&lt;script&gt;JNDI") && !html.contains("<script>"));
        assert!(
            html.contains(r#"href="https://logging.apache.org/security.html""#)
                && !html.contains("javascript:")
        );
    }
    assert_eq!(
        h.raw("GET", "/vulns/CVE-1999-0001", None, None).await.0,
        StatusCode::NOT_FOUND
    );

    let (status, html) = h.raw("GET", "/kev/CVE-2021-44228", None, None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains(r#"href="/projects/shop""#) && !html.contains("javascript:"));
    assert!(html.contains(r#"href="https://cwe.mitre.org/data/definitions/917.html""#));
    let (_, html) = h.raw("GET", "/kev?affecting=on", None, None).await;
    assert!(html.contains("Showing 1–1 of 1"));

    for page in ["/policies", "/alerts"] {
        assert_eq!(
            h.raw("GET", page, None, None).await.0,
            StatusCode::OK,
            "{page}"
        );
    }
    assert_eq!(
        h.raw("GET", "/projects/unknown", None, None).await.0,
        StatusCode::NOT_FOUND
    );
}

#[sqlx::test]
async fn kev_list_filters_and_paginates(db: PgPool) {
    let h = harness(db.clone(), |_| {}).await;
    sqlx::query(
        "INSERT INTO kev_entries (cve_id, vendor_project, product, name, date_added, known_ransomware, data)
         SELECT 'CVE-2026-' || lpad(i::text, 4, '0'), CASE WHEN i % 2 = 0 THEN 'Acme' ELSE 'Globex' END,
                'Widget', 'flaw', '2026-10-30', i % 3 = 0, '{}'
         FROM generate_series(1, 300) i",
    )
    .execute(&db)
    .await
    .unwrap();

    let (_, html) = h.raw("GET", "/kev?q=acme&ransomware=on", None, None).await;
    assert!(html.contains("Showing 1–50 of 50"));
    let (_, html) = h.raw("GET", "/kev?q=globex", None, None).await;
    assert!(html.contains("Showing 1–100 of 150"));
    assert!(html.contains(r#"href="/kev?q=globex&amp;page=2""#) && !html.contains("Previous"));
    let (_, html) = h.raw("GET", "/kev?q=globex&page=2", None, None).await;
    assert!(
        html.contains("Showing 101–150 of 150")
            && html.contains("Previous")
            && !html.contains("Next")
    );
    // LIKE wildcards are matched literally
    let (_, html) = h.raw("GET", "/kev?q=%25", None, None).await;
    assert!(html.contains("No entry matches"));
}

// ---------------------------------------------------------------------------------------------
// Dashboard actions

/// A dashboard response: status, headers and body.
struct Page {
    status: StatusCode,
    headers: axum::http::HeaderMap,
    body: String,
}

impl Page {
    fn header(&self, name: &str) -> &str {
        self.headers
            .get(name)
            .map(|v| v.to_str().unwrap())
            .unwrap_or("")
    }
}

impl Harness {
    async fn page(&self, req: Request<Body>) -> Page {
        let res = self.app.clone().oneshot(req).await.unwrap();
        let (parts, body) = res.into_parts();
        let bytes = axum::body::to_bytes(body, usize::MAX).await.unwrap();
        Page {
            status: parts.status,
            headers: parts.headers,
            body: String::from_utf8_lossy(&bytes).into_owned(),
        }
    }

    /// A form post as a browser sends it: admin Basic credentials, same-origin fetch metadata.
    async fn form(&self, uri: &str, fields: &[(&str, &str)], extra: &[(&str, &str)]) -> Page {
        let mut req = Request::post(uri)
            .header("authorization", "Basic dXNlcjphZG1pbg==") // user:admin
            .header("sec-fetch-site", "same-origin")
            .header("content-type", "application/x-www-form-urlencoded");
        for (k, v) in extra {
            req = req.header(*k, *v);
        }
        let body = serde_urlencoded::to_string(fields).unwrap();
        self.page(req.body(Body::from(body)).unwrap()).await
    }

    /// A multipart upload: a `file` part and text fields.
    async fn upload(&self, uri: &str, file: &[u8], fields: &[(&str, &str)]) -> Page {
        let boundary = "tocsin-test-boundary";
        let mut body = Vec::new();
        for (name, value) in fields {
            body.extend(
                format!("--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n")
                    .as_bytes(),
            );
        }
        body.extend(
            format!("--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"bom.json\"\r\nContent-Type: application/octet-stream\r\n\r\n").as_bytes(),
        );
        body.extend(file);
        body.extend(format!("\r\n--{boundary}--\r\n").as_bytes());
        let req = Request::post(uri)
            .header("authorization", "Basic dXNlcjphZG1pbg==")
            .header("sec-fetch-site", "same-origin")
            .header(
                "content-type",
                format!("multipart/form-data; boundary={boundary}"),
            )
            .body(Body::from(body))
            .unwrap();
        self.page(req).await
    }

    async fn get_page(&self, uri: &str, admin: bool) -> Page {
        let mut req = Request::get(uri);
        if admin {
            req = req.header("authorization", "Basic dXNlcjphZG1pbg==");
        }
        self.page(req.body(Body::empty()).unwrap()).await
    }
}

fn gzip_bytes(data: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gz.write_all(data).unwrap();
    gz.finish().unwrap()
}

#[sqlx::test]
async fn dashboard_actions_cover_the_api(db: PgPool) {
    let h = harness(db.clone(), |c| c.google_chat_webhook = None).await;

    // Public dashboard: read-only for visitors, forms for the admin; security headers set
    let visitor = h.get_page("/", false).await;
    assert!(visitor.body.contains("Sign in") && !visitor.body.contains("New project"));
    let admin = h.get_page("/", true).await;
    assert!(admin.body.contains("New project") && !admin.body.contains("Sign in"));
    assert!(
        admin
            .header("content-security-policy")
            .contains("script-src 'self'")
    );

    // Embedded assets, cached forever under content-versioned paths
    let css = admin
        .body
        .split("href=\"/static/tocsin-")
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .unwrap();
    let asset = h.get_page(&format!("/static/tocsin-{css}"), false).await;
    assert_eq!(asset.status, StatusCode::OK);
    assert!(asset.header("cache-control").contains("immutable"));
    assert!(asset.header("content-type").starts_with("text/css"));
    let htmx = h.get_page("/static/htmx-2.0.11.min.js", false).await;
    assert!(htmx.status == StatusCode::OK && htmx.body.contains("htmx"));
    assert_eq!(
        h.get_page("/static/nope.js", false).await.status,
        StatusCode::NOT_FOUND
    );

    // New project: the token is shown once, not cached, and works for CI
    let created = h.form("/projects", &[("name", "shop")], &[]).await;
    assert_eq!(created.status, StatusCode::CREATED, "{}", created.body);
    assert_eq!(created.header("cache-control"), "no-store");
    let token = created
        .body
        .split("class=\"token\">")
        .nth(1)
        .unwrap()
        .get(..64)
        .unwrap()
        .to_owned();
    h.push(&token, "1.0", &[LODASH]).await;
    let taken = h.form("/projects", &[("name", "shop")], &[]).await;
    assert_eq!(taken.status, StatusCode::CONFLICT);
    assert!(taken.body.contains("project already exists"));

    // SBOM upload, gzipped, with a version
    let up = h
        .upload(
            "/projects/shop/sboms",
            &gzip_bytes(bom(&[LOG4J, LODASH]).to_string().as_bytes()),
            &[("version", "2.0")],
        )
        .await;
    assert_eq!(up.status, StatusCode::CREATED, "{}", up.body);
    assert!(up.body.contains("Release 2.0 uploaded"));
    let bad = h.upload("/projects/shop/sboms", b"not json", &[]).await;
    assert_eq!(bad.status, StatusCode::BAD_REQUEST);
    assert!(bad.body.contains("not valid JSON"));

    // The project page offers audit forms, filters and the history chart
    let page = h.get_page("/projects/shop", true).await;
    assert!(
        page.body
            .contains(r#"action="/projects/shop/analyses/CVE-2021-44228""#)
    );
    assert!(page.body.contains("<svg") && page.body.contains("Upload a release"));
    let filtered = h.get_page("/projects/shop?severity=critical", true).await;
    assert!(filtered.body.contains("CVE-2021-44228") && !filtered.body.contains("CVE-2020-28500"));
    let none = h.get_page("/projects/shop?kev=on", true).await;
    assert!(
        none.body
            .contains("No vulnerability matches these filters.")
    );
    let visitor = h.get_page("/projects/shop", false).await;
    assert!(
        !visitor.body.contains("analyses/CVE-2021-44228")
            && !visitor.body.contains("Upload a release")
    );

    // Audit, plain post: redirect back with a fixed confirmation
    let audited = h
        .form(
            "/projects/shop/analyses/CVE-2021-44228",
            &[
                ("state", "not_affected"),
                ("justification", "code_not_reachable"),
                ("detail", "JNDI disabled"),
                ("return_to", "/projects/shop?severity=critical"),
            ],
            &[],
        )
        .await;
    assert_eq!(audited.status, StatusCode::SEE_OTHER);
    assert_eq!(
        audited.header("location"),
        "/projects/shop?severity=critical&done=audited"
    );
    let (_, findings) = h
        .call(
            "GET",
            "/api/projects/shop/findings?suppressed=true",
            Some("admin"),
            None,
        )
        .await;
    assert_eq!(findings["findings"][0]["analysis"]["state"], "not_affected");
    assert!(
        h.get_page("/projects/shop?done=audited", true)
            .await
            .body
            .contains("Audit decision saved.")
    );

    // Audit with htmx, by advisory ID: the cell fragment comes back
    let fragment = h
        .form(
            "/projects/shop/analyses/GHSA-jfh8-c2jp-5v3q",
            &[
                ("state", "in_triage"),
                ("return_to", "/vulns/CVE-2021-44228"),
            ],
            &[("hx-request", "true")],
        )
        .await;
    assert_eq!(fragment.status, StatusCode::OK);
    assert!(fragment.body.contains("In triage") && !fragment.body.contains("<html"));
    let invalid = h
        .form(
            "/projects/shop/analyses/CVE-2021-44228",
            &[("state", "nonsense")],
            &[("hx-request", "true")],
        )
        .await;
    assert_eq!(invalid.status, StatusCode::BAD_REQUEST);
    assert!(invalid.body.contains("invalid state") && invalid.body.contains("role=\"alert\""));
    // Removal, and a return path that is not ours falls back to the project page
    for evil in [
        "https://evil.example/",
        "//evil.example/",
        "/projects/..\\evil",
    ] {
        let removed = h
            .form(
                "/projects/shop/analyses/CVE-2021-44228",
                &[("state", "none"), ("return_to", evil)],
                &[],
            )
            .await;
        assert_eq!(removed.header("location"), "/projects/shop?done=audited");
    }
    let left: i64 = sqlx::query_scalar("SELECT count(*) FROM analyses")
        .fetch_one(&db)
        .await
        .unwrap();
    assert_eq!(left, 0);

    // VEX: download, then import
    let vex = h.get_page("/projects/shop/vex.json", true).await;
    assert!(vex.header("content-disposition").contains("shop-vex.json"));
    assert!(vex.body.contains(r#""bomFormat":"CycloneDX""#));
    let doc = json!({ "bomFormat": "CycloneDX", "specVersion": "1.6", "vulnerabilities": [
        { "id": "CVE-2021-23337", "analysis": { "state": "false_positive" } },
        { "id": "CVE-2020-28500" }
    ] });
    let imported = h
        .upload("/projects/shop/vex", doc.to_string().as_bytes(), &[])
        .await;
    assert_eq!(imported.status, StatusCode::OK, "{}", imported.body);
    assert!(
        imported.body.contains("1 audit decisions imported") && imported.body.contains("Skipped")
    );

    // Policies: create (valid, invalid), delete with htmx and without
    let created = h
        .form(
            "/policies",
            &[("name", "No KEV"), ("kind", "kev"), ("value", "")],
            &[],
        )
        .await;
    assert_eq!(created.header("location"), "/policies?done=policy-created");
    let invalid = h
        .form(
            "/policies",
            &[("name", "Bad"), ("kind", "epss"), ("value", "2")],
            &[],
        )
        .await;
    assert_eq!(invalid.status, StatusCode::BAD_REQUEST);
    h.form(
        "/policies",
        &[
            ("name", "No critical"),
            ("kind", "severity"),
            ("value", "critical"),
        ],
        &[],
    )
    .await;
    let ids: Vec<i64> = sqlx::query_scalar("SELECT id FROM policies ORDER BY id")
        .fetch_all(&db)
        .await
        .unwrap();
    let page = h.get_page("/policies?done=policy-created", true).await;
    assert!(page.body.contains("Policy created.") && page.body.contains("New policy"));
    let gone = h
        .form(
            &format!("/policies/{}/delete", ids[0]),
            &[],
            &[("hx-request", "true")],
        )
        .await;
    assert!(gone.status == StatusCode::OK && gone.body.is_empty());
    let gone = h
        .form(&format!("/policies/{}/delete", ids[1]), &[], &[])
        .await;
    assert_eq!(gone.header("location"), "/policies?done=policy-deleted");
    let missing = h
        .form(&format!("/policies/{}/delete", ids[1]), &[], &[])
        .await;
    assert_eq!(missing.status, StatusCode::NOT_FOUND);

    // Jobs
    let job = h
        .form("/jobs/kev-sync", &[], &[("hx-request", "true")])
        .await;
    assert!(
        job.status == StatusCode::OK && job.body.contains("Done:") && job.body.contains("synced")
    );
    let job = h.form("/jobs/refresh", &[], &[]).await;
    assert!(job.body.contains("Job refresh done") && job.body.contains("purls"));
    assert_eq!(
        h.form("/jobs/nope", &[], &[]).await.status,
        StatusCode::NOT_FOUND
    );
}

#[sqlx::test]
async fn dashboard_writes_need_admin_and_same_origin(db: PgPool) {
    let h = harness(db.clone(), |c| c.google_chat_webhook = None).await;
    let post = |headers: &[(&str, &str)]| {
        let mut req =
            Request::post("/projects").header("content-type", "application/x-www-form-urlencoded");
        for (k, v) in headers {
            req = req.header(*k, *v);
        }
        req.body(Body::from("name=shop")).unwrap()
    };
    const ADMIN: (&str, &str) = ("authorization", "Basic dXNlcjphZG1pbg==");

    // A public dashboard is read-only: visitors are asked to sign in
    let p = h.page(post(&[("sec-fetch-site", "same-origin")])).await;
    assert_eq!(p.status, StatusCode::UNAUTHORIZED);
    assert!(p.header("www-authenticate").starts_with("Basic"));
    let login = h.get_page("/login", false).await;
    assert_eq!(login.status, StatusCode::UNAUTHORIZED);
    assert_eq!(h.get_page("/login", true).await.header("location"), "/");

    // Cross-site posts are refused, even with the admin's credentials
    let p = h
        .page(post(&[ADMIN, ("sec-fetch-site", "cross-site")]))
        .await;
    assert_eq!(p.status, StatusCode::FORBIDDEN);
    let p = h
        .page(post(&[ADMIN, ("origin", "https://evil.example")]))
        .await;
    assert_eq!(p.status, StatusCode::FORBIDDEN);
    // The public URL is a trusted origin
    let p = h
        .page(post(&[ADMIN, ("origin", "https://tocsin.example")]))
        .await;
    assert_eq!(p.status, StatusCode::CREATED, "{}", p.body);

    // Without an admin token configured, nothing can be changed
    let h = harness(db, |c| {
        c.admin_token_hash = None;
        c.google_chat_webhook = None;
    })
    .await;
    let p = h.page(post(&[("sec-fetch-site", "same-origin")])).await;
    assert_eq!(p.status, StatusCode::FORBIDDEN);
    assert!(!h.get_page("/", false).await.body.contains("New project"));
}
