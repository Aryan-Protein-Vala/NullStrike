use crate::auditor::Auditor;
use anyhow::Result;
use async_trait::async_trait;
use reqwest::Client;
use shared::{SecurityEvent, Severity};
use std::time::Instant;

/// Time-based and error-based SQL injection symptom detection.
///
/// SAFETY GUARANTEES:
/// - No data is modified — SELECT/SLEEP/WAITFOR are read-only operations.
/// - Time-based probes use a 1-second delay; we compare against a baseline.
/// - Error-based probes look for database error keywords in the response text.
/// - No DROP, INSERT, UPDATE, DELETE, or UNION-based data exfiltration.
pub struct SqliSymptomDetector {
    pub paths: Vec<String>,
    pub client: Client,
}

/// A single time-based probe definition.
struct TimingProbe {
    label: &'static str,
    payload: &'static str,
}

/// Error keywords that indicate a database backend leaking errors.
const DB_ERROR_KEYWORDS: &[&str] = &[
    "SQL syntax",
    "mysql_fetch",
    "ORA-",
    "PG::Error",
    "SQLite3::SQLException",
    "Unclosed quotation mark",
    "quoted string not properly terminated",
    "You have an error in your SQL syntax",
    "Warning: mysql",
    "Microsoft OLE DB Provider for SQL Server",
    "SQLSTATE",
    "pg_query",
    "unterminated",
    "syntax error at or near",
];

const TIMING_PROBES: &[TimingProbe] = &[
    TimingProbe { label: "MySQL SLEEP", payload: "' OR SLEEP(1)-- " },
    TimingProbe { label: "MSSQL WAITFOR", payload: "'; WAITFOR DELAY '0:0:1'-- " },
    TimingProbe { label: "PostgreSQL pg_sleep", payload: "' OR pg_sleep(1)-- " },
];

const ERROR_PROBE: &str = "' OR '1'='1";

impl SqliSymptomDetector {
    pub fn new(paths: Vec<String>) -> Self {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .danger_accept_invalid_certs(true)
            .redirect(reqwest::redirect::Policy::limited(3))
            .build()
            .unwrap_or_default();

        let paths = if paths.is_empty() {
            vec![
                "/".to_string(),
                "/search".to_string(),
                "/login".to_string(),
                "/api/users".to_string(),
                "/products".to_string(),
            ]
        } else {
            paths
        };

        Self { paths, client }
    }

    /// Get a baseline response time for a normal request.
    async fn baseline_time(&self, url: &str) -> Option<u128> {
        let start = Instant::now();
        if self.client.get(url).send().await.is_ok() {
            Some(start.elapsed().as_millis())
        } else {
            None
        }
    }
}

#[async_trait]
impl Auditor for SqliSymptomDetector {
    fn name(&self) -> String {
        "SQLi Symptom Detector".into()
    }

    fn severity(&self) -> Severity {
        Severity::Critical
    }

    async fn execute(&self, target: &str) -> Result<SecurityEvent> {
        let mut attack_path = Vec::new();
        let mut is_vulnerable = false;

        let test_params = ["id", "q", "search", "user", "page", "category"];

        for path in &self.paths {
            let ep = if path.starts_with('/') {
                path.to_string()
            } else {
                format!("/{}", path)
            };

            let base_url = format!("http://{}{}", target, ep);

            // Get baseline response time
            let baseline_ms = self.baseline_time(&base_url).await.unwrap_or(200);

            for param in &test_params {
                // ── Time-based detection ──────────────────────────────────
                for probe in TIMING_PROBES {
                    let url = format!("{}?{}={}", base_url, param, probe.payload);
                    let start = Instant::now();

                    if let Ok(_resp) = self.client.get(&url).send().await {
                        let elapsed_ms = start.elapsed().as_millis();

                        // If response took >1000ms longer than baseline, flag it
                        if elapsed_ms > baseline_ms + 900 {
                            attack_path.push(format!(
                                "TIMING: {} param '{}' at {} — baseline {}ms, probe {}ms (delta +{}ms) [{}]",
                                probe.label,
                                param,
                                base_url,
                                baseline_ms,
                                elapsed_ms,
                                elapsed_ms.saturating_sub(baseline_ms),
                                probe.label,
                            ));
                            is_vulnerable = true;
                        }
                    }
                }

                // ── Error-based detection ─────────────────────────────────
                let error_url = format!("{}?{}={}", base_url, param, ERROR_PROBE);
                if let Ok(resp) = self.client.get(&error_url).send().await {
                    if let Ok(body) = resp.text().await {
                        for keyword in DB_ERROR_KEYWORDS {
                            if body.contains(keyword) {
                                attack_path.push(format!(
                                    "ERROR_BASED: Database error keyword '{}' found in response for param '{}' at {}",
                                    keyword, param, base_url
                                ));
                                is_vulnerable = true;
                                break; // One keyword match per param is enough
                            }
                        }
                    }
                }
            }
        }

        if is_vulnerable {
            Ok(SecurityEvent::SimulationAlert {
                target: target.to_string(),
                check_name: self.name(),
                severity: Severity::Critical,
                is_vulnerable: true,
                details: format!(
                    "{} SQL injection symptom(s) detected on {} — IMMEDIATE REMEDIATION REQUIRED",
                    attack_path.len(),
                    target
                ),
                attack_path,
            })
        } else {
            Ok(SecurityEvent::Pass {
                target: target.to_string(),
                check_name: self.name(),
            })
        }
    }
}
