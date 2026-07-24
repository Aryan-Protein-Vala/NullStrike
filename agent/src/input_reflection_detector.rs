use crate::auditor::Auditor;
use anyhow::Result;
use async_trait::async_trait;
use reqwest::Client;
use shared::{SecurityEvent, Severity};

/// A harmless, plain-text canary string used to detect output reflection.
/// Contains NO script tags, NO HTML, NO special characters — just alphanumeric.
const CANARY: &str = "nullstrike_canary_7x9k2m";

/// Detects missing output encoding by injecting a harmless plain-text canary
/// into URL query parameters and checking if it appears verbatim in the response body.
///
/// This is a standard technique for identifying fields that reflect user input
/// without encoding — a prerequisite for XSS, but this module itself sends
/// NO exploit payloads whatsoever.
pub struct InputReflectionDetector {
    pub paths: Vec<String>,
    pub client: Client,
}

impl InputReflectionDetector {
    pub fn new(paths: Vec<String>) -> Self {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(3))
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap_or_default();

        Self { paths, client }
    }
}

#[async_trait]
impl Auditor for InputReflectionDetector {
    fn name(&self) -> String {
        "Input Reflection Detector".into()
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    async fn execute(&self, target: &str) -> Result<SecurityEvent> {
        let mut attack_path = Vec::new();

        // Common parameter names to test for reflection
        let test_params = ["q", "search", "query", "input", "name", "user", "id", "redirect", "url", "callback"];

        for path in &self.paths {
            let ep = if path.starts_with('/') {
                path.to_string()
            } else {
                format!("/{}", path)
            };

            for param in &test_params {
                let url = format!("http://{}{}?{}={}", target, ep, param, CANARY);

                if let Ok(resp) = self.client.get(&url).send().await {
                    let status = resp.status();
                    if status.is_success() || status.as_u16() == 403 {
                        if let Ok(body) = resp.text().await {
                            if body.contains(CANARY) {
                                attack_path.push(format!(
                                    "REFLECTED: param '{}' at {} — input appears in response body (potential output encoding issue)",
                                    param, url
                                ));
                            }
                        }
                    }
                }
            }
        }

        if !attack_path.is_empty() {
            Ok(SecurityEvent::SimulationAlert {
                target: target.to_string(),
                check_name: self.name(),
                severity: self.severity(),
                is_vulnerable: true,
                details: format!(
                    "{} reflected input point(s) found — indicates missing output encoding.",
                    attack_path.len()
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
