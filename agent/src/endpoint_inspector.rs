use crate::auditor::Auditor;
use anyhow::Result;
use async_trait::async_trait;
use reqwest::Client;
use shared::{SecurityEvent, Severity};

/// Default paths to probe for exposed endpoints.
const DEFAULT_PATHS: &[&str] = &[
    "/health",
    "/status",
    "/info",
    "/metrics",
    "/swagger.json",
    "/swagger-ui.html",
    "/openapi.json",
    "/api/v1",
    "/api/users",
    "/api/admin",
    "/graphql",
    "/actuator",
    "/actuator/health",
    "/actuator/env",
    "/debug/vars",
    "/server-status",
    "/.well-known/openid-configuration",
];

/// Sends GET requests to a set of common API/admin paths and reports which ones
/// respond with a non-404 status. No payloads, no mutations — read-only probes.
pub struct EndpointInspector {
    pub paths: Vec<String>,
    pub client: Client,
}

impl EndpointInspector {
    pub fn new(paths: Vec<String>) -> Self {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(3))
            .danger_accept_invalid_certs(true)
            .redirect(reqwest::redirect::Policy::limited(3))
            .build()
            .unwrap_or_default();

        let paths = if paths.is_empty() {
            DEFAULT_PATHS.iter().map(|s| s.to_string()).collect()
        } else {
            paths
        };

        Self { paths, client }
    }
}

#[async_trait]
impl Auditor for EndpointInspector {
    fn name(&self) -> String {
        "Endpoint Inspector".into()
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    async fn execute(&self, target: &str) -> Result<SecurityEvent> {
        let mut attack_path = Vec::new();

        for path in &self.paths {
            let ep = if path.starts_with('/') {
                path.to_string()
            } else {
                format!("/{}", path)
            };

            // Try HTTPS first, fall back to HTTP
            for scheme in &["https", "http"] {
                let url = format!("{}://{}{}", scheme, target, ep);

                if let Ok(resp) = self.client.get(&url).send().await {
                    let status = resp.status();
                    // We care about anything that isn't a 404 — it means the path exists
                    if status.as_u16() != 404 {
                        let content_type = resp
                            .headers()
                            .get("content-type")
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or("unknown")
                            .to_string();

                        attack_path.push(format!(
                            "DISCOVERED: {} [{}] Content-Type: {}",
                            url, status, content_type
                        ));
                        break; // Don't duplicate for both schemes
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
                details: format!("{} endpoint(s) discovered on {}", attack_path.len(), target),
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
