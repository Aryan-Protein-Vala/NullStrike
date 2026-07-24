use crate::auditor::Auditor;
use anyhow::Result;
use async_trait::async_trait;
use reqwest::Client;
use shared::{SecurityEvent, Severity};

/// All security headers we check, with their expected behavior.
const SECURITY_HEADERS: &[(&str, &str)] = &[
    ("strict-transport-security", "HSTS — Forces HTTPS connections"),
    ("content-security-policy", "CSP — Prevents XSS and data injection"),
    ("x-frame-options", "Clickjacking protection"),
    ("x-content-type-options", "MIME-type sniffing prevention"),
    ("x-xss-protection", "Legacy XSS filter (deprecated but still checked)"),
    ("referrer-policy", "Controls referrer information leakage"),
    ("permissions-policy", "Controls browser feature access"),
    ("cache-control", "Prevents sensitive data caching"),
];

/// Examines HTTP response headers for missing or misconfigured security headers.
/// Read-only — sends a single GET request and inspects the response.
pub struct HeaderAuditor {
    pub client: Client,
}

impl HeaderAuditor {
    pub fn new() -> Self {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap_or_default();

        Self { client }
    }
}

#[async_trait]
impl Auditor for HeaderAuditor {
    fn name(&self) -> String {
        "Header Auditor".into()
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    async fn execute(&self, target: &str) -> Result<SecurityEvent> {
        let mut attack_path = Vec::new();
        let mut is_vulnerable = false;

        // Try HTTPS first, then HTTP
        let url = format!("https://{}", target);
        let fallback_url = format!("http://{}", target);

        let resp = match self.client.get(&url).send().await {
            Ok(r) => r,
            Err(_) => match self.client.get(&fallback_url).send().await {
                Ok(r) => r,
                Err(_) => {
                    return Ok(SecurityEvent::Pass {
                        target: target.to_string(),
                        check_name: self.name(),
                    });
                }
            },
        };

        let headers = resp.headers();

        // Check for missing security headers
        for (header_name, description) in SECURITY_HEADERS {
            if !headers.contains_key(*header_name) {
                attack_path.push(format!(
                    "MISSING: {} — {}", header_name, description
                ));
            }
        }

        // Check for dangerous CORS wildcard
        if let Some(cors) = headers.get("access-control-allow-origin") {
            if let Ok(val) = cors.to_str() {
                if val == "*" {
                    attack_path.push(
                        "VULNERABILITY: Access-Control-Allow-Origin: * — Wildcard CORS allows any origin".to_string()
                    );
                    is_vulnerable = true;
                }
            }
        }

        // Check for overly permissive X-Frame-Options
        if let Some(xfo) = headers.get("x-frame-options") {
            if let Ok(val) = xfo.to_str() {
                let val_upper = val.to_uppercase();
                if val_upper != "DENY" && val_upper != "SAMEORIGIN" {
                    attack_path.push(format!(
                        "WEAK: X-Frame-Options: {} — should be DENY or SAMEORIGIN", val
                    ));
                }
            }
        }

        // Check for Server header information leakage
        if let Some(server) = headers.get("server") {
            if let Ok(val) = server.to_str() {
                if val.contains('/') {
                    // Contains version info like "Apache/2.4.41"
                    attack_path.push(format!(
                        "INFO_LEAK: Server: {} — version disclosed", val
                    ));
                }
            }
        }

        // Check for X-Powered-By information leakage
        if let Some(powered) = headers.get("x-powered-by") {
            if let Ok(val) = powered.to_str() {
                attack_path.push(format!(
                    "INFO_LEAK: X-Powered-By: {} — technology stack disclosed", val
                ));
            }
        }

        if !attack_path.is_empty() {
            let missing_count = attack_path
                .iter()
                .filter(|s| s.starts_with("MISSING"))
                .count();

            Ok(SecurityEvent::SimulationAlert {
                target: target.to_string(),
                check_name: self.name(),
                severity: if is_vulnerable { Severity::High } else { self.severity() },
                is_vulnerable: is_vulnerable || missing_count >= 3,
                details: format!(
                    "{} header issue(s) found on {}",
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
