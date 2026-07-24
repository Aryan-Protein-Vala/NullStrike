use crate::auditor::Auditor;
use anyhow::Result;
use async_trait::async_trait;
use reqwest::Client;
use shared::{SecurityEvent, Severity};

/// Sensitive files that should never be publicly accessible.
const SENSITIVE_PATHS: &[(&str, &str)] = &[
    ("/.env", "Environment variables — may contain API keys, DB credentials"),
    ("/.git/config", "Git configuration — reveals repository URLs and author info"),
    ("/.git/HEAD", "Git HEAD — confirms .git directory is exposed"),
    ("/config.json", "Application config — may contain secrets"),
    ("/config.yaml", "Application config — may contain secrets"),
    ("/config.yml", "Application config — may contain secrets"),
    ("/backup.sql", "Database backup — full database dump"),
    ("/dump.sql", "Database dump — full database contents"),
    ("/database.sql", "Database export — full database contents"),
    ("/.htpasswd", "Apache password file — contains hashed credentials"),
    ("/.htaccess", "Apache config — may reveal internal routing"),
    ("/wp-config.php", "WordPress config — contains DB credentials"),
    ("/phpinfo.php", "PHP info page — reveals full server configuration"),
    ("/server-info", "Apache server info — reveals modules and config"),
    ("/.dockerenv", "Docker environment marker"),
    ("/docker-compose.yml", "Docker Compose config — reveals service architecture"),
    ("/Dockerfile", "Dockerfile — reveals build process"),
    ("/.aws/credentials", "AWS credentials file"),
    ("/id_rsa", "SSH private key"),
    ("/.ssh/authorized_keys", "SSH authorized keys"),
];

/// Checks for exposed sensitive files that should never be publicly accessible.
/// Sends GET requests only — no mutations, no write operations.
pub struct CredentialLeakChecker {
    pub client: Client,
}

impl CredentialLeakChecker {
    pub fn new() -> Self {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(3))
            .danger_accept_invalid_certs(true)
            .redirect(reqwest::redirect::Policy::limited(3))
            .build()
            .unwrap_or_default();

        Self { client }
    }
}

#[async_trait]
impl Auditor for CredentialLeakChecker {
    fn name(&self) -> String {
        "Credential Leak Checker".into()
    }

    fn severity(&self) -> Severity {
        Severity::Critical
    }

    async fn execute(&self, target: &str) -> Result<SecurityEvent> {
        let mut attack_path = Vec::new();
        let mut critical_leaks = 0u32;

        for (path, description) in SENSITIVE_PATHS {
            for scheme in &["https", "http"] {
                let url = format!("{}://{}{}", scheme, target, path);

                if let Ok(resp) = self.client.get(&url).send().await {
                    let status = resp.status();

                    // A 200 OK on a sensitive file is a critical finding
                    if status.is_success() {
                        let content_length = resp
                            .headers()
                            .get("content-length")
                            .and_then(|v| v.to_str().ok())
                            .and_then(|s| s.parse::<u64>().ok())
                            .unwrap_or(0);

                        // Only flag if there's actual content (not an empty custom 200 page)
                        if content_length > 0 {
                            critical_leaks += 1;
                            attack_path.push(format!(
                                "CRITICAL LEAK: {} [{}] ({} bytes) — {}",
                                url, status, content_length, description
                            ));
                            break; // Don't check HTTP if HTTPS already found it
                        }
                    }
                }
            }
        }

        if critical_leaks > 0 {
            Ok(SecurityEvent::SimulationAlert {
                target: target.to_string(),
                check_name: self.name(),
                severity: Severity::Critical,
                is_vulnerable: true,
                details: format!(
                    "{} sensitive file(s) publicly accessible on {} — IMMEDIATE ACTION REQUIRED",
                    critical_leaks, target
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
