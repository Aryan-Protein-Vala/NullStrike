use anyhow::Result;
use chrono::Utc;
use reqwest::Client;
use serde_json::Value;
use shared::agent_audit::Finding;
use shared::Severity;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;

/// Module 3: JSON Schema Inspector (GraphQL/API)
/// Issues lightweight introspection and root GET queries to detect exposed PII or admin endpoints.
pub struct JsonSchemaInspector {
    pub client: Client,
    pub is_lab_mode: bool,
    pub semaphore: Arc<Semaphore>,
}

impl JsonSchemaInspector {
    pub fn new(is_lab_mode: bool) -> Self {
        let max_permits = if is_lab_mode { 10 } else { 2 };
        let client = Client::builder()
            .timeout(Duration::from_secs(5))
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap_or_default();

        Self {
            client,
            is_lab_mode,
            semaphore: Arc::new(Semaphore::new(max_permits)),
        }
    }

    pub async fn inspect(&self, target_url: &str) -> Result<Option<Finding>> {
        let _permit = self.semaphore.acquire().await?;

        let endpoints = if self.is_lab_mode {
            vec!["/graphql", "/api/v1/schema", "/admin", "/debug"]
        } else {
            vec!["/graphql", "/api/v1/schema"]
        };

        let mut exposed_paths = Vec::new();
        let sensitive_keys = ["password", "token", "ssn", "secret", "private_key", "admin"];

        for ep in &endpoints {
            let full_url = format!("{}{}", target_url.trim_end_matches('/'), ep);
            if let Ok(resp) = self.client.get(&full_url).send().await {
                if resp.status().is_success() {
                    if let Ok(json) = resp.json::<Value>().await {
                        let json_str = json.to_string().to_lowercase();
                        for key in &sensitive_keys {
                            if json_str.contains(key) {
                                exposed_paths.push(format!("Endpoint {} contains sensitive schema field '{}'", full_url, key));
                            }
                        }
                    }
                }
            }
        }

        if !exposed_paths.is_empty() {
            return Ok(Some(Finding {
                severity: Severity::Medium,
                timestamp: Utc::now().to_rfc3339(),
                target_ip: target_url.to_string(),
                probe_type: "JSON Schema Inspection".to_string(),
                observation_score: 0.7,
                details: format!("Found {} exposed sensitive schema field(s) on {}", exposed_paths.len(), target_url),
                attack_path: exposed_paths,
            }));
        }

        Ok(None)
    }
}
