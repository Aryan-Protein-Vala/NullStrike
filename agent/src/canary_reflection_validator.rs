use anyhow::Result;
use chrono::Utc;
use reqwest::Client;
use shared::agent_audit::Finding;
use shared::Severity;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;

/// Module 5: Canary Reflection Validator
/// Appends a unique UUID timestamped string to form/URL parameters and checks for exact byte-for-byte reflection.
pub struct CanaryReflectionValidator {
    pub client: Client,
    pub is_lab_mode: bool,
    pub semaphore: Arc<Semaphore>,
}

impl CanaryReflectionValidator {
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

    pub async fn validate(&self, target_url: &str, param_name: &str) -> Result<Option<Finding>> {
        let _permit = self.semaphore.acquire().await?;

        let canary = format!("canary_{}_{}", Utc::now().timestamp_millis(), &uuid::Uuid::new_v4().to_string()[..8]);
        let url = format!("{}?{}={}", target_url, param_name, canary);

        if let Ok(resp) = self.client.get(&url).send().await {
            if let Ok(body_bytes) = resp.bytes().await {
                if body_bytes.windows(canary.len()).any(|window| window == canary.as_bytes()) {
                    return Ok(Some(Finding {
                        severity: Severity::High,
                        timestamp: Utc::now().to_rfc3339(),
                        target_ip: target_url.to_string(),
                        probe_type: "Canary Reflection Validation".to_string(),
                        observation_score: 0.9,
                        details: format!("Byte-for-byte canary reflection validated on param '{}' at {}", param_name, target_url),
                        attack_path: vec![
                            format!("Injected Canary: {}", canary),
                            format!("URL Probed: {}", url),
                            "Exact byte match found in response body".to_string(),
                        ],
                    }));
                }
            }
        }

        Ok(None)
    }
}
