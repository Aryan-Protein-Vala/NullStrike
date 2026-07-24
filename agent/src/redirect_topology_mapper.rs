use anyhow::Result;
use chrono::Utc;
use reqwest::Client;
use shared::agent_audit::Finding;
use shared::Severity;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;

/// Module 4: Redirect Topology Mapper
/// Maps HTTP redirects up to depth 5 for common sensitive paths.
pub struct RedirectTopologyMapper {
    pub client: Client,
    pub is_lab_mode: bool,
    pub semaphore: Arc<Semaphore>,
}

impl RedirectTopologyMapper {
    pub fn new(is_lab_mode: bool) -> Self {
        let max_permits = if is_lab_mode { 10 } else { 2 };
        let client = Client::builder()
            .redirect(reqwest::redirect::Policy::limited(5))
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

    pub async fn map_target(&self, target_url: &str) -> Result<Option<Finding>> {
        let _permit = self.semaphore.acquire().await?;

        let sensitive_paths = vec!["/.git/", "/backup.sql", "/.env", "/config.json"];
        let mut hops = Vec::new();

        for path in sensitive_paths {
            let full_url = format!("{}{}", target_url.trim_end_matches('/'), path);
            if let Ok(resp) = self.client.get(&full_url).send().await {
                let final_url = resp.url().to_string();
                if resp.status().is_success() && final_url != full_url {
                    hops.push(format!("Path {} redirected to -> {}", full_url, final_url));
                }
            }
        }

        if !hops.is_empty() {
            return Ok(Some(Finding {
                severity: Severity::Low,
                timestamp: Utc::now().to_rfc3339(),
                target_ip: target_url.to_string(),
                probe_type: "Redirect Topology Mapping".to_string(),
                observation_score: 0.5,
                details: format!("Mapped {} redirect topology hop(s) on sensitive paths for {}", hops.len(), target_url),
                attack_path: hops,
            }));
        }

        Ok(None)
    }
}
