use anyhow::Result;
use chrono::Utc;
use reqwest::Client;
use shared::agent_audit::Finding;
use shared::Severity;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;

/// Module 2: Header Integrity Checker
/// Verifies consistency in returned HTTP headers (HSTS, CSP, Server leaks) using randomized User-Agent headers.
pub struct HeaderIntegrityChecker {
    pub client: Client,
    pub is_lab_mode: bool,
    pub semaphore: Arc<Semaphore>,
}

impl HeaderIntegrityChecker {
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

    pub async fn check(&self, target_url: &str) -> Result<Option<Finding>> {
        let _permit = self.semaphore.acquire().await?;

        let user_agents = [
            "NullStrike-Sensor/1.0",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
        ];

        let mut header_sets: Vec<HashSet<String>> = Vec::new();

        for ua in &user_agents {
            if let Ok(resp) = self.client.get(target_url).header("User-Agent", *ua).send().await {
                let keys: HashSet<String> = resp
                    .headers()
                    .keys()
                    .map(|k| k.as_str().to_lowercase())
                    .collect();
                header_sets.push(keys);
            }
        }

        if header_sets.len() < 2 {
            return Ok(None);
        }

        let first = &header_sets[0];
        let mut inconsistent = false;
        let mut diff_details = Vec::new();

        for (idx, other) in header_sets.iter().enumerate().skip(1) {
            if first != other {
                inconsistent = true;
                let added: Vec<_> = other.difference(first).collect();
                let removed: Vec<_> = first.difference(other).collect();
                diff_details.push(format!(
                    "UA #{} header differences — Added: {:?}, Removed: {:?}",
                    idx, added, removed
                ));
            }
        }

        if inconsistent {
            return Ok(Some(Finding {
                severity: Severity::Low,
                timestamp: Utc::now().to_rfc3339(),
                target_ip: target_url.to_string(),
                probe_type: "Header Integrity Check".to_string(),
                observation_score: 0.4,
                details: format!("Inconsistent security response headers detected across User-Agents on {}", target_url),
                attack_path: diff_details,
            }));
        }

        Ok(None)
    }
}
