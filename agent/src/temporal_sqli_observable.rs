use anyhow::Result;
use chrono::Utc;
use reqwest::Client;
use shared::agent_audit::Finding;
use shared::Severity;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;
use tokio::time::sleep;

/// Module 1: Temporal SQLi Observable
/// Compares response timing between baseline and canary probe requests to detect server-side parsing deltas.
pub struct TemporalSqliObservable {
    pub client: Client,
    pub is_lab_mode: bool,
    pub semaphore: Arc<Semaphore>,
}

impl TemporalSqliObservable {
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

    pub async fn observe(&self, target_url: &str, param_name: &str) -> Result<Option<Finding>> {
        let _permit = self.semaphore.acquire().await?;
        let canary_id = uuid::Uuid::new_v4().to_string()[..8].to_string();

        let baseline_url = format!("{}?{}=1", target_url, param_name);
        let probe_url = format!("{}?{}={}", target_url, param_name, canary_id);

        let mut backoff = Duration::from_millis(100);
        let mut baseline_duration = Duration::ZERO;
        let mut probe_duration = Duration::ZERO;

        // Baseline request
        for _ in 0..3 {
            let start = Instant::now();
            match self.client.get(&baseline_url).send().await {
                Ok(_) => {
                    baseline_duration = start.elapsed();
                    break;
                }
                Err(_) => {
                    sleep(backoff).await;
                    backoff *= 2;
                }
            }
        }

        // Probe request
        backoff = Duration::from_millis(100);
        for _ in 0..3 {
            let start = Instant::now();
            match self.client.get(&probe_url).send().await {
                Ok(_) => {
                    probe_duration = start.elapsed();
                    break;
                }
                Err(_) => {
                    sleep(backoff).await;
                    backoff *= 2;
                }
            }
        }

        let delta_ms = if probe_duration > baseline_duration {
            (probe_duration - baseline_duration).as_millis()
        } else {
            0
        };

        // If delta > 5ms, flag observation symptom
        if delta_ms > 5 {
            let score = (delta_ms as f64 / 100.0).min(1.0);
            return Ok(Some(Finding {
                severity: if delta_ms > 500 { Severity::High } else { Severity::Medium },
                timestamp: Utc::now().to_rfc3339(),
                target_ip: target_url.to_string(),
                probe_type: "Temporal SQLi Observation".to_string(),
                observation_score: score,
                details: format!(
                    "Timing anomaly detected on param '{}': baseline {}ms, probe {}ms (delta {}ms)",
                    param_name,
                    baseline_duration.as_millis(),
                    probe_duration.as_millis(),
                    delta_ms
                ),
                attack_path: vec![
                    format!("Baseline GET: {}", baseline_url),
                    format!("Canary Probe GET: {}", probe_url),
                    format!("Delta: {}ms", delta_ms),
                ],
            }));
        }

        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::service::{make_service_fn, service_fn};
    use hyper::{Body, Request, Response, Server};
    use std::convert::Infallible;
    use std::net::SocketAddr;

    async fn handle_request(req: Request<Body>) -> Result<Response<Body>, Infallible> {
        let uri = req.uri().to_string();
        if uri.contains("id=1") {
            // Fast response for baseline
            Ok(Response::new(Body::from("OK")))
        } else {
            // Simulated delay for probe
            tokio::time::sleep(Duration::from_millis(20)).await;
            Ok(Response::new(Body::from("SLOW")))
        }
    }

    #[tokio::test]
    async fn test_temporal_sqli_anomaly_detection() {
        let addr = SocketAddr::from(([127, 0, 0, 1], 0));
        let make_svc = make_service_fn(|_conn| async { Ok::<_, Infallible>(service_fn(handle_request)) });
        let server = Server::bind(&addr).serve(make_svc);
        let local_addr = server.local_addr();

        tokio::spawn(async move {
            let _ = server.await;
        });

        let target_url = format!("http://{}", local_addr);
        let observer = TemporalSqliObservable::new(true);

        let result = observer.observe(&target_url, "id").await.unwrap();
        assert!(result.is_some());
        let finding = result.unwrap();
        assert_eq!(finding.probe_type, "Temporal SQLi Observation");
    }
}
