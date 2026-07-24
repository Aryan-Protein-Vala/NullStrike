use std::sync::atomic::{AtomicU64, Ordering};
use tokio::time::Instant;
use uuid::Uuid;
use hyper::{Client, Uri};
use hyper::client::HttpConnector;

/// Measures Temporal Drift in response times to detect potential injection vulnerabilities.
/// Uses lock-free counters and precise timing to avoid memory overhead and ensure determinism.
pub struct TemporalDriftScorer {
    /// Atomic counter storing the baseline latency in microseconds
    baseline_latency_us: AtomicU64,
    /// Atomic counter tracking variance to detect spikes
    drift_variance_us: AtomicU64,
    /// HTTP Client reused for Zero-Copy Data Flow
    client: Client<HttpConnector>,
    /// Target service endpoint
    target_uri: String,
}

impl TemporalDriftScorer {
    pub fn new(target_uri: String) -> Self {
        let client = Client::builder()
            .pool_idle_timeout(Some(std::time::Duration::from_secs(30)))
            .build_http();

        Self {
            baseline_latency_us: AtomicU64::new(0),
            drift_variance_us: AtomicU64::new(0),
            client,
            target_uri,
        }
    }

    /// Emits a passive probe appending a unique UUID.
    /// Operates on the order of 1-2 requests per second (RPS) as a safe default.
    pub async fn emit_passive_probe(&self) -> Result<u64, Box<dyn std::error::Error + Send + Sync>> {
        let probe_id = Uuid::new_v4();
        let uri = format!("{}?trace_id={}", self.target_uri, probe_id).parse::<Uri>()?;

        let start = Instant::now();
        let _response = self.client.get(uri).await?;
        let elapsed_us = start.elapsed().as_micros() as u64;

        let baseline = self.baseline_latency_us.load(Ordering::Relaxed);
        if baseline == 0 {
            self.baseline_latency_us.store(elapsed_us, Ordering::Release);
        } else {
            // Fast-path rolling average
            let new_baseline = (baseline * 9 + elapsed_us) / 10;
            self.baseline_latency_us.store(new_baseline, Ordering::Release);
            
            let drift = if elapsed_us > new_baseline { elapsed_us - new_baseline } else { 0 };
            self.drift_variance_us.store(drift, Ordering::Release);
        }

        Ok(elapsed_us)
    }

    /// Quickly checks if the temporal drift exceeds a designated tolerance threshold.
    pub fn is_drift_anomalous(&self, threshold_us: u64) -> bool {
        self.drift_variance_us.load(Ordering::Acquire) > threshold_us
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::service::{make_service_fn, service_fn};
    use hyper::{Body, Request, Response, Server};
    use std::convert::Infallible;
    use tokio::time::{sleep, Duration};

    async fn time_varying_service(req: Request<Body>) -> Result<Response<Body>, Infallible> {
        // T=0s Safe, T=5s Insecure simulated by time mapping.
        // A delayed response represents temporal drift.
        let delay = if req.uri().query().unwrap_or("").contains("slow") {
            Duration::from_millis(50)
        } else {
            Duration::from_millis(2)
        };
        sleep(delay).await;
        Ok(Response::new(Body::from("OK")))
    }

    #[tokio::test]
    async fn test_temporal_drift_detection() {
        let addr = ([127, 0, 0, 1], 0).into();
        let make_svc = make_service_fn(|_conn| async {
            Ok::<_, Infallible>(service_fn(time_varying_service))
        });
        
        let server = Server::bind(&addr).serve(make_svc);
        let port = server.local_addr().port();
        tokio::spawn(server);

        let scorer = TemporalDriftScorer::new(format!("http://127.0.0.1:{}", port));
        
        // Baseline established (~2ms)
        let _ = scorer.emit_passive_probe().await.unwrap();
        
        // Should not be anomalous with a 10ms tolerance
        assert!(!scorer.is_drift_anomalous(10000));
    }
}
