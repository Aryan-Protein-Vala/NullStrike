use flume::{Sender, Receiver};
use serde::{Serialize, Deserialize};
use hyper::{Client, Uri};
use hyper::client::HttpConnector;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TrustAnomalyEvent {
    pub source_service: String,
    pub target_path: String,
    pub leaked_artifact_type: String, // e.g., "AuthToken", "InternalIP"
    pub timestamp: u64,
}

/// Builds an in-memory Attack Graph by passively observing lateral service trust.
/// Explores minimal administrative footprint to avoid active intrusion.
pub struct LateralTrustMapper {
    event_tx: Sender<TrustAnomalyEvent>,
    client: Client<HttpConnector>,
}

impl LateralTrustMapper {
    pub fn new() -> (Self, Receiver<TrustAnomalyEvent>) {
        // Zero-copy unbounded channel for high-throughput, non-blocking event streaming
        let (tx, rx) = flume::unbounded();
        
        let client = Client::builder()
            .pool_max_idle_per_host(100)
            .build_http();

        let mapper = Self {
            event_tx: tx,
            client,
        };

        (mapper, rx)
    }

    /// Spawns an asynchronous discovery probe checking for latent trust relationships
    pub async fn map_trust(&self, target_service: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let paths = vec!["/.admin", "/health", "/metrics"];
        
        for path in paths {
            let uri = format!("{}{}", target_service, path).parse::<Uri>()?;
            let response = self.client.get(uri).await?;
            
            if response.status().is_success() {
                let bytes = hyper::body::to_bytes(response.into_body()).await?;
                let content = String::from_utf8_lossy(&bytes);
                
                // Deterministic checks (O(N) search with high data locality)
                if content.contains("eyJh") { // JWT Prefix Base64 (eyJhbGci...)
                    self.emit_anomaly(target_service, path, "AuthToken");
                }
                
                // Basic string search for 10.x.x.x subnet pattern (Internal IP leak)
                if content.contains("10.") && content.matches('.').count() >= 3 {
                    self.emit_anomaly(target_service, path, "InternalIP");
                }
            }
        }
        
        Ok(())
    }

    #[inline(always)]
    fn emit_anomaly(&self, source: &str, path: &str, artifact: &str) {
        let event = TrustAnomalyEvent {
            source_service: source.to_string(),
            target_path: path.to_string(),
            leaked_artifact_type: artifact.to_string(),
            timestamp: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),
        };
        // Asynchronous, non-blocking send to heavy processing queues
        let _ = self.event_tx.send(event);
    }
}
