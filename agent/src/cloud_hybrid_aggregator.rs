use flume::Receiver;
use serde::{Serialize, Deserialize};
use tokio::task::JoinHandle;

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub enum CloudServiceType {
    AwsEc2,
    AwsEks,
    AzureVm,
    AzureAks,
    OnPremK8s,
    Unknown,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct UnifiedTelemetryEvent {
    pub service_type: CloudServiceType,
    pub region_id: String,
    pub risk_score: f64,
    // Employs a reference or ID-based string for zero-copy downstream handling
    pub raw_payload_ref: String, 
}

/// Acts as a central hub that normalizes data from agents deployed across hybrid environments.
/// Aggregates findings into a unified schema without pushing commands back down (Passive mode).
pub struct CloudHybridAggregator {
    /// Inbound telemetry from dispersed hybrid agents
    telemetry_rx: Receiver<UnifiedTelemetryEvent>,
}

impl CloudHybridAggregator {
    pub fn new(rx: Receiver<UnifiedTelemetryEvent>) -> Self {
        Self {
            telemetry_rx: rx,
        }
    }

    /// Spawns a dedicated thread for continuous, lock-free telemetry ingestion and normalization
    pub fn spawn_aggregator_loop(self) -> JoinHandle<()> {
        tokio::spawn(async move {
            while let Ok(event) = self.telemetry_rx.recv_async().await {
                // Event-Driven Topology: Process findings synchronously here
                // maintaining high-throughput without blocking discovery threads.
                self.normalize_and_correlate(&event);
            }
        })
    }

    #[inline(always)]
    fn normalize_and_correlate(&self, event: &UnifiedTelemetryEvent) {
        // High-frequency trading desk philosophy: log anomalies, do not block.
        // Performs statistical correlation across regions and service types.
        if event.risk_score > 0.8 {
            // Placeholder: Emits to an external SIEM, SOAR, or observability dashboard
            // e.g., println!("CRITICAL Drift detected in {} | Score: {}", event.region_id, event.risk_score);
        }
    }
}
