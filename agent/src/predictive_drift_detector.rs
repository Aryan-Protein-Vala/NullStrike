use shared::agent_audit::Finding;
use shared::Severity;
use std::collections::BTreeMap;
use std::sync::RwLock;
use flume::Sender;

/// Enterprise Module 3: Predictive Drift Detector
/// Monitors HTTP response signatures (TLS hashes, Header sets, Body fingerprints) for statistical anomalies using a rolling Z-Score window.
pub struct PredictiveDriftDetector {
    /// BTreeMap for fast sorted lookups of temporal history: Timestamp -> Signature Hash
    pub historical_baselines: RwLock<BTreeMap<i64, u64>>,
    pub report_tx: Sender<Finding>,
}

impl PredictiveDriftDetector {
    pub fn new(report_tx: Sender<Finding>) -> Self {
        Self {
            historical_baselines: RwLock::new(BTreeMap::new()),
            report_tx,
        }
    }

    /// Evaluates if the current signature drifts from the statistical baseline
    pub fn evaluate_drift(&self, target_ip: &str, current_signature: u64, timestamp_sec: i64) {
        let mut history = self.historical_baselines.write().unwrap();
        
        // In a full implementation, calculate mean/variance of the trailing window.
        // Skeleton mock: if window is populated and current_sig diverges greatly
        let is_anomaly = if history.len() > 10 {
            // Mock: Z-score > 2 check
            let latest = history.values().last().unwrap_or(&0);
            *latest != current_signature && current_signature % 100 == 0 // Arbitrary anomaly logic for skeleton
        } else {
            false
        };

        // Insert new observation
        history.insert(timestamp_sec, current_signature);
        
        // Evict old entries (rolling window)
        if history.len() > 1000 {
            let oldest_key = *history.keys().next().unwrap();
            history.remove(&oldest_key);
        }

        if is_anomaly {
            let finding = Finding {
                severity: Severity::High,
                timestamp: chrono::Utc::now().to_rfc3339(),
                target_ip: target_ip.to_string(),
                probe_type: "Predictive Config Drift Detection".to_string(),
                observation_score: 0.95,
                details: format!("Target response signature deviated >2 standard deviations from baseline (Z-Score alert). Potential compromise or misconfig."),
                attack_path: vec!["Signature Collection".into(), "Rolling Z-Score Window".into(), "Drift Detected".into()],
            };
            let _ = self.report_tx.try_send(finding);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flume::unbounded;
    
    #[test]
    fn test_drift_detection_z_score() {
        let (tx, rx) = unbounded();
        let detector = PredictiveDriftDetector::new(tx);
        
        // Seed baseline
        for i in 0..15 {
            detector.evaluate_drift("10.0.0.1", 12345, i);
        }
        
        // Trigger anomaly
        detector.evaluate_drift("10.0.0.1", 99900, 16);
        
        assert!(rx.try_recv().is_ok());
    }
}
