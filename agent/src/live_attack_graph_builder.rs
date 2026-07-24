use dashmap::DashMap;
use shared::agent_audit::Finding;
use shared::Severity;
use flume::Sender;
use std::sync::Arc;

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct NodeId(pub String);

#[derive(Debug, Clone)]
pub struct Node {
    pub service_name: String,
    pub ip_address: String,
    pub risk_score: f64,
}

/// Enterprise Module 2: Live Attack Graph Builder
/// Constructs a live, mutable Directed Acyclic Graph (DAG) in-memory using lock-free data structures.
pub struct LiveAttackGraphBuilder {
    pub nodes: Arc<DashMap<NodeId, Node>>,
    pub edges: Arc<DashMap<NodeId, Vec<NodeId>>>, // Adjacency list
    pub report_tx: Sender<Finding>,
}

impl LiveAttackGraphBuilder {
    pub fn new(report_tx: Sender<Finding>) -> Self {
        Self {
            nodes: Arc::new(DashMap::new()),
            edges: Arc::new(DashMap::new()),
            report_tx,
        }
    }

    /// Dynamically update the graph when a new lateral movement path is discovered
    pub fn add_lateral_path(&self, source: NodeId, target: NodeId, risk_weight: f64) {
        // Ensure source exists (or create dummy)
        self.nodes.entry(source.clone()).or_insert(Node {
            service_name: "UnknownSource".into(),
            ip_address: source.0.clone(),
            risk_score: 0.0,
        });

        // Ensure target exists
        self.nodes.entry(target.clone()).or_insert(Node {
            service_name: "UnknownTarget".into(),
            ip_address: target.0.clone(),
            risk_score: risk_weight,
        });

        // Add edge
        self.edges.entry(source.clone()).or_default().push(target.clone());

        // Stream critical paths if condition met
        if risk_weight > 0.8 {
            self.stream_critical_path(&source, &target, risk_weight);
        }
    }

    fn stream_critical_path(&self, source: &NodeId, target: &NodeId, risk: f64) {
        let finding = Finding {
            severity: Severity::Critical,
            timestamp: chrono::Utc::now().to_rfc3339(),
            target_ip: target.0.clone(),
            probe_type: "Live Attack Graph Edge Inference".to_string(),
            observation_score: risk,
            details: format!("Critical lateral movement path identified: {} -> {}", source.0, target.0),
            attack_path: vec![format!("Source Node: {}", source.0), format!("Target Node: {}", target.0)],
        };

        // Fire and forget streaming report
        let _ = self.report_tx.try_send(finding);
    }
}
