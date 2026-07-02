use serde::Serialize;
use anyhow::Result;
use async_trait::async_trait;

#[derive(Debug, Clone, Serialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize)]
pub enum SecurityEvent {
    SimulationAlert {
        target: String,
        check_name: String,
        severity: Severity,
        is_vulnerable: bool,
        details: String,
        attack_path: Vec<String>,
    },
    Pass {
        target: String,
        check_name: String,
    }
}

impl SecurityEvent {
    pub fn is_vulnerable(&self) -> bool {
        match self {
            SecurityEvent::SimulationAlert { is_vulnerable, .. } => *is_vulnerable,
            SecurityEvent::Pass { .. } => false,
        }
    }
    
    pub fn severity(&self) -> &Severity {
        match self {
            SecurityEvent::SimulationAlert { severity, .. } => severity,
            SecurityEvent::Pass { .. } => &Severity::Low,
        }
    }

    pub fn check_name(&self) -> &str {
        match self {
            SecurityEvent::SimulationAlert { check_name, .. } => check_name,
            SecurityEvent::Pass { check_name, .. } => check_name,
        }
    }
    
    pub fn target(&self) -> &str {
        match self {
            SecurityEvent::SimulationAlert { target, .. } => target,
            SecurityEvent::Pass { target, .. } => target,
        }
    }

    pub fn details(&self) -> &str {
        match self {
            SecurityEvent::SimulationAlert { details, .. } => details,
            SecurityEvent::Pass { .. } => "Check passed successfully. No vulnerabilities found.",
        }
    }
}

#[async_trait]
pub trait Auditor: Send + Sync {
    fn name(&self) -> String;
    fn severity(&self) -> Severity;
    async fn execute(&self, target: &str) -> Result<SecurityEvent>;
}
