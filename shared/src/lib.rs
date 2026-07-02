pub mod pb {
    tonic::include_proto!("nullstrike");
}

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Playbook {
    pub name: String,
    pub description: String,
    pub targets: Vec<String>,
    pub checks: Vec<CheckType>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type")]
pub enum CheckType {
    IamRoleAssumption { role_arn: String },
    EphemeralPortSweep { ports: Vec<u16> },
    ContainerNamespaceVerification { namespace: String },
    HostFileInspector { paths: Vec<String> },
    LuaPlugin { script_path: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
}

#[derive(Debug, Serialize)]
pub enum SecurityEvent {
    SimulationAlert {
        target: String,
        check_name: String,
        severity: Severity,
        is_vulnerable: bool,
        details: String,
    },
}

impl Playbook {
    pub fn from_yaml_str(content: &str) -> anyhow::Result<Self> {
        let playbook: Playbook = serde_yaml::from_str(content)?;
        Ok(playbook)
    }
}

impl SecurityEvent {
    pub fn is_vulnerable(&self) -> bool {
        match self {
            SecurityEvent::SimulationAlert { is_vulnerable, .. } => *is_vulnerable,
        }
    }
    pub fn severity(&self) -> &Severity {
        match self {
            SecurityEvent::SimulationAlert { severity, .. } => severity,
        }
    }
    pub fn target(&self) -> &str {
        match self {
            SecurityEvent::SimulationAlert { target, .. } => target,
        }
    }
    pub fn check_name(&self) -> &str {
        match self {
            SecurityEvent::SimulationAlert { check_name, .. } => check_name,
        }
    }
    pub fn details(&self) -> &str {
        match self {
            SecurityEvent::SimulationAlert { details, .. } => details,
        }
    }
}
