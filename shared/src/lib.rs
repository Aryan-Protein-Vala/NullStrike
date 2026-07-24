pub mod pb {
    tonic::include_proto!("nullstrike");
}

use serde::{Deserialize, Serialize};

pub mod agent_audit {
    use super::*;

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct Finding {
        pub severity: Severity,
        pub timestamp: String,
        pub target_ip: String,
        pub probe_type: String,
        pub observation_score: f64,
        pub details: String,
        pub attack_path: Vec<String>,
    }
}

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
    /// Kubernetes/container escape detection — runs 5 real checks
    KubernetesEscape,
    ApiDiscovery { subdomains: Vec<String>, endpoints: Vec<String> },
    /// DNS subdomain enumeration from a wordlist
    SubdomainAudit { wordlist: Vec<String> },
    /// TCP port probe for common services
    PortProbe { ports: Vec<u16> },
    /// HTTP endpoint discovery for common paths
    EndpointInspection { paths: Vec<String> },
    /// Detects input reflection (output encoding issues)
    InputReflection { paths: Vec<String> },
    /// HTTP security header audit
    HeaderAudit,
    /// TLS certificate & cipher inspection
    TlsInspection,
    /// Checks for exposed sensitive files (.env, .git/config, etc.)
    CredentialLeakCheck,
    /// SQL injection timing/error symptom detection (read-only)
    SqliSymptomDetection { paths: Vec<String> },
    /// GraphQL introspection query to map API surface
    GraphqlIntrospection,
    /// Run all audit modules in sequence
    FullAudit,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
}

/// A single node in the in-memory Attack Graph
#[derive(Debug, Clone, Serialize)]
pub struct AttackNode {
    pub id: String,
    pub label: String,
    pub node_type: AttackNodeType,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub enum AttackNodeType {
    Target,
    Vulnerability,
    Pivot, // future: lateral movement
}

#[derive(Debug, Serialize)]
pub enum SecurityEvent {
    SimulationAlert {
        target: String,
        check_name: String,
        severity: Severity,
        is_vulnerable: bool,
        details: String,
        /// Sub-findings for multi-check auditors (e.g. K8s escape has 5 sub-checks)
        attack_path: Vec<String>,
    },
    Pass {
        target: String,
        check_name: String,
    }
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
            SecurityEvent::Pass { .. } => false,
        }
    }
    pub fn severity(&self) -> &Severity {
        match self {
            SecurityEvent::SimulationAlert { severity, .. } => severity,
            SecurityEvent::Pass { .. } => &Severity::Low,
        }
    }
    pub fn target(&self) -> &str {
        match self {
            SecurityEvent::SimulationAlert { target, .. } => target,
            SecurityEvent::Pass { target, .. } => target,
        }
    }
    pub fn check_name(&self) -> &str {
        match self {
            SecurityEvent::SimulationAlert { check_name, .. } => check_name,
            SecurityEvent::Pass { check_name, .. } => check_name,
        }
    }
    pub fn details(&self) -> &str {
        match self {
            SecurityEvent::SimulationAlert { details, .. } => details,
            SecurityEvent::Pass { .. } => "Check passed successfully. No vulnerabilities found.",
        }
    }
}
