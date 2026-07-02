use serde::{Deserialize, Serialize};
use anyhow::{Result, bail};
use std::fs;

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
    HostFileInspector { path: String },
}

impl Playbook {
    pub fn from_yaml_file(path: &str) -> Result<Self> {
        let content = fs::read_to_string(path)?;
        let playbook: Playbook = serde_yaml::from_str(&content)?;
        playbook.validate()?;
        Ok(playbook)
    }

    pub fn validate(&self) -> Result<()> {
        if self.targets.is_empty() {
            bail!("Playbook must have at least one target defined.");
        }
        if self.checks.is_empty() {
            bail!("Playbook must define at least one security check.");
        }
        
        for check in &self.checks {
            match check {
                CheckType::EphemeralPortSweep { ports } => {
                    if ports.len() > 1000 {
                        bail!("Port sweep exceeds maximum safe limit of 1000 ports to prevent connection exhaustion.");
                    }
                }
                CheckType::HostFileInspector { path } => {
                    if path.contains("..") {
                        bail!("Path traversal detected in HostFileInspector path: {}", path);
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }
}
