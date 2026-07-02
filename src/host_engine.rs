use crate::auditor::{Auditor, SecurityEvent, Severity};
use anyhow::Result;
use async_trait::async_trait;
use tokio::fs;

pub struct HostFileInspector {
    pub path: String,
}

#[async_trait]
impl Auditor for HostFileInspector {
    fn name(&self) -> String {
        format!("Host Inspector: {}", self.path)
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    async fn execute(&self, target: &str) -> Result<SecurityEvent> {
        let is_vulnerable = match fs::metadata(&self.path).await {
            Ok(metadata) => {
                !metadata.permissions().readonly()
            }
            Err(_) => false,
        };

        Ok(SecurityEvent::SimulationAlert {
            target: target.to_string(),
            check_name: self.name(),
            severity: self.severity(),
            is_vulnerable,
            details: if is_vulnerable {
                format!("File {} is exposed and modifiable.", self.path)
            } else {
                format!("File {} is secure or inaccessible.", self.path)
            },
        })
    }
}
