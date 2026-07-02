use crate::auditor::{Auditor, SecurityEvent, Severity};
use anyhow::Result;
use async_trait::async_trait;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;

pub struct EphemeralPortSweepAuditor {
    pub ports: Vec<u16>,
}

#[async_trait]
impl Auditor for EphemeralPortSweepAuditor {
    fn name(&self) -> String {
        "Ephemeral Port Sweep".to_string()
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    async fn execute(&self, target: &str) -> Result<SecurityEvent> {
        let mut open_ports = Vec::new();

        for port in &self.ports {
            let addr = format!("{}:{}", target, port);
            if let Ok(Ok(_)) = timeout(Duration::from_millis(150), TcpStream::connect(&addr)).await {
                open_ports.push(*port);
            }
        }

        let is_vulnerable = !open_ports.is_empty();

        Ok(SecurityEvent::SimulationAlert {
            target: target.to_string(),
            check_name: self.name(),
            severity: self.severity(),
            is_vulnerable,
            details: if is_vulnerable {
                format!("Open ports detected: {:?}", open_ports)
            } else {
                "No unexpected open ports detected.".into()
            },
        })
    }
}
