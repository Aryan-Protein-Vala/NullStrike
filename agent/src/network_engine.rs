use crate::auditor::Auditor;
use shared::{SecurityEvent, Severity};
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
        Severity::High
    }

    async fn execute(&self, target: &str) -> Result<SecurityEvent> {
        let mut tasks = Vec::new();
        
        let target_str = target.to_string();
        for port in self.ports.clone() {
            let addr = format!("{}:{}", target_str, port);
            let task = tokio::spawn(async move {
                let res = timeout(Duration::from_millis(150), TcpStream::connect(&addr)).await;
                (port, res)
            });
            tasks.push(task);
        }

        let mut open_ports = Vec::new();
        let mut timeouts = Vec::new();

        for task in tasks {
            let (port, res) = task.await?;
            match res {
                Ok(Ok(_)) => open_ports.push(port),
                Ok(Err(_)) => {}, // Closed
                Err(_) => timeouts.push(port), // Timeout
            }
        }

        let is_vulnerable = !open_ports.is_empty();

        let details = if is_vulnerable {
            format!("Open: {:?} | TimedOut: {:?}", open_ports, timeouts)
        } else {
            format!("No exposed ports found. TimedOut: {:?}", timeouts)
        };

        Ok(SecurityEvent::SimulationAlert {
            target: target.to_string(),
            check_name: self.name(),
            severity: self.severity(),
            is_vulnerable,
            details,
            attack_path: vec![],
        })
    }
}
