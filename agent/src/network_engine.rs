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
        
        let ip_addrs: Vec<std::net::IpAddr> = match tokio::net::lookup_host(format!("{}:80", target_str)).await {
            Ok(mut iter) => iter.map(|socket| socket.ip()).collect(),
            Err(_) => return Ok(SecurityEvent::Pass { target: target.to_string(), check_name: self.name() })
        };
        
        let target_ip = match ip_addrs.first() {
            Some(ip) => ip,
            None => return Ok(SecurityEvent::Pass { target: target.to_string(), check_name: self.name() })
        };

        for port in self.ports.clone() {
            let addr = std::net::SocketAddr::new(*target_ip, port);
            let task = tokio::spawn(async move {
                let res = timeout(Duration::from_millis(150), TcpStream::connect(addr)).await;
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

        if !open_ports.is_empty() {
            let details = format!("Open: {:?} | TimedOut: {:?}", open_ports, timeouts);
            Ok(SecurityEvent::SimulationAlert {
                target: target.to_string(),
                check_name: self.name(),
                severity: self.severity(),
                is_vulnerable: true,
                details,
                attack_path: vec![],
            })
        } else {
            Ok(SecurityEvent::Pass {
                target: target.to_string(),
                check_name: self.name(),
            })
        }
    }
}
