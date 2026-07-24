use crate::auditor::Auditor;
use anyhow::Result;
use async_trait::async_trait;
use shared::{SecurityEvent, Severity};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;

/// Well-known service ports for common services.
const DEFAULT_PORTS: &[u16] = &[
    21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
    993, 995, 3306, 3389, 5432, 6379, 8080, 8443, 9090, 9200,
];

/// Probes TCP ports to determine which services are listening.
/// This is a standard connect-scan — no payloads, no exploitation.
pub struct PortProber {
    pub ports: Vec<u16>,
}

impl PortProber {
    pub fn new(ports: Vec<u16>) -> Self {
        Self { ports }
    }

    pub fn default_ports() -> Self {
        Self {
            ports: DEFAULT_PORTS.to_vec(),
        }
    }

    fn port_service_hint(port: u16) -> &'static str {
        match port {
            21 => "FTP",
            22 => "SSH",
            23 => "Telnet",
            25 => "SMTP",
            53 => "DNS",
            80 => "HTTP",
            110 => "POP3",
            143 => "IMAP",
            443 => "HTTPS",
            445 => "SMB",
            993 => "IMAPS",
            995 => "POP3S",
            3306 => "MySQL",
            3389 => "RDP",
            5432 => "PostgreSQL",
            6379 => "Redis",
            8080 => "HTTP-Alt",
            8443 => "HTTPS-Alt",
            9090 => "Prometheus",
            9200 => "Elasticsearch",
            _ => "Unknown",
        }
    }
}

#[async_trait]
impl Auditor for PortProber {
    fn name(&self) -> String {
        "Port Prober".into()
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    async fn execute(&self, target: &str) -> Result<SecurityEvent> {
        // Resolve target to IP first
        let ip_addrs: Vec<std::net::IpAddr> =
            match tokio::net::lookup_host(format!("{}:80", target)).await {
                Ok(iter) => iter.map(|s| s.ip()).collect(),
                Err(_) => {
                    return Ok(SecurityEvent::Pass {
                        target: target.to_string(),
                        check_name: self.name(),
                    })
                }
            };

        let target_ip = match ip_addrs.first() {
            Some(ip) => *ip,
            None => {
                return Ok(SecurityEvent::Pass {
                    target: target.to_string(),
                    check_name: self.name(),
                })
            }
        };

        // Fan-out all port probes concurrently
        let mut tasks = Vec::with_capacity(self.ports.len());
        for &port in &self.ports {
            let addr = SocketAddr::new(target_ip, port);
            tasks.push(tokio::spawn(async move {
                let result = timeout(Duration::from_millis(200), TcpStream::connect(addr)).await;
                (port, result)
            }));
        }

        let mut attack_path = Vec::new();
        let mut open_count = 0u32;

        for task in tasks {
            if let Ok((port, result)) = task.await {
                match result {
                    Ok(Ok(_)) => {
                        open_count += 1;
                        let svc = Self::port_service_hint(port);
                        attack_path.push(format!("OPEN: port {} ({}) on {}", port, svc, target));
                    }
                    _ => {} // closed or timed out — not reported
                }
            }
        }

        if open_count > 0 {
            Ok(SecurityEvent::SimulationAlert {
                target: target.to_string(),
                check_name: self.name(),
                severity: self.severity(),
                is_vulnerable: true,
                details: format!("{} open port(s) detected on {}", open_count, target),
                attack_path,
            })
        } else {
            Ok(SecurityEvent::Pass {
                target: target.to_string(),
                check_name: self.name(),
            })
        }
    }
}
