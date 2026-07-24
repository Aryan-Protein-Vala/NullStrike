use crate::auditor::Auditor;
use anyhow::Result;
use async_trait::async_trait;
use shared::{SecurityEvent, Severity};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;

/// Well-known service ports — top 30 for comprehensive coverage.
const DEFAULT_PORTS: &[u16] = &[
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
    993, 995, 1433, 1521, 2049, 3306, 3389, 5432, 5900, 6379,
    8080, 8443, 9090, 9200, 11211, 27017, 50051,
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
            111 => "rpcbind",
            135 => "MSRPC",
            139 => "NetBIOS",
            143 => "IMAP",
            443 => "HTTPS",
            445 => "SMB",
            993 => "IMAPS",
            995 => "POP3S",
            1433 => "MSSQL",
            1521 => "Oracle",
            2049 => "NFS",
            3306 => "MySQL",
            3389 => "RDP",
            5432 => "PostgreSQL",
            5900 => "VNC",
            6379 => "Redis",
            8080 => "HTTP-Alt",
            8443 => "HTTPS-Alt",
            9090 => "Prometheus",
            9200 => "Elasticsearch",
            11211 => "Memcached",
            27017 => "MongoDB",
            50051 => "gRPC",
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
                let result = timeout(Duration::from_secs(3), TcpStream::connect(addr)).await;
                match result {
                    Ok(Ok(mut stream)) => {
                        // Attempt banner grab — read whatever the server sends within 500ms
                        use tokio::io::AsyncReadExt;
                        let mut banner_buf = vec![0u8; 256];
                        let banner = match timeout(
                            Duration::from_millis(500),
                            stream.read(&mut banner_buf),
                        )
                        .await
                        {
                            Ok(Ok(n)) if n > 0 => {
                                String::from_utf8_lossy(&banner_buf[..n])
                                    .trim()
                                    .chars()
                                    .take(80)
                                    .collect::<String>()
                            }
                            _ => String::new(),
                        };
                        (port, true, banner)
                    }
                    _ => (port, false, String::new()),
                }
            }));
        }

        let mut attack_path = Vec::new();
        let mut open_count = 0u32;

        for task in tasks {
            if let Ok((port, is_open, banner)) = task.await {
                if is_open {
                    open_count += 1;
                    let svc = Self::port_service_hint(port);
                    if banner.is_empty() {
                        attack_path.push(format!("OPEN: port {} ({}) on {}", port, svc, target));
                    } else {
                        attack_path.push(format!(
                            "OPEN: port {} ({}) on {} | Banner: {}",
                            port, svc, target, banner
                        ));
                    }
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
