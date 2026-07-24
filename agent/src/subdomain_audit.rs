use crate::auditor::Auditor;
use anyhow::Result;
use async_trait::async_trait;
use shared::{SecurityEvent, Severity};
use tokio::net::lookup_host;

/// Enumerates subdomains by attempting DNS resolution against a provided wordlist.
/// This is a passive, read-only DNS lookup — no zone transfers or brute-force attacks.
pub struct SubdomainAuditor {
    pub wordlist: Vec<String>,
}

#[async_trait]
impl Auditor for SubdomainAuditor {
    fn name(&self) -> String {
        "Subdomain Audit".into()
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    async fn execute(&self, target: &str) -> Result<SecurityEvent> {
        let mut attack_path = Vec::new();
        let mut resolved_count: usize = 0;

        for sub in &self.wordlist {
            let fqdn = format!("{}.{}", sub, target);
            // lookup_host requires host:port — we use port 80 as a dummy
            if let Ok(mut addrs) = lookup_host(format!("{}:80", fqdn)).await {
                if let Some(addr) = addrs.next() {
                    resolved_count += 1;
                    attack_path.push(format!(
                        "RESOLVED: {} -> {}", fqdn, addr.ip()
                    ));
                }
            }
        }

        if resolved_count > 0 {
            Ok(SecurityEvent::SimulationAlert {
                target: target.to_string(),
                check_name: self.name(),
                severity: self.severity(),
                is_vulnerable: true,
                details: format!(
                    "Discovered {} resolvable subdomain(s) out of {} tested.",
                    resolved_count,
                    self.wordlist.len()
                ),
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
