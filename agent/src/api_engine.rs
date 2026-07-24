use crate::auditor::Auditor;
use anyhow::Result;
use async_trait::async_trait;
use reqwest::{Client, StatusCode};
use shared::{SecurityEvent, Severity};
use tokio::net::lookup_host;

pub struct ApiDiscoveryAuditor {
    pub subdomains: Vec<String>,
    pub endpoints: Vec<String>,
    pub client: Client,
}

impl ApiDiscoveryAuditor {
    pub fn new(subdomains: Vec<String>, endpoints: Vec<String>) -> Self {
        // A simple client with a timeout, skipping SSL errors for internal testing
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(3))
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap_or_default();
            
        Self {
            subdomains,
            endpoints,
            client,
        }
    }
}

#[async_trait]
impl Auditor for ApiDiscoveryAuditor {
    fn name(&self) -> String {
        "API Discovery & Subdomain Recon".into()
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    async fn execute(&self, target: &str) -> Result<SecurityEvent> {
        let mut attack_path = Vec::new();
        let mut is_vulnerable = false;
        
        // Step 1: Subdomain Enumeration
        let mut active_hosts = vec![target.to_string()];
        
        for sub in &self.subdomains {
            let host_to_check = format!("{}.{}", sub, target);
            // Quick DNS resolution check (requires port so we use 80 temporarily)
            if let Ok(mut addrs) = lookup_host(format!("{}:80", host_to_check)).await {
                if addrs.next().is_some() {
                    attack_path.push(format!("Resolved subdomain: {}", host_to_check));
                    active_hosts.push(host_to_check);
                }
            }
        }
        
        // Step 2: Endpoint Scanning & Header Analysis
        for host in active_hosts {
            for endpoint in &self.endpoints {
                // Ensure the endpoint starts with a slash
                let ep = if endpoint.starts_with('/') {
                    endpoint.to_string()
                } else {
                    format!("/{}", endpoint)
                };
                
                // Try HTTPS first, then HTTP if needed. For simplicity we try HTTP in this module.
                let url = format!("http://{}{}", host, ep);
                
                if let Ok(resp) = self.client.get(&url).send().await {
                    let status = resp.status();
                    if status.is_success() || status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
                        attack_path.push(format!("Discovered Endpoint: {} [{}]", url, status));
                        
                        let headers = resp.headers();
                        
                        // Check for permissive CORS
                        if let Some(cors) = headers.get("access-control-allow-origin") {
                            if cors == "*" {
                                attack_path.push(format!("VULNERABILITY (CORS): Wildcard origin allowed at {}", url));
                                is_vulnerable = true;
                            }
                        }
                        
                        // Check for missing HSTS (often missing on internal endpoints, but good practice to flag)
                        if !headers.contains_key("strict-transport-security") {
                            attack_path.push(format!("MISCONFIGURATION: Missing HSTS header at {}", url));
                        }
                        
                        // Check for missing CSP
                        if !headers.contains_key("content-security-policy") {
                            attack_path.push(format!("MISCONFIGURATION: Missing CSP header at {}", url));
                        }
                    }
                }
            }
        }
        
        if is_vulnerable || !attack_path.is_empty() {
            Ok(SecurityEvent::SimulationAlert {
                target: target.to_string(),
                check_name: self.name(),
                severity: self.severity(),
                is_vulnerable: true, // We mark true if we found endpoints or vulnerabilities
                details: "Discovered internal API endpoints and/or security header misconfigurations.".to_string(),
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
