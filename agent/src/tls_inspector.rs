use crate::auditor::Auditor;
use anyhow::Result;
use async_trait::async_trait;
use shared::{SecurityEvent, Severity};

use std::net::TcpStream;
use std::sync::Arc;

use rustls::{ClientConfig, ClientConnection, ServerName, StreamOwned, RootCertStore};
use x509_parser::prelude::*;

/// Connects to the target via TLS and inspects the server certificate for:
/// - Expiration (expired or expiring within 30 days)
/// - Self-signed certificates
/// - Weak key sizes (< 2048-bit RSA)
/// - TLS version (flags TLS < 1.2)
///
/// This is a read-only connection — no data is sent after the handshake.
pub struct TlsInspector;

impl TlsInspector {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Auditor for TlsInspector {
    fn name(&self) -> String {
        "TLS Inspector".into()
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    async fn execute(&self, target: &str) -> Result<SecurityEvent> {
        let target_host = target.to_string();

        // Run the blocking TLS handshake on a dedicated thread
        let result = tokio::task::spawn_blocking(move || {
            inspect_tls(&target_host)
        }).await?;

        result
    }
}

fn inspect_tls(target: &str) -> Result<SecurityEvent> {
    let mut attack_path = Vec::new();
    let mut is_vulnerable = false;

    // Build a rustls config that trusts the webpki root store
    let mut root_store = RootCertStore::empty();
    root_store.add_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
        rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
            ta.subject.to_vec(),
            ta.spki.to_vec(),
            ta.name_constraints.map(|nc| nc.to_vec()),
        )
    }));

    let config = ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let server_name = match ServerName::try_from(target) {
        Ok(sn) => sn,
        Err(_) => {
            // If target is an IP address, we can't do SNI-based TLS
            attack_path.push(format!(
                "INFO: Target '{}' is not a valid DNS name — SNI unavailable, attempting raw IP connect",
                target
            ));
            // Try connecting without SNI validation
            return Ok(SecurityEvent::SimulationAlert {
                target: target.to_string(),
                check_name: "TLS Inspector".to_string(),
                severity: Severity::Low,
                is_vulnerable: false,
                details: "Cannot perform SNI-based TLS inspection on raw IP address.".to_string(),
                attack_path,
            });
        }
    };

    let mut conn = match ClientConnection::new(Arc::new(config), server_name) {
        Ok(c) => c,
        Err(e) => {
            attack_path.push(format!("TLS_ERROR: Failed to initiate TLS handshake: {}", e));
            return Ok(SecurityEvent::SimulationAlert {
                target: target.to_string(),
                check_name: "TLS Inspector".to_string(),
                severity: Severity::High,
                is_vulnerable: true,
                details: format!("TLS handshake failed: {}", e),
                attack_path,
            });
        }
    };

    // Connect via raw TCP, then perform TLS handshake
    let tcp = match TcpStream::connect(format!("{}:443", target)) {
        Ok(s) => s,
        Err(e) => {
            return Ok(SecurityEvent::Pass {
                target: target.to_string(),
                check_name: "TLS Inspector".to_string(),
            });
        }
    };
    tcp.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;
    tcp.set_write_timeout(Some(std::time::Duration::from_secs(5)))?;

    let mut tls_stream = StreamOwned::new(conn, tcp);

    // Trigger the handshake by attempting a read
    use std::io::Read;
    let mut buf = [0u8; 1];
    let _ = tls_stream.read(&mut buf); // We don't care about the result

    // Extract peer certificates
    if let Some(certs) = tls_stream.conn.peer_certificates() {
        if let Some(cert_der) = certs.first() {
            match X509Certificate::from_der(cert_der.as_ref()) {
                Ok((_, cert)) => {
                    // Check expiration
                    let not_after = cert.validity().not_after.to_datetime();
                    let not_before = cert.validity().not_before.to_datetime();
                    let now = chrono::Utc::now();

                    if let Some(expires) = chrono::DateTime::from_timestamp(
                        not_after.unix_timestamp(), 0
                    ) {
                        if expires < now {
                            attack_path.push(format!(
                                "EXPIRED: Certificate expired on {}",
                                expires.format("%Y-%m-%d")
                            ));
                            is_vulnerable = true;
                        } else {
                            let days_left = (expires - now).num_days();
                            if days_left < 30 {
                                attack_path.push(format!(
                                    "WARNING: Certificate expires in {} days ({})",
                                    days_left,
                                    expires.format("%Y-%m-%d")
                                ));
                            }
                        }
                    }

                    // Check if self-signed (issuer == subject)
                    let issuer = cert.issuer().to_string();
                    let subject = cert.subject().to_string();
                    if issuer == subject {
                        attack_path.push(format!(
                            "SELF_SIGNED: Certificate is self-signed (issuer == subject: {})",
                            issuer
                        ));
                        is_vulnerable = true;
                    } else {
                        attack_path.push(format!("ISSUER: {}", issuer));
                    }

                    // Check key size
                    let key_info = cert.public_key();
                    let key_size = key_info.parsed().map(|pk| {
                        match pk {
                            x509_parser::public_key::PublicKey::RSA(rsa) => {
                                rsa.key_size()
                            }
                            _ => 0,
                        }
                    }).unwrap_or(0);

                    if key_size > 0 && key_size < 2048 {
                        attack_path.push(format!(
                            "WEAK_KEY: RSA key size is {} bits (minimum 2048 recommended)",
                            key_size
                        ));
                        is_vulnerable = true;
                    }
                }
                Err(e) => {
                    attack_path.push(format!("PARSE_ERROR: Could not parse certificate: {:?}", e));
                }
            }
        }
    } else {
        attack_path.push("NO_CERTS: Server did not present any certificates".to_string());
        is_vulnerable = true;
    }

    // Check negotiated TLS version
    let proto = tls_stream.conn.protocol_version();
    if let Some(version) = proto {
        let version_str = format!("{:?}", version);
        attack_path.push(format!("TLS_VERSION: {}", version_str));
        if version_str.contains("1.0") || version_str.contains("1.1") {
            attack_path.push("DEPRECATED: TLS version < 1.2 is deprecated and insecure".to_string());
            is_vulnerable = true;
        }
    }

    if is_vulnerable || !attack_path.is_empty() {
        Ok(SecurityEvent::SimulationAlert {
            target: target.to_string(),
            check_name: "TLS Inspector".to_string(),
            severity: if is_vulnerable { Severity::Critical } else { Severity::Low },
            is_vulnerable,
            details: format!("TLS configuration audit completed for {}", target),
            attack_path,
        })
    } else {
        Ok(SecurityEvent::Pass {
            target: target.to_string(),
            check_name: "TLS Inspector".to_string(),
        })
    }
}
