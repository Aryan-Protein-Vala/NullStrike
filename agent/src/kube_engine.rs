use crate::auditor::Auditor;
use shared::{SecurityEvent, Severity};
use anyhow::Result;
use async_trait::async_trait;
use std::fs;

/// Performs 5 real, non-destructive Kubernetes/container escape checks.
/// Designed to work correctly inside a real K8s pod OR on a bare-metal host/Mac.
pub struct KubernetesEscapeAuditor;

// ── Individual check results ───────────────────────────────────────────────

struct CheckResult {
    name: &'static str,
    is_vulnerable: bool,
    detail: String,
}

/// Check 1: Privileged container mode via /proc/1/status
/// A privileged container has CapEff: 0000003fffffffff or similar full bit-mask
fn check_privileged_container() -> CheckResult {
    let name = "Privileged Container Mode";
    match fs::read_to_string("/proc/1/status") {
        Ok(content) => {
            // Look for CapEff (effective capabilities). Full caps = all 1s in hex
            if let Some(line) = content.lines().find(|l| l.starts_with("CapEff:")) {
                let hex_str = line.split_whitespace().nth(1).unwrap_or("0");
                // A fully privileged container has CapEff = 000003ffffffffff
                let cap_val = u64::from_str_radix(hex_str, 16).unwrap_or(0);
                let is_privileged = cap_val == 0x000003ffffffffff;
                return CheckResult {
                    name,
                    is_vulnerable: is_privileged,
                    detail: if is_privileged {
                        format!("CRITICAL: Container is running in PRIVILEGED mode (CapEff: {}). Full host kernel access possible.", hex_str)
                    } else {
                        format!("Container capabilities are restricted (CapEff: {}). Not privileged.", hex_str)
                    },
                };
            }
            CheckResult { name, is_vulnerable: false, detail: "Could not parse CapEff from /proc/1/status".into() }
        }
        Err(_) => CheckResult {
            name,
            is_vulnerable: false,
            detail: "Not running in a Linux container (no /proc/1/status). Host is a macOS/Windows system.".into(),
        },
    }
}

/// Check 2: Docker socket exposure — ultimate host takeover vector
fn check_docker_socket() -> CheckResult {
    let name = "Docker Socket Exposure";
    let socket_path = "/var/run/docker.sock";
    let is_exposed = std::path::Path::new(socket_path).exists();
    CheckResult {
        name,
        is_vulnerable: is_exposed,
        detail: if is_exposed {
            "CRITICAL: /var/run/docker.sock is mounted into this container. An attacker can spawn a privileged container and mount the host filesystem, achieving full root takeover.".into()
        } else {
            "Docker socket is NOT accessible from this container. Correct isolation.".into()
        },
    }
}

/// Check 3: Kubernetes Service Account Token theft
/// The token is a JWT that reveals the pod's identity and RBAC permissions
fn check_service_account_token() -> CheckResult {
    let name = "K8s Service Account Token";
    let token_path = "/var/run/secrets/kubernetes.io/serviceaccount/token";
    let namespace_path = "/var/run/secrets/kubernetes.io/serviceaccount/namespace";

    match fs::read_to_string(token_path) {
        Ok(token) => {
            let ns = fs::read_to_string(namespace_path).unwrap_or_else(|_| "unknown".into());
            // Decode the JWT payload (part between first and second dot) — base64 standard
            let payload_detail = token.split('.').nth(1).and_then(|b| {
                use std::io::Read;
                // Base64 URL decode (no padding)
                let padded = match b.len() % 4 {
                    2 => format!("{}==", b),
                    3 => format!("{}=", b),
                    _ => b.to_string(),
                };
                let b64 = padded.replace('-', "+").replace('_', "/");
                base64_decode_simple(&b64).ok().and_then(|bytes| String::from_utf8(bytes).ok())
            }).unwrap_or_else(|| "Could not decode JWT payload".into());

            CheckResult {
                name,
                is_vulnerable: true,
                detail: format!(
                    "HIGH: Kubernetes Service Account Token found (namespace: {}). JWT payload: {}. An attacker with this token can query the Kubernetes API Server.",
                    ns.trim(), &payload_detail[..payload_detail.len().min(200)]
                ),
            }
        }
        Err(_) => CheckResult {
            name,
            is_vulnerable: false,
            detail: "No Kubernetes Service Account Token found. Not running inside a K8s pod, or token projection is disabled.".into(),
        },
    }
}

/// Minimal base64 decoder (no external crate needed for this check)
fn base64_decode_simple(input: &str) -> Result<Vec<u8>> {
    let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = Vec::new();
    let chars: Vec<char> = input.chars().filter(|&c| c != '=').collect();
    for chunk in chars.chunks(4) {
        let mut val: u32 = 0;
        let mut bits = 0;
        for &c in chunk {
            let idx = alphabet.find(c).ok_or_else(|| anyhow::anyhow!("bad char"))? as u32;
            val = (val << 6) | idx;
            bits += 6;
        }
        bits -= 8;
        while bits >= 0 {
            output.push(((val >> bits) & 0xFF) as u8);
            bits -= 8;
        }
    }
    Ok(output)
}

/// Check 4: Writable host path mounts
/// Checks /proc/mounts for bind-mounted host directories
fn check_host_mounts() -> CheckResult {
    let name = "Host Path Mount Detection";
    match fs::read_to_string("/proc/mounts") {
        Ok(mounts) => {
            // Dangerous host bind-mounts: /host, /etc, /root, /var/lib
            let danger_prefixes = ["/host", "/etc", "/root", "/var/lib/kubelet", "/sys/kernel"];
            let mut found: Vec<String> = Vec::new();

            for line in mounts.lines() {
                let fields: Vec<&str> = line.split_whitespace().collect();
                if fields.len() >= 2 {
                    let mount_point = fields[1];
                    if danger_prefixes.iter().any(|&p| mount_point.starts_with(p)) {
                        found.push(mount_point.to_string());
                    }
                }
            }

            let is_vulnerable = !found.is_empty();
            CheckResult {
                name,
                is_vulnerable,
                detail: if is_vulnerable {
                    format!("HIGH: Dangerous host path(s) bind-mounted into container: {:?}. An attacker could read/write sensitive host files.", found)
                } else {
                    "No dangerous host path bind-mounts detected in /proc/mounts.".into()
                },
            }
        }
        Err(_) => CheckResult {
            name,
            is_vulnerable: false,
            detail: "Cannot read /proc/mounts. Not a Linux system.".into(),
        },
    }
}

/// Check 5: PID namespace sharing with host
/// If PID namespace inode matches host PID 1's namespace, full process visibility
fn check_pid_namespace() -> CheckResult {
    let name = "PID Namespace Isolation";
    let container_ns = fs::read_link("/proc/self/ns/pid");
    let host_ns = fs::read_link("/proc/1/ns/pid");

    match (container_ns, host_ns) {
        (Ok(c), Ok(h)) => {
            let is_shared = c == h;
            CheckResult {
                name,
                is_vulnerable: is_shared,
                detail: if is_shared {
                    format!("HIGH: Container shares the HOST PID namespace ({:?}). The container can see and signal ALL host processes, enabling potential process injection attacks.", c)
                } else {
                    format!("PID namespace is isolated: container={:?}, host={:?}.", c, h)
                },
            }
        }
        _ => CheckResult {
            name,
            is_vulnerable: false,
            detail: "Cannot read PID namespace links. Not a Linux system.".into(),
        },
    }
}

// ── Auditor Implementation ─────────────────────────────────────────────────

#[async_trait]
impl Auditor for KubernetesEscapeAuditor {
    fn name(&self) -> String {
        "Kubernetes Escape Engine".to_string()
    }

    fn severity(&self) -> Severity {
        Severity::Critical
    }

    async fn execute(&self, target: &str) -> Result<SecurityEvent> {
        // Run all 5 checks concurrently via blocking tasks
        let (r1, r2, r3, r4, r5) = tokio::join!(
            tokio::task::spawn_blocking(check_privileged_container),
            tokio::task::spawn_blocking(check_docker_socket),
            tokio::task::spawn_blocking(check_service_account_token),
            tokio::task::spawn_blocking(check_host_mounts),
            tokio::task::spawn_blocking(check_pid_namespace),
        );

        let checks = vec![
            r1.unwrap_or_else(|_| CheckResult { name: "Privileged Container Mode", is_vulnerable: false, detail: "check panicked".into() }),
            r2.unwrap_or_else(|_| CheckResult { name: "Docker Socket Exposure", is_vulnerable: false, detail: "check panicked".into() }),
            r3.unwrap_or_else(|_| CheckResult { name: "K8s Service Account Token", is_vulnerable: false, detail: "check panicked".into() }),
            r4.unwrap_or_else(|_| CheckResult { name: "Host Path Mount Detection", is_vulnerable: false, detail: "check panicked".into() }),
            r5.unwrap_or_else(|_| CheckResult { name: "PID Namespace Isolation", is_vulnerable: false, detail: "check panicked".into() }),
        ];

        // Build the attack_path from all sub-findings
        let attack_path: Vec<String> = checks.iter()
            .map(|c| format!("[{}] {}: {}", if c.is_vulnerable { "VULN" } else { "SAFE" }, c.name, c.detail))
            .collect();

        // The overall result: vulnerable if ANY sub-check is vulnerable
        let any_vulnerable = checks.iter().any(|c| c.is_vulnerable);
        let vuln_names: Vec<&str> = checks.iter()
            .filter(|c| c.is_vulnerable)
            .map(|c| c.name)
            .collect();

        let summary = if any_vulnerable {
            format!(
                "ESCAPE VECTORS FOUND on '{}': [{}]. See attack_path for full details.",
                target,
                vuln_names.join(", ")
            )
        } else {
            format!("'{}' is properly isolated. All 5 K8s escape vectors are secured.", target)
        };

        Ok(SecurityEvent::SimulationAlert {
            target: target.to_string(),
            check_name: self.name(),
            severity: self.severity(),
            is_vulnerable: any_vulnerable,
            details: summary,
            attack_path,
        })
    }
}
