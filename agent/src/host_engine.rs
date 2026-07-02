use crate::auditor::Auditor;
use shared::{SecurityEvent, Severity};
use anyhow::Result;
use async_trait::async_trait;
use std::os::unix::fs::PermissionsExt;
use sysinfo::System;

pub struct HostInspectorAuditor {
    pub paths: Vec<String>,
}

#[async_trait]
impl Auditor for HostInspectorAuditor {
    fn name(&self) -> String {
        "Host Configuration & Service Audit".to_string()
    }

    fn severity(&self) -> Severity {
        Severity::Critical
    }

    async fn execute(&self, target: &str) -> Result<SecurityEvent> {
        let mut issues = Vec::new();

        for path in &self.paths {
            if let Ok(metadata) = std::fs::metadata(path) {
                let mode = metadata.permissions().mode();
                if mode & 0o002 != 0 {
                    issues.push(format!("File {} is world-writable ({:o})", path, mode));
                }
            }
        }

        let mut sys = System::new_all();
        sys.refresh_all();
        
        let mut root_processes = 0;
        for (_pid, process) in sys.processes() {
            if let Some(uid) = process.user_id() {
                if uid.to_string() == "0" {
                    root_processes += 1;
                }
            }
        }
        
        if root_processes > 50 {
            issues.push(format!("High number of root-privileged processes detected: {}", root_processes));
        }

        let is_vulnerable = !issues.is_empty();

        Ok(SecurityEvent::SimulationAlert {
            target: target.to_string(),
            check_name: self.name(),
            severity: self.severity(),
            is_vulnerable,
            details: if is_vulnerable {
                issues.join("; ")
            } else {
                "Host configuration and services are secure.".into()
            },
            attack_path: vec![],
        })
    }
}
