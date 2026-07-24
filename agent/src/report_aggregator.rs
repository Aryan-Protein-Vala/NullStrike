use anyhow::Result;
use chrono::Utc;
use serde::Serialize;
use shared::SecurityEvent;

/// A single structured finding for the JSON report.
#[derive(Debug, Serialize)]
pub struct Finding {
    pub target: String,
    pub check_name: String,
    pub severity: String,
    pub is_vulnerable: bool,
    pub details: String,
    pub attack_path: Vec<String>,
}

/// The full aggregated report.
#[derive(Debug, Serialize)]
pub struct AuditReport {
    pub agent_id: String,
    pub hostname: String,
    pub timestamp: String,
    pub total_checks: usize,
    pub total_vulnerabilities: usize,
    pub severity_summary: SeveritySummary,
    pub findings: Vec<Finding>,
}

#[derive(Debug, Serialize)]
pub struct SeveritySummary {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
}

/// Collects SecurityEvents and writes a structured JSON report to disk.
pub struct ReportAggregator {
    pub agent_id: String,
    pub hostname: String,
    pub findings: Vec<Finding>,
}

impl ReportAggregator {
    pub fn new(agent_id: String, hostname: String) -> Self {
        Self {
            agent_id,
            hostname,
            findings: Vec::new(),
        }
    }

    /// Add a SecurityEvent to the report
    pub fn add_event(&mut self, event: &SecurityEvent) {
        match event {
            SecurityEvent::SimulationAlert {
                target,
                check_name,
                severity,
                is_vulnerable,
                details,
                attack_path,
            } => {
                self.findings.push(Finding {
                    target: target.clone(),
                    check_name: check_name.clone(),
                    severity: format!("{:?}", severity),
                    is_vulnerable: *is_vulnerable,
                    details: details.clone(),
                    attack_path: attack_path.clone(),
                });
            }
            SecurityEvent::Pass { target, check_name } => {
                self.findings.push(Finding {
                    target: target.clone(),
                    check_name: check_name.clone(),
                    severity: "Low".to_string(),
                    is_vulnerable: false,
                    details: "Check passed — no vulnerabilities found.".to_string(),
                    attack_path: vec![],
                });
            }
        }
    }

    /// Write the aggregated report to a JSON file.
    pub fn export_json(&self, output_path: &str) -> Result<()> {
        let vuln_count = self
            .findings
            .iter()
            .filter(|f| f.is_vulnerable)
            .count();

        let severity_summary = SeveritySummary {
            critical: self.findings.iter().filter(|f| f.severity == "Critical").count(),
            high: self.findings.iter().filter(|f| f.severity == "High").count(),
            medium: self.findings.iter().filter(|f| f.severity == "Medium").count(),
            low: self.findings.iter().filter(|f| f.severity == "Low").count(),
        };

        let report = AuditReport {
            agent_id: self.agent_id.clone(),
            hostname: self.hostname.clone(),
            timestamp: Utc::now().to_rfc3339(),
            total_checks: self.findings.len(),
            total_vulnerabilities: vuln_count,
            severity_summary,
            findings: self.findings.iter().map(|f| Finding {
                target: f.target.clone(),
                check_name: f.check_name.clone(),
                severity: f.severity.clone(),
                is_vulnerable: f.is_vulnerable,
                details: f.details.clone(),
                attack_path: f.attack_path.clone(),
            }).collect(),
        };

        let json = serde_json::to_string_pretty(&report)?;
        std::fs::write(output_path, json)?;

        println!("📄 Agent report exported to: {}", output_path);
        Ok(())
    }
}
