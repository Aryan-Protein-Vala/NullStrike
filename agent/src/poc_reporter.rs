use anyhow::Result;
use chrono::Utc;
use serde::Serialize;
use shared::SecurityEvent;
use tera::{Context, Tera};

/// A single structured finding for reports.
#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub target: String,
    pub check_name: String,
    pub severity: String,
    pub is_vulnerable: bool,
    pub details: String,
    pub attack_path: Vec<String>,
    pub timestamp: String,
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

/// Proof-of-Concept Reporter — collects all findings and exports JSON + HTML reports.
pub struct PocReporter {
    pub agent_id: String,
    pub hostname: String,
    pub findings: Vec<Finding>,
}

impl PocReporter {
    pub fn new(agent_id: String, hostname: String) -> Self {
        Self {
            agent_id,
            hostname,
            findings: Vec::new(),
        }
    }

    /// Add a SecurityEvent to the report.
    pub fn add_event(&mut self, event: &SecurityEvent) {
        let ts = Utc::now().to_rfc3339();
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
                    timestamp: ts,
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
                    timestamp: ts,
                });
            }
        }
    }

    fn build_report(&self) -> AuditReport {
        let vuln_count = self.findings.iter().filter(|f| f.is_vulnerable).count();
        AuditReport {
            agent_id: self.agent_id.clone(),
            hostname: self.hostname.clone(),
            timestamp: Utc::now().to_rfc3339(),
            total_checks: self.findings.len(),
            total_vulnerabilities: vuln_count,
            severity_summary: SeveritySummary {
                critical: self.findings.iter().filter(|f| f.severity == "Critical").count(),
                high: self.findings.iter().filter(|f| f.severity == "High").count(),
                medium: self.findings.iter().filter(|f| f.severity == "Medium").count(),
                low: self.findings.iter().filter(|f| f.severity == "Low").count(),
            },
            findings: self.findings.clone(),
        }
    }

    /// Write JSON report to disk.
    pub fn export_json(&self, path: &str) -> Result<()> {
        let report = self.build_report();
        let json = serde_json::to_string_pretty(&report)?;
        std::fs::write(path, json)?;
        println!("📄 JSON report exported to: {}", path);
        Ok(())
    }

    /// Write an HTML Proof-of-Concept report to disk using Tera templates.
    pub fn export_html(&self, path: &str) -> Result<()> {
        let report = self.build_report();

        let mut tera = Tera::default();
        tera.add_raw_template("report.html", HTML_TEMPLATE)?;

        let mut ctx = Context::new();
        ctx.insert("report", &report);

        let rendered = tera.render("report.html", &ctx)?;
        std::fs::write(path, rendered)?;
        println!("🌐 HTML report exported to: {}", path);
        Ok(())
    }
}

/// Embedded HTML template for the PoC report.
const HTML_TEMPLATE: &str = r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>NullStrike Audit Report</title>
<style>
  :root { --bg: #0d1117; --card: #161b22; --border: #30363d; --text: #c9d1d9;
           --critical: #f85149; --high: #f0883e; --medium: #d29922; --low: #58a6ff; }
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { background: var(--bg); color: var(--text); font-family: 'Inter', -apple-system, sans-serif; padding: 2rem; }
  h1 { font-size: 2rem; margin-bottom: 0.5rem; background: linear-gradient(135deg, #58a6ff, #f0883e);
       -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
  .meta { color: #8b949e; margin-bottom: 2rem; font-size: 0.9rem; }
  .summary { display: grid; grid-template-columns: repeat(4, 1fr); gap: 1rem; margin-bottom: 2rem; }
  .summary-card { background: var(--card); border: 1px solid var(--border); border-radius: 12px;
                  padding: 1.5rem; text-align: center; }
  .summary-card .count { font-size: 2.5rem; font-weight: 700; }
  .summary-card .label { font-size: 0.85rem; color: #8b949e; margin-top: 0.25rem; }
  .critical .count { color: var(--critical); }
  .high .count { color: var(--high); }
  .medium .count { color: var(--medium); }
  .low .count { color: var(--low); }
  .finding { background: var(--card); border: 1px solid var(--border); border-radius: 12px;
             padding: 1.5rem; margin-bottom: 1rem; }
  .finding-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.75rem; }
  .finding h3 { font-size: 1.1rem; }
  .badge { padding: 0.25rem 0.75rem; border-radius: 999px; font-size: 0.75rem; font-weight: 600; }
  .badge-Critical { background: rgba(248,81,73,0.15); color: var(--critical); border: 1px solid var(--critical); }
  .badge-High { background: rgba(240,136,62,0.15); color: var(--high); border: 1px solid var(--high); }
  .badge-Medium { background: rgba(210,153,34,0.15); color: var(--medium); border: 1px solid var(--medium); }
  .badge-Low { background: rgba(88,166,255,0.15); color: var(--low); border: 1px solid var(--low); }
  .details { color: #8b949e; margin-bottom: 0.75rem; font-size: 0.9rem; }
  .evidence { background: var(--bg); border: 1px solid var(--border); border-radius: 8px; padding: 0.75rem;
              font-family: monospace; font-size: 0.8rem; white-space: pre-wrap; max-height: 300px; overflow-y: auto; }
  .footer { text-align: center; color: #484f58; margin-top: 3rem; font-size: 0.8rem; }
</style>
</head>
<body>
<h1>🛡️ NullStrike Proof-of-Concept Report</h1>
<p class="meta">Agent: {{ report.agent_id }} | Host: {{ report.hostname }} | Generated: {{ report.timestamp }}</p>

<div class="summary">
  <div class="summary-card critical"><div class="count">{{ report.severity_summary.critical }}</div><div class="label">Critical</div></div>
  <div class="summary-card high"><div class="count">{{ report.severity_summary.high }}</div><div class="label">High</div></div>
  <div class="summary-card medium"><div class="count">{{ report.severity_summary.medium }}</div><div class="label">Medium</div></div>
  <div class="summary-card low"><div class="count">{{ report.severity_summary.low }}</div><div class="label">Low</div></div>
</div>

{% for finding in report.findings %}
{% if finding.is_vulnerable %}
<div class="finding">
  <div class="finding-header">
    <h3>{{ finding.check_name }} — {{ finding.target }}</h3>
    <span class="badge badge-{{ finding.severity }}">{{ finding.severity }}</span>
  </div>
  <p class="details">{{ finding.details }}</p>
  {% if finding.attack_path | length > 0 %}
  <div class="evidence">{% for step in finding.attack_path %}{{ step }}
{% endfor %}</div>
  {% endif %}
</div>
{% endif %}
{% endfor %}

<div class="footer">NullStrike — Authorised Internal Security Audit Tool</div>
</body>
</html>"##;
