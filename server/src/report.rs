use crate::app::AppState;
use shared::Severity;
use std::fs;
use anyhow::Result;
use comfy_table::{Table, Cell, Color as TColor, Attribute};

/// Export full report suite: JSON, Markdown, and Graphviz DOT
pub fn export_report(app: &AppState) -> Result<()> {
    // ── JSON Report ───────────────────────────────────────────────────────
    let json_data = serde_json::to_string_pretty(app)?;
    fs::write("report.json", json_data)?;

    // ── Graphviz DOT Export ───────────────────────────────────────────────
    let dot = app.attack_graph.export_dot();
    fs::write("report.dot", &dot)?;

    // ── Markdown Report ───────────────────────────────────────────────────
    let mut md = String::new();
    md.push_str("# 🛡️ NullStrike Red Team Report\n\n");
    md.push_str(&format!("**Targets Scope:** {}\n\n", app.targets.join(", ")));
    md.push_str(&format!("**Total Checks Executed:** {}\n\n", app.total_checks));

    if let (Some(end), start) = (app.end_time, app.start_time) {
        let duration = (end - start).num_seconds();
        md.push_str(&format!("**Scan Duration:** {}s\n\n", duration));
    }

    let counts = app.severity_counts();
    md.push_str("## Vulnerability Summary\n\n");
    md.push_str("| Severity | Count |\n|----------|-------|\n");
    md.push_str(&format!("| 🔴 Critical | {} |\n", counts.get(&Severity::Critical).unwrap_or(&0)));
    md.push_str(&format!("| 🟠 High | {} |\n", counts.get(&Severity::High).unwrap_or(&0)));
    md.push_str(&format!("| 🟡 Medium | {} |\n", counts.get(&Severity::Medium).unwrap_or(&0)));
    md.push_str(&format!("| 🔵 Low | {} |\n\n", counts.get(&Severity::Low).unwrap_or(&0)));

    // ── Attack Graph section ──────────────────────────────────────────────
    md.push_str("## ⚡ Attack Graph — Blast Radius Analysis\n\n");
    md.push_str("```text\n");
    md.push_str(&app.attack_graph.render_ascii_tree());
    md.push_str("```\n\n");
    md.push_str("> 💡 Open `report.dot` in https://dreampuf.github.io/GraphvizOnline/ for an interactive visual.\n\n");

    // ── Detailed findings ─────────────────────────────────────────────────
    md.push_str("## Detailed Findings & Remediation\n\n");

    let mut any_vuln = false;
    for res in &app.results {
        if res.is_vulnerable() {
            any_vuln = true;
            md.push_str(&format!(
                "### [{:?}] {} on `{}`\n\n**Details:** {}\n\n",
                res.severity(), res.check_name(), res.target(), res.details()
            ));

            // Include sub-findings from attack_path if this is a K8s escape or multi-check
            let shared::SecurityEvent::SimulationAlert { attack_path, .. } = res;
            if !attack_path.is_empty() {
                md.push_str("**Sub-Findings (Attack Path):**\n");
                for step in attack_path {
                    md.push_str(&format!("- {}\n", step));
                }
                md.push('\n');
            }

            md.push_str("**Remediation:**\n");
            let check = res.check_name();
            if check.contains("IAM") {
                md.push_str("```json\n{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [{ \"Effect\": \"Deny\", \"Action\": \"sts:AssumeRole\", \"Resource\": \"*\" }]\n}\n```\n\n");
            } else if check.contains("Host") {
                md.push_str("```bash\nchmod 600 /etc/shadow\nchown root:root /etc/shadow\n```\n\n");
            } else if check.contains("Ephemeral Port") {
                md.push_str("```bash\niptables -A INPUT -p tcp --match multiport --dports 1024:65535 -j DROP\n```\n\n");
            } else if check.contains("Kubernetes") {
                md.push_str("```yaml\n# Pod Security Policy\napiVersion: policy/v1beta1\nkind: PodSecurityPolicy\nspec:\n  privileged: false\n  hostPID: false\n  hostIPC: false\n  volumes:\n    - 'configMap'\n    - 'emptyDir'\n    - 'projected'\n    - 'secret'\n    - 'downwardAPI'\n    - 'persistentVolumeClaim'\n```\n\n");
            } else {
                md.push_str("```text\nPlease review security policies for this resource.\n```\n\n");
            }
        }
    }

    if !any_vuln {
        md.push_str("✅ **No vulnerabilities detected in this scan.**\n\n");
    }

    fs::write("report.md", md)?;

    Ok(())
}

pub fn print_stdout_summary(app: &AppState) {
    let counts = app.severity_counts();

    println!("\n========================================================");
    println!("             NullStrike Execution Summary                 ");
    println!("========================================================");
    println!("Targets Scope: {}", app.targets.join(", "));
    println!("Total Checks: {}", app.total_checks);
    println!();

    let mut table = Table::new();
    table.set_header(vec![
        Cell::new("Severity").add_attribute(Attribute::Bold),
        Cell::new("Count").add_attribute(Attribute::Bold),
        Cell::new("Bar Chart").add_attribute(Attribute::Bold),
    ]);

    let max_count = *counts.values().max().unwrap_or(&0) as f64;
    let max_bars = 40;

    let mut add_row = |label: &str, count: u64, color: TColor| {
        let bars = if max_count > 0.0 {
            ((count as f64 / max_count) * max_bars as f64).round() as usize
        } else {
            0
        };
        let bar_str = "█".repeat(bars);
        table.add_row(vec![
            Cell::new(label).fg(color),
            Cell::new(count.to_string()),
            Cell::new(bar_str).fg(color),
        ]);
    };

    add_row("Critical", *counts.get(&Severity::Critical).unwrap_or(&0), TColor::Red);
    add_row("High",     *counts.get(&Severity::High).unwrap_or(&0),     TColor::DarkRed);
    add_row("Medium",   *counts.get(&Severity::Medium).unwrap_or(&0),   TColor::Yellow);
    add_row("Low",      *counts.get(&Severity::Low).unwrap_or(&0),       TColor::Blue);

    println!("{table}");
    println!();

    // ── Attack Graph ──────────────────────────────────────────────────────
    println!("⚡ ATTACK GRAPH — Blast Radius:");
    println!("{}", app.attack_graph.render_ascii_tree());

    // ── Top 5 Vulnerabilities ─────────────────────────────────────────────
    println!("Top 5 Vulnerabilities Detected:");
    let mut vuln_table = Table::new();
    vuln_table.set_header(vec![
        Cell::new("Target").add_attribute(Attribute::Bold),
        Cell::new("Check").add_attribute(Attribute::Bold),
        Cell::new("Severity").add_attribute(Attribute::Bold),
        Cell::new("Details").add_attribute(Attribute::Bold),
    ]);

    let mut printed = 0;
    for res in app.results.iter().filter(|r| r.is_vulnerable()) {
        if printed >= 5 { break; }
        let color = match res.severity() {
            Severity::Critical => TColor::Red,
            Severity::High => TColor::DarkRed,
            Severity::Medium => TColor::Yellow,
            Severity::Low => TColor::Blue,
        };
        vuln_table.add_row(vec![
            Cell::new(res.target()),
            Cell::new(res.check_name()),
            Cell::new(format!("{:?}", res.severity())).fg(color),
            Cell::new(&res.details()[..res.details().len().min(80)]),
        ]);
        printed += 1;
    }

    if printed > 0 {
        println!("{vuln_table}");
    } else {
        println!("No vulnerabilities detected!");
    }
    println!("========================================================");
    println!("Exported: report.json | report.md | report.dot");
    println!("Open report.dot at https://dreampuf.github.io/GraphvizOnline/");
    println!("========================================================");
}
