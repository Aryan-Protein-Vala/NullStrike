use crate::app::AppState;
use crate::auditor::Severity;
use std::fs;
use anyhow::Result;
use comfy_table::{Table, Cell, Color as TColor, Attribute};
use petgraph::graph::Graph;
use std::collections::HashMap;

pub fn build_blast_radius_graph(app: &AppState) -> String {
    let mut graph = Graph::<String, String>::new();
    let mut node_indices = HashMap::new();
    
    // Add nodes for targets
    for target in &app.targets {
        let idx = graph.add_node(format!("Target: {}", target));
        node_indices.insert(target.clone(), idx);
    }
    
    for result in &app.results {
        if result.is_vulnerable() {
            let target_idx = *node_indices.get(result.target()).unwrap();
            let vuln_name = format!("Vuln: {}", result.check_name());
            let vuln_idx = *node_indices.entry(vuln_name.clone()).or_insert_with(|| graph.add_node(vuln_name));
            graph.add_edge(target_idx, vuln_idx, format!("{:?}", result.severity()));
        }
    }
    
    let mut output = String::new();
    output.push_str("## Structural Blast-Radius Report (Graph BFS)\n\n");
    
    if let Some(start_target) = app.targets.first() {
        if let Some(&start_idx) = node_indices.get(start_target) {
            output.push_str(&format!("**Exposure chain starting from {}**:\n\n```text\n", start_target));
            let mut bfs = petgraph::visit::Bfs::new(&graph, start_idx);
            let mut depth = 0;
            while let Some(nx) = petgraph::visit::Bfs::next(&mut bfs, &graph) {
                let node_name = &graph[nx];
                if node_name.starts_with("Target") {
                    output.push_str(&format!("{} {}\n", "  ".repeat(depth), node_name));
                    depth += 1;
                } else {
                    output.push_str(&format!("{} -> {} [Exposed]\n", "  ".repeat(depth), node_name));
                }
            }
            output.push_str("```\n\n");
        }
    }
    
    output
}

pub fn export_report(app: &AppState) -> Result<()> {
    let json_data = serde_json::to_string_pretty(app)?;
    fs::write("report.json", json_data)?;

    let mut md = String::new();
    md.push_str("# NullStrike Simulation Report\n\n");
    md.push_str(&format!("**Targets Scope:** {}\n\n", app.targets.join(", ")));
    md.push_str(&format!("**Total Checks:** {}\n", app.total_checks));
    
    let counts = app.severity_counts();
    md.push_str("## Vulnerabilities Summary\n");
    md.push_str(&format!("- Critical: {}\n", counts.get(&Severity::Critical).unwrap_or(&0)));
    md.push_str(&format!("- High: {}\n", counts.get(&Severity::High).unwrap_or(&0)));
    md.push_str(&format!("- Medium: {}\n", counts.get(&Severity::Medium).unwrap_or(&0)));
    md.push_str(&format!("- Low: {}\n\n", counts.get(&Severity::Low).unwrap_or(&0)));

    md.push_str(&build_blast_radius_graph(app));

    md.push_str("## Detailed Findings & Remediation\n");
    for res in &app.results {
        if res.is_vulnerable() {
            md.push_str(&format!("### [{:?}] {} on {}\n", res.severity(), res.check_name(), res.target()));
            md.push_str(&format!("**Details:** {}\n\n", res.details()));
            
            md.push_str("**Remediation:**\n");
            if res.check_name().contains("IAM Blast-Radius") {
                md.push_str("```json\n{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"Effect\": \"Deny\",\n      \"Action\": \"sts:AssumeRole\",\n      \"Resource\": \"*\"\n    }\n  ]\n}\n```\n\n");
            } else if res.check_name().contains("Host Inspector") {
                md.push_str("```bash\nchmod 600 /etc/shadow\nchown root:root /etc/shadow\n```\n\n");
            } else if res.check_name().contains("Ephemeral Port Sweep") {
                md.push_str("```bash\niptables -A INPUT -p tcp --match multiport --dports 1024:65535 -j DROP\n```\n\n");
            } else {
                md.push_str("```text\nPlease review security policies for this resource.\n```\n\n");
            }
        }
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
    add_row("High", *counts.get(&Severity::High).unwrap_or(&0), TColor::DarkRed);
    add_row("Medium", *counts.get(&Severity::Medium).unwrap_or(&0), TColor::Yellow);
    add_row("Low", *counts.get(&Severity::Low).unwrap_or(&0), TColor::Blue);

    println!("{table}");
    println!();

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
            Cell::new(res.details()),
        ]);
        printed += 1;
    }

    if printed > 0 {
        println!("{vuln_table}");
    } else {
        println!("No vulnerabilities detected!");
    }
    println!("========================================================");
    println!("Exported detailed report to report.json and report.md");
    println!("========================================================");
}
