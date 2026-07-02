use std::collections::HashMap;
use petgraph::graph::{DiGraph, NodeIndex};
use petgraph::visit::Bfs;
use shared::Severity;

/// Represents a node in the attack graph
#[derive(Debug, Clone)]
pub struct GraphNode {
    pub label: String,
    pub node_kind: NodeKind,
}

#[derive(Debug, Clone, PartialEq)]
pub enum NodeKind {
    Target,      // A host/IP/pod being scanned
    Vuln,        // A vulnerability found
}

/// An edge connecting a target to a vulnerability it is exposed to
#[derive(Debug, Clone)]
pub struct GraphEdge {
    pub severity: Severity,
    pub check_name: String,
}

/// The in-process Attack Graph — wraps petgraph DiGraph
pub struct AttackGraph {
    graph: DiGraph<GraphNode, GraphEdge>,
    /// Maps label → NodeIndex for deduplication
    index_map: HashMap<String, NodeIndex>,
}

impl AttackGraph {
    pub fn new() -> Self {
        Self {
            graph: DiGraph::new(),
            index_map: HashMap::new(),
        }
    }

    /// Add a target host node (idempotent)
    pub fn add_target(&mut self, target: &str) -> NodeIndex {
        let key = format!("target:{}", target);
        if let Some(&idx) = self.index_map.get(&key) {
            return idx;
        }
        let idx = self.graph.add_node(GraphNode {
            label: target.to_string(),
            node_kind: NodeKind::Target,
        });
        self.index_map.insert(key, idx);
        idx
    }

    /// Add a vulnerability finding and draw an edge from its target
    pub fn add_finding(&mut self, target: &str, check_name: &str, severity: &Severity) {
        let target_idx = self.add_target(target);

        let vuln_key = format!("vuln:{}:{}", target, check_name);
        if self.index_map.contains_key(&vuln_key) {
            return; // already added
        }

        let vuln_idx = self.graph.add_node(GraphNode {
            label: format!("{} [{}]", check_name, severity_label(severity)),
            node_kind: NodeKind::Vuln,
        });
        self.index_map.insert(vuln_key, vuln_idx);

        self.graph.add_edge(target_idx, vuln_idx, GraphEdge {
            severity: severity.clone(),
            check_name: check_name.to_string(),
        });
    }

    /// Perform BFS from every target node and render a full ASCII attack tree
    pub fn render_ascii_tree(&self) -> String {
        let mut out = String::new();
        out.push_str("┌─────────────────────────────────────────────────┐\n");
        out.push_str("│           NULLSTRIKE ATTACK GRAPH                │\n");
        out.push_str("└─────────────────────────────────────────────────┘\n\n");

        let target_nodes: Vec<NodeIndex> = self.graph.node_indices()
            .filter(|&n| self.graph[n].node_kind == NodeKind::Target)
            .collect();

        if target_nodes.is_empty() {
            out.push_str("  (no targets scanned yet)\n");
            return out;
        }

        for &start in &target_nodes {
            let target_label = &self.graph[start].label;
            out.push_str(&format!("  ◉ TARGET: {}\n", target_label));

            // Collect direct vulnerability neighbors (1-hop from target)
            let vulns: Vec<NodeIndex> = self.graph.neighbors(start).collect();

            if vulns.is_empty() {
                out.push_str("  │  └── ✅ No vulnerabilities detected\n");
            } else {
                for (i, &vuln_idx) in vulns.iter().enumerate() {
                    let is_last = i == vulns.len() - 1;
                    let connector = if is_last { "└──" } else { "├──" };
                    let edge = self.graph.edges_connecting(start, vuln_idx).next();
                    let sev_icon = edge.map(|e| severity_icon(&e.weight().severity)).unwrap_or("⚠️");
                    let vuln_label = &self.graph[vuln_idx].label;
                    out.push_str(&format!("  │  {} {} {}\n", connector, sev_icon, vuln_label));
                }
            }
            out.push('\n');
        }

        out
    }

    /// Export to Graphviz DOT format for external visualization
    pub fn export_dot(&self) -> String {
        let mut dot = String::from("digraph NullStrike {\n");
        dot.push_str("  rankdir=LR;\n");
        dot.push_str("  node [shape=box, style=filled, fontname=\"Courier\"];\n\n");

        for idx in self.graph.node_indices() {
            let node = &self.graph[idx];
            let (color, shape) = match node.node_kind {
                NodeKind::Target => ("#1a1a2e", "ellipse"),
                NodeKind::Vuln => ("#c0392b", "box"),
            };
            dot.push_str(&format!(
                "  n{} [label=\"{}\", fillcolor=\"{}\", fontcolor=\"white\", shape=\"{}\"];\n",
                idx.index(), escape_dot(&node.label), color, shape
            ));
        }

        dot.push('\n');

        for edge in self.graph.edge_indices() {
            let (src, dst) = self.graph.edge_endpoints(edge).unwrap();
            let weight = &self.graph[edge];
            let color = match weight.severity {
                Severity::Critical => "#ff0000",
                Severity::High => "#ff6600",
                Severity::Medium => "#ffcc00",
                Severity::Low => "#00aaff",
            };
            dot.push_str(&format!(
                "  n{} -> n{} [label=\"{}\", color=\"{}\", fontcolor=\"{}\"];\n",
                src.index(), dst.index(), escape_dot(&weight.check_name), color, color
            ));
        }

        dot.push_str("}\n");
        dot
    }

    /// Returns count of vulnerability nodes
    pub fn vuln_count(&self) -> usize {
        self.graph.node_indices()
            .filter(|&n| self.graph[n].node_kind == NodeKind::Vuln)
            .count()
    }
}

fn severity_label(s: &Severity) -> &'static str {
    match s {
        Severity::Critical => "CRIT",
        Severity::High => "HIGH",
        Severity::Medium => "MED",
        Severity::Low => "LOW",
    }
}

fn severity_icon(s: &Severity) -> &'static str {
    match s {
        Severity::Critical => "🔴",
        Severity::High => "🟠",
        Severity::Medium => "🟡",
        Severity::Low => "🔵",
    }
}

fn escape_dot(s: &str) -> String {
    s.replace('"', "\\\"").replace('\n', " ")
}
