use crate::app::AppState;
use ratatui::{
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Gauge, List, ListItem, Paragraph, Sparkline},
    Frame,
};

pub fn draw_ui(f: &mut Frame, app: &AppState) {
    // ── Top level: main content + bottom telemetry bar ────────────────────
    let outer = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(12),    // main panels
            Constraint::Length(3),  // progress bar
            Constraint::Length(4),  // sparkline
        ])
        .split(f.size());

    // ── Main row: target list | execution stream | attack graph ───────────
    let main_row = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(20), // target list
            Constraint::Percentage(50), // execution stream
            Constraint::Percentage(30), // attack graph
        ])
        .split(outer[0]);

    // ─── Panel 1: Target Scope ────────────────────────────────────────────
    let targets: Vec<ListItem> = app
        .targets
        .iter()
        .map(|t| {
            let has_vuln = app.results.iter().any(|r| r.target() == t && r.is_vulnerable());
            let color = if has_vuln { Color::Red } else { Color::Cyan };
            let prefix = if has_vuln { "🔴 " } else { "🟢 " };
            ListItem::new(Line::from(vec![
                Span::styled(format!("{}{}", prefix, t), Style::default().fg(color))
            ]))
        })
        .collect();

    let targets_list = List::new(targets)
        .block(
            Block::default()
                .title(Span::styled(" 🎯 Target Scope ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)))
                .borders(Borders::ALL)
                .style(Style::default().fg(Color::Cyan)),
        );
    f.render_widget(targets_list, main_row[0]);

    // ─── Panel 2: Real-time Execution Stream ──────────────────────────────
    let stream_items: Vec<ListItem> = app
        .results
        .iter()
        .rev()
        .take(60)
        .map(|r| {
            let (color, symbol) = if r.is_vulnerable() {
                (Color::Red, "⚠ VULN")
            } else {
                (Color::Green, "✓ OK  ")
            };
            let content = format!("{} | {} → {}", symbol, r.check_name(), r.target());
            ListItem::new(Line::from(vec![Span::styled(content, Style::default().fg(color))]))
        })
        .collect();

    let stream_list = List::new(stream_items)
        .block(
            Block::default()
                .title(Span::styled(
                    format!(" ⚡ Live Stream ({}/{}) ", app.completed_checks, app.total_checks),
                    Style::default().fg(Color::White).add_modifier(Modifier::BOLD),
                ))
                .borders(Borders::ALL),
        );
    f.render_widget(stream_list, main_row[1]);

    // ─── Panel 3: Live Attack Graph ───────────────────────────────────────
    let graph_text = app.attack_graph.render_ascii_tree();
    let graph_lines: Vec<Line> = graph_text
        .lines()
        .map(|line| {
            let color = if line.contains("🔴") || line.contains("CRIT") {
                Color::Red
            } else if line.contains("🟠") || line.contains("HIGH") {
                Color::LightRed
            } else if line.contains("🟡") || line.contains("MED") {
                Color::Yellow
            } else if line.contains("◉") || line.contains("TARGET") {
                Color::Cyan
            } else {
                Color::White
            };
            Line::from(Span::styled(line.to_string(), Style::default().fg(color)))
        })
        .collect();

    let graph_widget = Paragraph::new(graph_lines)
        .block(
            Block::default()
                .title(Span::styled(
                    format!(" 🕸  Attack Graph ({} vulns) ", app.attack_graph.vuln_count()),
                    Style::default().fg(Color::Magenta).add_modifier(Modifier::BOLD),
                ))
                .borders(Borders::ALL)
                .style(Style::default().fg(Color::Magenta)),
        )
        .wrap(ratatui::widgets::Wrap { trim: false });

    f.render_widget(graph_widget, main_row[2]);

    // ─── Progress Bar ─────────────────────────────────────────────────────
    let progress = if app.total_checks == 0 {
        0.0
    } else {
        (app.completed_checks as f64 / app.total_checks as f64).clamp(0.0, 1.0)
    };

    let pct = (progress * 100.0) as u16;
    let gauge = Gauge::default()
        .block(Block::default().title(" Overall Progress ").borders(Borders::ALL))
        .gauge_style(Style::default().fg(Color::Magenta).bg(Color::DarkGray))
        .percent(pct);
    f.render_widget(gauge, outer[1]);

    // ─── Checks/sec Sparkline ─────────────────────────────────────────────
    let sparkline = Sparkline::default()
        .block(
            Block::default()
                .title(" Checks/sec ")
                .borders(Borders::ALL),
        )
        .data(&app.checks_per_second)
        .style(Style::default().fg(Color::Yellow));
    f.render_widget(sparkline, outer[2]);
}
