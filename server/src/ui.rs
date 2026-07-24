use crate::app::{AppMode, AppState};
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Gauge, List, ListItem, Paragraph, Sparkline, Tabs, BarChart},
    Frame,
};

pub fn draw_ui(f: &mut Frame, app: &AppState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),  // Tabs
            Constraint::Min(0),     // Main content
            Constraint::Length(3),  // Progress bar
        ])
        .split(f.size());

    // ─── Tabs ─────────────────────────────────────────────────────────────
    let tab_titles: Vec<Line> = vec![
        " 1. Overview ",
        " 2. Agent Swarm Mesh ",
        " 3. Attack Graph ",
        " 4. Threat Stream ",
        " 5. Remediation Console ",
    ]
    .into_iter()
    .map(|t| Line::from(t))
    .collect();

    let tabs = Tabs::new(tab_titles)
        .block(Block::default().borders(Borders::ALL).title(" NullStrike Enterprise Orchestrator "))
        .select(app.selected_tab)
        .style(Style::default().fg(Color::Cyan))
        .highlight_style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))
        .divider(Span::raw("|"));

    f.render_widget(tabs, chunks[0]);

    // ─── Main Content ──────────────────────────────────────────────────────
    match app.selected_tab {
        0 => draw_overview_tab(f, app, chunks[1]),
        1 => draw_agent_mesh_tab(f, app, chunks[1]),
        2 => draw_attack_graph_tab(f, app, chunks[1]),
        3 => draw_threat_stream_tab(f, app, chunks[1]),
        4 => draw_remediation_tab(f, app, chunks[1]),
        _ => {}
    }

    // ─── Progress Bar ──────────────────────────────────────────────────────
    let progress = if app.total_checks == 0 {
        0.0
    } else {
        (app.completed_checks as f64 / app.total_checks as f64).clamp(0.0, 1.0)
    };

    let pct = (progress * 100.0) as u16;
    let gauge = Gauge::default()
        .block(Block::default().title(" Global Audit Progress ").borders(Borders::ALL))
        .gauge_style(Style::default().fg(Color::Magenta).bg(Color::DarkGray))
        .percent(pct);
    f.render_widget(gauge, chunks[2]);
}

fn draw_overview_tab(f: &mut Frame, app: &AppState, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    let sparkline = Sparkline::default()
        .block(Block::default().title(" Checks/sec Velocity ").borders(Borders::ALL))
        .data(&app.checks_per_second)
        .style(Style::default().fg(Color::Green));
    f.render_widget(sparkline, chunks[0]);

    let counts = app.severity_counts();
    let barchart_data = vec![
        ("Crit", *counts.get(&shared::Severity::Critical).unwrap_or(&0)),
        ("High", *counts.get(&shared::Severity::High).unwrap_or(&0)),
        ("Med", *counts.get(&shared::Severity::Medium).unwrap_or(&0)),
        ("Low", *counts.get(&shared::Severity::Low).unwrap_or(&0)),
    ];

    let barchart = BarChart::default()
        .block(Block::default().title(" Severity Breakdown ").borders(Borders::ALL))
        .data(&barchart_data)
        .bar_width(8)
        .bar_gap(4)
        .value_style(Style::default().fg(Color::Black).bg(Color::Cyan))
        .label_style(Style::default().fg(Color::White));
    f.render_widget(barchart, chunks[1]);
}

fn draw_agent_mesh_tab(f: &mut Frame, _app: &AppState, area: Rect) {
    // In a real implementation, this would read from a connected agent list in AppState.
    // For now, we mock the mesh visualization.
    let list = List::new(vec![
        ListItem::new("agent-123e4567-e89b... [Active] - CPU: 12% RAM: 45MB"),
        ListItem::new("agent-987fcdeb-51a2... [Idle]   - CPU: 1%  RAM: 15MB"),
    ])
    .block(Block::default().title(" Connected Agent Swarm ").borders(Borders::ALL));
    f.render_widget(list, area);
}

fn draw_attack_graph_tab(f: &mut Frame, app: &AppState, area: Rect) {
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
                    format!(" 🕸  Live Infrastructure Attack Graph ({} paths) ", app.attack_graph.vuln_count()),
                    Style::default().fg(Color::Magenta).add_modifier(Modifier::BOLD),
                ))
                .borders(Borders::ALL)
                .style(Style::default().fg(Color::Magenta)),
        )
        .wrap(ratatui::widgets::Wrap { trim: false });

    f.render_widget(graph_widget, area);
}

fn draw_threat_stream_tab(f: &mut Frame, app: &AppState, area: Rect) {
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
                    format!(" ⚡ Live Threat Stream ({}/{}) ", app.completed_checks, app.total_checks),
                    Style::default().fg(Color::White).add_modifier(Modifier::BOLD),
                ))
                .borders(Borders::ALL),
        );
    f.render_widget(stream_list, area);
}

fn draw_remediation_tab(f: &mut Frame, _app: &AppState, area: Rect) {
    let text = vec![
        Line::from("Select a critical finding in the Threat Stream to generate remediation patches."),
        Line::from(""),
        Line::from("Example Patch (SQLi detected on /api/login):"),
        Line::from(Span::styled("  UPDATE parameters SET type = 'prepared_statement' WHERE query = 'SELECT * FROM users';", Style::default().fg(Color::Green))),
    ];

    let p = Paragraph::new(text)
        .block(Block::default().title(" Remediation Console ").borders(Borders::ALL));
    f.render_widget(p, area);
}
