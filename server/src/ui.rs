use crate::app::AppState;
use ratatui::{
    layout::{Constraint, Direction, Layout},
    style::{Color, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Gauge, List, ListItem, Sparkline},
    Frame,
};

pub fn draw_ui(f: &mut Frame, app: &AppState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(10), Constraint::Length(5)])
        .split(f.size());

    let top_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(30), Constraint::Percentage(70)])
        .split(chunks[0]);

    // Left sidebar: Target Scope
    let targets: Vec<ListItem> = app
        .targets
        .iter()
        .map(|t| ListItem::new(Line::from(vec![Span::raw(t)])))
        .collect();

    let targets_list = List::new(targets)
        .block(Block::default().title(" Target Scope ").borders(Borders::ALL).style(Style::default().fg(Color::Cyan)));

    f.render_widget(targets_list, top_chunks[0]);

    // Top-right: Real-time Execution Stream
    let stream_items: Vec<ListItem> = app
        .results
        .iter()
        .rev()
        .take(50)
        .map(|r| {
            let color = if r.is_vulnerable() { Color::Red } else { Color::Green };
            let symbol = if r.is_vulnerable() { "[VULN]" } else { "[OK]" };
            let content = format!("{} {} on {} - {}", symbol, r.check_name(), r.target(), r.details());
            ListItem::new(Line::from(vec![Span::styled(content, Style::default().fg(color))]))
        })
        .collect();

    let stream_list = List::new(stream_items)
        .block(Block::default().title(" Real-time Execution Stream ").borders(Borders::ALL).style(Style::default().fg(Color::White)));

    f.render_widget(stream_list, top_chunks[1]);

    // Bottom pane: Telemetry & Metrics
    let bottom_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(chunks[1]);

    let progress = if app.total_checks == 0 {
        0.0
    } else {
        (app.completed_checks as f64 / app.total_checks as f64).clamp(0.0, 1.0)
    };

    let gauge = Gauge::default()
        .block(Block::default().title(" Overall Progress ").borders(Borders::ALL))
        .gauge_style(Style::default().fg(Color::Magenta).bg(Color::DarkGray))
        .ratio(progress);

    f.render_widget(gauge, bottom_chunks[0]);

    let sparkline = Sparkline::default()
        .block(Block::default().title(" Checks/sec ").borders(Borders::ALL))
        .data(&app.checks_per_second)
        .style(Style::default().fg(Color::Yellow));

    f.render_widget(sparkline, bottom_chunks[1]);
}
