mod playbook;
mod cloud_engine;
mod network_engine;
mod host_engine;
mod app;
mod auditor;
mod report;
mod ui;

use app::{AppMode, AppState};
use auditor::{Auditor, SecurityEvent};
use playbook::{Playbook, CheckType};
use cloud_engine::IamChainingAuditor;
use network_engine::EphemeralPortSweepAuditor;
use host_engine::HostFileInspector;

use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, Terminal};
use std::{error::Error, io, sync::Arc, time::Duration};
use tokio::sync::mpsc;
use tokio::time;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    if !std::path::Path::new("playbook.yaml").exists() {
        let default_playbook = Playbook {
            name: "Default Security Sweep".into(),
            description: "A standard mock check".into(),
            targets: vec!["10.0.0.5".into(), "kube-pod-1".into()],
            checks: vec![
                CheckType::IamRoleAssumption { role_arn: "arn:aws:iam::123456789012:role/worker".into() },
                CheckType::EphemeralPortSweep { ports: vec![22, 80, 443, 8080] },
                CheckType::HostFileInspector { path: "/etc/shadow".into() },
            ],
        };
        let yaml = serde_yaml::to_string(&default_playbook)?;
        std::fs::write("playbook.yaml", yaml)?;
    }

    let playbook = Playbook::from_yaml_file("playbook.yaml")?;
    
    let mut auditors: Vec<Arc<dyn Auditor>> = Vec::new();
    for check in &playbook.checks {
        match check {
            CheckType::IamRoleAssumption { role_arn } => {
                auditors.push(Arc::new(IamChainingAuditor { role_arn: role_arn.clone() }));
            }
            CheckType::EphemeralPortSweep { ports } => {
                auditors.push(Arc::new(EphemeralPortSweepAuditor { ports: ports.clone() }));
            }
            CheckType::HostFileInspector { path } => {
                auditors.push(Arc::new(HostFileInspector { path: path.clone() }));
            }
            CheckType::ContainerNamespaceVerification { .. } => {}
        }
    }

    let iterations = 20;
    let total_checks = playbook.targets.len() * auditors.len() * iterations;
    if total_checks == 0 {
        println!("No checks to perform.");
        return Ok(());
    }

    let mut app = AppState::new(playbook.targets.clone(), total_checks);

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let (tx, mut rx) = mpsc::channel::<SecurityEvent>(5000);

    let tx_clone = tx.clone();
    let targets_clone = playbook.targets.clone();
    tokio::spawn(async move {
        let mut handles = vec![];
        for _ in 0..iterations {
            for target in targets_clone.iter() {
                for auditor in auditors.iter() {
                    let target = target.clone();
                    let auditor = auditor.clone();
                    let tx = tx_clone.clone();
                    handles.push(tokio::spawn(async move {
                        if let Ok(result) = auditor.execute(&target).await {
                            let _ = tx.send(result).await;
                        }
                    }));
                }
            }
        }
        for handle in handles {
            let _ = handle.await;
        }
    });

    let mut tick_rate = time::interval(Duration::from_millis(100));

    loop {
        terminal.draw(|f| {
            if matches!(app.mode, AppMode::Running) {
                ui::draw_ui(f, &app)
            }
        })?;

        if matches!(app.mode, AppMode::Report) || app.should_quit {
            break;
        }

        tokio::select! {
            _ = tick_rate.tick() => {
                app.on_tick();
                if crossterm::event::poll(Duration::from_secs(0))? {
                    if let Event::Key(key) = event::read()? {
                        match key.code {
                            KeyCode::Char('q') | KeyCode::Esc => {
                                app.should_quit = true;
                            },
                            _ => {}
                        }
                    }
                }
            }
            Some(result) = rx.recv() => {
                app.handle_result(result);
            }
        }
    }

    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    if matches!(app.mode, AppMode::Report) || app.completed_checks > 0 {
        let _ = report::export_report(&app);
        report::print_stdout_summary(&app);
    }

    Ok(())
}
