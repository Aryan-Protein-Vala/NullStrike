mod app;
mod ui;
mod report;
mod grpc;
mod graph;
mod db;

use app::{AppMode, AppState};
use shared::{Playbook, SecurityEvent};
use grpc::OrchestratorService;
use shared::pb::null_strike_orchestrator_server::NullStrikeOrchestratorServer;
use tonic::transport::{Server, ServerTlsConfig, Identity, Certificate};

use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, Terminal};
use std::{error::Error, io, time::Duration};
use tokio::sync::mpsc;
use tokio::time;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    if !std::path::Path::new("playbook.yaml").exists() {
        let default_playbook = Playbook {
            name: "Distributed Security Sweep".into(),
            description: "gRPC Distributed check".into(),
            targets: vec!["10.0.0.5".into(), "kube-pod-1".into()],
            checks: vec![],
        };
        let yaml = serde_yaml::to_string(&default_playbook)?;
        std::fs::write("playbook.yaml", yaml)?;
    }

    let playbook_yaml = std::fs::read_to_string("playbook.yaml")?;
    let playbook = Playbook::from_yaml_str(&playbook_yaml)?;
    let targets = playbook.targets.clone();
    
    // Agents execute checks exactly once per target
    let total_checks = playbook.targets.len() * playbook.checks.len();
    
    let mut app = AppState::new(playbook.targets.clone(), total_checks);

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let (tx, mut rx) = mpsc::channel::<SecurityEvent>(5000);

    let service = OrchestratorService {
        playbook_yaml,
        targets,
        result_tx: tx,
    };
    
    tokio::spawn(async move {
        let cert = std::env::var("NULLSTRIKE_SERVER_CERT").unwrap_or_else(|_| include_str!("../../certs/server.crt").to_string());
        let key = std::env::var("NULLSTRIKE_SERVER_KEY").unwrap_or_else(|_| include_str!("../../certs/server.key").to_string());
        let server_identity = Identity::from_pem(&cert, &key);
        let ca_cert_pem = std::env::var("NULLSTRIKE_CA_CERT").unwrap_or_else(|_| include_str!("../../certs/ca.crt").to_string());
        let client_ca_cert = Certificate::from_pem(&ca_cert_pem);

        let tls_config = ServerTlsConfig::new()
            .identity(server_identity)
            .client_ca_root(client_ca_cert);

        let _ = Server::builder()
            .tls_config(tls_config).expect("Failed to configure server TLS")
            .add_service(NullStrikeOrchestratorServer::new(service))
            .serve("127.0.0.1:50051".parse().unwrap())
            .await;
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
                            KeyCode::Char('1') | KeyCode::F(1) => app.selected_tab = 0,
                            KeyCode::Char('2') | KeyCode::F(2) => app.selected_tab = 1,
                            KeyCode::Char('3') | KeyCode::F(3) => app.selected_tab = 2,
                            KeyCode::Char('4') | KeyCode::F(4) => app.selected_tab = 3,
                            KeyCode::Char('5') | KeyCode::F(5) => app.selected_tab = 4,
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
