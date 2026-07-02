use std::collections::HashMap;
use chrono::{DateTime, Utc};
use serde::Serialize;
use crate::auditor::{SecurityEvent, Severity};

pub enum AppMode {
    Running,
    Report,
}

#[derive(Serialize)]
pub struct AppState {
    #[serde(skip)]
    pub mode: AppMode,
    pub targets: Vec<String>,
    pub results: Vec<SecurityEvent>,
    pub start_time: DateTime<Utc>,
    pub end_time: Option<DateTime<Utc>>,
    pub total_checks: usize,
    pub completed_checks: usize,
    pub checks_per_second: Vec<u64>,
    #[serde(skip)]
    pub should_quit: bool,
    #[serde(skip)]
    pub current_sec_checks: u64,
}

impl AppState {
    pub fn new(targets: Vec<String>, total_checks: usize) -> Self {
        Self {
            mode: AppMode::Running,
            targets,
            results: Vec::new(),
            start_time: Utc::now(),
            end_time: None,
            total_checks,
            completed_checks: 0,
            checks_per_second: vec![0; 100],
            should_quit: false,
            current_sec_checks: 0,
        }
    }

    pub fn on_tick(&mut self) {
        if matches!(self.mode, AppMode::Running) {
            self.checks_per_second.remove(0);
            self.checks_per_second.push(self.current_sec_checks);
            self.current_sec_checks = 0;
        }
    }

    pub fn handle_result(&mut self, result: SecurityEvent) {
        self.results.push(result);
        self.completed_checks += 1;
        self.current_sec_checks += 1;
        if self.completed_checks >= self.total_checks {
            self.mode = AppMode::Report;
            if self.end_time.is_none() {
                self.end_time = Some(Utc::now());
            }
        }
    }

    pub fn severity_counts(&self) -> HashMap<Severity, u64> {
        let mut counts = HashMap::new();
        counts.insert(Severity::Critical, 0);
        counts.insert(Severity::High, 0);
        counts.insert(Severity::Medium, 0);
        counts.insert(Severity::Low, 0);

        for res in &self.results {
            if let Some(c) = counts.get_mut(res.severity()) {
                *c += 1;
            }
        }
        counts
    }
}
