use rusqlite::{Connection, Result};
use shared::SecurityEvent;
use chrono::Utc;

pub struct Database {
    conn: Connection,
}

impl Database {
    pub fn new() -> Result<Self> {
        // Open local SQLite database
        let conn = Connection::open("nullstrike.db")?;
        
        // Initialize schema
        conn.execute(
            "CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                target TEXT NOT NULL,
                check_name TEXT NOT NULL,
                severity TEXT NOT NULL,
                is_vulnerable BOOLEAN NOT NULL,
                details TEXT NOT NULL
            )",
            [],
        )?;

        Ok(Self { conn })
    }

    pub fn insert_finding(&self, event: &SecurityEvent) -> Result<()> {
        let timestamp = Utc::now().to_rfc3339();
        let severity_str = format!("{:?}", event.severity());
        
        self.conn.execute(
            "INSERT INTO findings (timestamp, target, check_name, severity, is_vulnerable, details) 
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            (
                &timestamp,
                event.target(),
                event.check_name(),
                &severity_str,
                event.is_vulnerable(),
                event.details(),
            ),
        )?;
        
        Ok(())
    }
}
