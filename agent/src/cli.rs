use clap::{Parser, Subcommand};

/// NullStrike Agent — Distributed Security Audit Client
///
/// For authorised internal network testing only.
/// Run audits against your own infrastructure and report findings securely.
#[derive(Parser, Debug)]
#[command(name = "nullstrike-agent", version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Run a full audit against a target (bypasses gRPC orchestrator for standalone mode)
    Audit {
        /// Target URL or IP address to audit
        #[arg(short, long)]
        target: String,

        /// Optional webhook URL for critical alert notifications
        #[arg(long)]
        webhook: Option<String>,

        /// Output JSON report path (default: nullstrike_report.json)
        #[arg(short, long, default_value = "nullstrike_report.json")]
        output: String,
    },

    /// Generate or view a JSON report from a previous scan
    Report {
        /// Output as JSON (default)
        #[arg(long, default_value_t = true)]
        json: bool,

        /// Path to the report file
        #[arg(short, long, default_value = "nullstrike_report.json")]
        file: String,
    },

    /// Send a notification for a specific finding by index
    Notify {
        /// Finding index from the report (0-based)
        #[arg(long)]
        id: usize,

        /// Webhook URL to send the notification to
        #[arg(long)]
        webhook: String,

        /// Path to the report file
        #[arg(short, long, default_value = "nullstrike_report.json")]
        file: String,
    },

    /// Connect to the gRPC orchestrator (default mode if no subcommand given)
    Connect,
}
