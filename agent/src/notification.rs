use anyhow::Result;
use shared::SecurityEvent;

/// Notification configuration — supports webhook (reqwest POST) or SMTP (lettre).
#[derive(Debug, Clone)]
pub enum NotifyChannel {
    /// POST a JSON payload to a webhook URL (Slack, Discord, PagerDuty, etc.)
    Webhook { url: String },
    /// Send an email via SMTP
    Smtp {
        server: String,
        port: u16,
        username: String,
        password: String,
        from: String,
        to: String,
    },
}

/// Sends critical finding alerts to a configured notification channel.
/// This is a responsible-disclosure helper for internal teams — it ensures
/// sysadmins are immediately notified when a critical misconfiguration is found.
pub struct Notifier {
    pub channel: NotifyChannel,
    pub client: reqwest::Client,
}

impl Notifier {
    pub fn new(channel: NotifyChannel) -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .unwrap_or_default();

        Self { channel, client }
    }

    /// Send a notification for a critical finding. Returns Ok(()) on success.
    pub async fn notify(&self, event: &SecurityEvent) -> Result<()> {
        let (target, check, details) = match event {
            SecurityEvent::SimulationAlert {
                target,
                check_name,
                details,
                ..
            } => (target.as_str(), check_name.as_str(), details.as_str()),
            SecurityEvent::Pass { .. } => return Ok(()), // No notification for passes
        };

        match &self.channel {
            NotifyChannel::Webhook { url } => {
                let payload = serde_json::json!({
                    "text": format!(
                        "🚨 *NullStrike Critical Alert*\n*Target:* {}\n*Check:* {}\n*Details:* {}",
                        target, check, details
                    ),
                    "target": target,
                    "check": check,
                    "details": details,
                    "severity": "CRITICAL",
                    "timestamp": chrono::Utc::now().to_rfc3339(),
                });

                self.client
                    .post(url)
                    .json(&payload)
                    .send()
                    .await?;
            }
            NotifyChannel::Smtp {
                server,
                port,
                username,
                password,
                from,
                to,
            } => {
                use lettre::message::header::ContentType;
                use lettre::transport::smtp::authentication::Credentials;
                use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};

                let email = Message::builder()
                    .from(from.parse()?)
                    .to(to.parse()?)
                    .subject(format!(
                        "[NullStrike CRITICAL] {} on {}",
                        check, target
                    ))
                    .header(ContentType::TEXT_PLAIN)
                    .body(format!(
                        "NullStrike Security Alert\n\
                         ========================\n\
                         Target: {}\n\
                         Check: {}\n\
                         Severity: CRITICAL\n\
                         Time: {}\n\n\
                         Details:\n{}\n\n\
                         — NullStrike Automated Audit",
                        target,
                        check,
                        chrono::Utc::now().to_rfc3339(),
                        details
                    ))?;

                let creds = Credentials::new(username.clone(), password.clone());

                let mailer = AsyncSmtpTransport::<Tokio1Executor>::relay(server)?
                    .port(*port)
                    .credentials(creds)
                    .build();

                mailer.send(email).await?;
            }
        }

        Ok(())
    }
}
