use crate::auditor::{Auditor, SecurityEvent, Severity};
use anyhow::Result;
use async_trait::async_trait;
use std::time::Duration;
use tokio::time::sleep;
use rand::RngExt;

pub struct IamChainingAuditor {
    pub role_arn: String,
}

#[async_trait]
impl Auditor for IamChainingAuditor {
    fn name(&self) -> String {
        format!("IAM Blast-Radius: {}", self.role_arn)
    }

    fn severity(&self) -> Severity {
        Severity::Critical
    }

    async fn execute(&self, target: &str) -> Result<SecurityEvent> {
        let (sleep_time, is_vulnerable) = {
            let mut rng = rand::rng();
            (rng.random_range(100..300), rng.random_bool(0.15))
        };
        sleep(Duration::from_millis(sleep_time)).await;

        Ok(SecurityEvent::SimulationAlert {
            target: target.to_string(),
            check_name: self.name(),
            severity: self.severity(),
            is_vulnerable,
            details: if is_vulnerable {
                format!("Role {} on {} can assume overly permissive roles.", self.role_arn, target)
            } else {
                "Role boundary strictly enforced.".into()
            },
        })
    }
}
