use crate::auditor::Auditor;
use shared::{SecurityEvent, Severity};
use anyhow::Result;
use async_trait::async_trait;
use aws_config::SdkConfig;
use aws_sdk_sts::Client as StsClient;

pub struct IamChainingAuditor {
    pub role_arn: String,
    pub config: SdkConfig,
}

#[async_trait]
impl Auditor for IamChainingAuditor {
    fn name(&self) -> String {
        "IAM Blast-Radius Extrapolator".to_string()
    }

    fn severity(&self) -> Severity {
        Severity::Critical
    }

    async fn execute(&self, target: &str) -> Result<SecurityEvent> {
        let sts_client = StsClient::new(&self.config);
        
        let mut is_vulnerable = false;
        let mut details = String::new();
        
        // This is a REAL AWS STS call
        match sts_client.assume_role().role_arn(&self.role_arn).role_session_name("NullStrikeAudit").send().await {
            Ok(resp) => {
                is_vulnerable = true;
                if let Some(creds) = resp.credentials() {
                    let key = creds.access_key_id();
                    let masked_key = if key.len() >= 8 {
                        format!("{}***{}", &key[..4], &key[key.len()-4..])
                    } else {
                        "***".to_string()
                    };
                    details = format!("CRITICAL: Successfully assumed role! Masked Key: {}", masked_key);
                }
            },
            Err(e) => {
                details = format!("Access Denied or Failed to assume role: {:?}", e);
            }
        }

        Ok(SecurityEvent::SimulationAlert {
            target: target.to_string(),
            check_name: self.name(),
            severity: self.severity(),
            is_vulnerable,
            details,
            attack_path: vec![],
        })
    }
}
