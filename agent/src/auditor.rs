use anyhow::Result;
use async_trait::async_trait;
use shared::{SecurityEvent, Severity};

#[async_trait]
pub trait Auditor: Send + Sync {
    fn name(&self) -> String;
    fn severity(&self) -> Severity;
    async fn execute(&self, target: &str) -> Result<SecurityEvent>;
}
