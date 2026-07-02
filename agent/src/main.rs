use shared::pb::null_strike_orchestrator_client::NullStrikeOrchestratorClient;
use shared::pb::{AgentRegistration, SecurityResult};
use shared::{Playbook, CheckType, SecurityEvent, Severity};
use tonic::Request;
use std::sync::Arc;
use tokio::sync::mpsc;
use aws_config::BehaviorVersion;

mod auditor;
mod cloud_engine;
mod network_engine;
mod host_engine;
mod lua_engine;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Connecting to NullStrike Orchestrator...");
    
    // In a real scenario we might retry, but let's just attempt connection.
    let mut client = NullStrikeOrchestratorClient::connect("http://127.0.0.1:50051").await?;
    
    let request = Request::new(AgentRegistration {
        agent_id: "agent-alpha".into(),
        hostname: "worker-node-1".into(),
    });
    
    let (tx, rx) = mpsc::channel::<SecurityResult>(100);
    let out_stream = tokio_stream::wrappers::ReceiverStream::new(rx);
    
    let mut client_clone = client.clone();
    tokio::spawn(async move {
        let _ = client_clone.stream_results(Request::new(out_stream)).await;
    });

    let mut stream = client.connect_agent(request).await?.into_inner();
    println!("Connected! Waiting for jobs...");

    while let Some(job) = stream.message().await? {
        println!("Received Job {} for target {}", job.job_id, job.target);
        
        if let Ok(playbook) = Playbook::from_yaml_str(&job.playbook_yaml) {
            let tx_clone = tx.clone();
            tokio::spawn(async move {
                execute_playbook(playbook, job.target, tx_clone).await;
            });
        } else {
            eprintln!("Failed to parse playbook for job {}", job.job_id);
        }
    }

    Ok(())
}

async fn execute_playbook(playbook: Playbook, target: String, tx: mpsc::Sender<SecurityResult>) {
    let mut auditors: Vec<Arc<dyn auditor::Auditor>> = Vec::new();
    
    let aws_config = aws_config::load_defaults(BehaviorVersion::latest()).await;
    
    for check in playbook.checks {
        match check {
            CheckType::IamRoleAssumption { role_arn } => {
                auditors.push(Arc::new(cloud_engine::IamChainingAuditor { 
                    role_arn,
                    config: aws_config.clone()
                }));
            }
            CheckType::EphemeralPortSweep { ports } => {
                auditors.push(Arc::new(network_engine::EphemeralPortSweepAuditor { ports }));
            }
            CheckType::HostFileInspector { paths } => {
                auditors.push(Arc::new(host_engine::HostInspectorAuditor { paths }));
            }
            CheckType::LuaPlugin { script_path } => {
                auditors.push(Arc::new(lua_engine::LuaPluginAuditor { script_path }));
            }
            _ => {}
        }
    }
    
    for auditor in auditors {
        if let Ok(SecurityEvent::SimulationAlert { target, check_name, severity, is_vulnerable, details }) = auditor.execute(&target).await {
            let severity_str = match severity {
                Severity::Critical => "Critical",
                Severity::High => "High",
                Severity::Medium => "Medium",
                Severity::Low => "Low",
            };
            
            let _ = tx.send(SecurityResult {
                agent_id: "agent-alpha".into(),
                target,
                check_name,
                severity: severity_str.to_string(),
                is_vulnerable,
                details,
            }).await;
        }
    }
}
