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
    
    // Retry loop for connection
    let mut client = loop {
        match NullStrikeOrchestratorClient::connect("http://127.0.0.1:50051").await {
            Ok(c) => break c,
            Err(_) => {
                println!("Connection refused. Is the server running? Retrying in 5 seconds...");
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            }
        }
    };

    let my_uuid = uuid::Uuid::new_v4().to_string();
    let my_host = hostname::get().unwrap().into_string().unwrap();
    let agent_id = format!("agent-{}", my_uuid);

    let request = Request::new(AgentRegistration {
        agent_id: agent_id.clone(),
        hostname: my_host,
    });
    
    let (tx, rx) = mpsc::channel::<SecurityResult>(100);
    let out_stream = tokio_stream::wrappers::ReceiverStream::new(rx);
    
    let mut client_clone = client.clone();
    let stream_handle = tokio::spawn(async move {
        let _ = client_clone.stream_results(Request::new(out_stream)).await;
    });

    let mut stream = client.connect_agent(request).await?.into_inner();
    println!("Connected! Waiting for jobs...");

    let mut handles = Vec::new();

    while let Some(job) = stream.message().await? {
        println!("Received Job {} for target {}", job.job_id, job.target);
        
        if let Ok(playbook) = Playbook::from_yaml_str(&job.playbook_yaml) {
            let tx_clone = tx.clone();
            let aid = agent_id.clone();
            let handle = tokio::spawn(async move {
                execute_playbook(playbook, job.target, tx_clone, aid).await;
            });
            handles.push(handle);
        } else {
            eprintln!("Failed to parse playbook for job {}", job.job_id);
        }
    }

    for handle in handles {
        let _ = handle.await;
    }

    // Drop the sender so stream_results task can finish
    drop(tx);

    // Wait for the results to finish streaming to the server
    let _ = stream_handle.await;
    
    println!("All jobs completed and results streamed successfully.");

    Ok(())
}

async fn execute_playbook(playbook: Playbook, target: String, tx: mpsc::Sender<SecurityResult>, agent_id: String) {
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
                agent_id: agent_id.clone(),
                target,
                check_name,
                severity: severity_str.to_string(),
                is_vulnerable,
                details,
            }).await;
        }
    }
}
