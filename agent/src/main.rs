use shared::pb::null_strike_orchestrator_client::NullStrikeOrchestratorClient;
use shared::pb::{AgentRegistration, SecurityResult};
use shared::{Playbook, CheckType, SecurityEvent, Severity};
use tonic::transport::{Channel, ClientTlsConfig, Certificate, Identity};
use tonic::Request;
use std::sync::Arc;
use tokio::sync::mpsc;
use aws_config::BehaviorVersion;

mod auditor;
mod cloud_engine;
mod network_engine;
mod host_engine;
mod lua_engine;
mod kube_engine;
mod api_engine;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Connecting to NullStrike Orchestrator...");
    
    // Retry loop for connection
    let mut client = loop {
        let ca_cert_pem = include_str!("../../certs/ca.crt");
        let ca_cert = Certificate::from_pem(ca_cert_pem);
        let client_cert = include_str!("../../certs/client.crt");
        let client_key = include_str!("../../certs/client.key");
        let client_identity = Identity::from_pem(client_cert, client_key);

        let tls = ClientTlsConfig::new()
            .domain_name("127.0.0.1")
            .ca_certificate(ca_cert)
            .identity(client_identity);
        
        let channel = match Channel::from_static("https://127.0.0.1:50051")
            .tls_config(tls)
        {
            Ok(c) => c,
            Err(e) => {
                println!("TLS setup failed: {:?}", e);
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                continue;
            }
        };

        match channel.connect().await {
            Ok(ch) => break NullStrikeOrchestratorClient::new(ch),
            Err(e) => {
                println!("Connection refused. Is the server running? Retrying in 5 seconds... {:?}", e);
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
            CheckType::KubernetesEscape => {
                auditors.push(Arc::new(kube_engine::KubernetesEscapeAuditor));
            }
            CheckType::ApiDiscovery { subdomains, endpoints } => {
                auditors.push(Arc::new(api_engine::ApiDiscoveryAuditor::new(subdomains, endpoints)));
            }
            _ => {}
        }
    }
    
    for auditor in auditors {
        match auditor.execute(&target).await {
            Ok(SecurityEvent::SimulationAlert { target, check_name, severity, is_vulnerable, details, attack_path }) => {
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
                    attack_path,
                }).await;
            }
            Ok(SecurityEvent::Pass { target, check_name }) => {
                let _ = tx.send(SecurityResult {
                    agent_id: agent_id.clone(),
                    target,
                    check_name,
                    severity: "Low".to_string(),
                    is_vulnerable: false,
                    details: "Check passed successfully. No vulnerabilities found.".to_string(),
                    attack_path: vec![],
                }).await;
            }
            Err(e) => {
                let _ = tx.send(SecurityResult {
                    agent_id: agent_id.clone(),
                    target: target.clone(),
                    check_name: auditor.name(),
                    severity: "Low".to_string(),
                    is_vulnerable: false,
                    details: format!("Check failed to execute: {}", e),
                    attack_path: vec![],
                }).await;
            }
        }
    }
}
