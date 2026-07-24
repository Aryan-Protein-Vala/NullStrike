use shared::pb::null_strike_orchestrator_client::NullStrikeOrchestratorClient;
use shared::pb::{AgentRegistration, SecurityResult};
use shared::{Playbook, CheckType, SecurityEvent, Severity};
use tonic::transport::{Channel, ClientTlsConfig, Certificate, Identity};
use tonic::Request;
use std::sync::Arc;
use tokio::sync::mpsc;
use aws_config::BehaviorVersion;
use clap::Parser;

mod auditor;
mod cli;
mod cloud_engine;
mod network_engine;
mod host_engine;
mod lua_engine;
mod kube_engine;
mod api_engine;
mod subdomain_audit;
mod port_prober;
mod endpoint_inspector;
mod input_reflection_detector;
mod header_auditor;
mod tls_inspector;
mod credential_leak_checker;
mod notification;
mod poc_reporter;
mod sqli_symptom_detector;
mod graphql_introspector;
mod headless_dom_analyzer;
mod temporal_sqli_observable;
mod header_integrity_checker;
mod json_schema_inspector;
mod redirect_topology_mapper;
mod canary_reflection_validator;
mod temporal_risk_scoring_engine;
mod live_attack_graph_builder;
mod predictive_drift_detector;
mod cross_cloud_orchestrator_hub;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli_args = cli::Cli::parse();

    match cli_args.command {
        Some(cli::Commands::Audit { target, webhook, output }) => {
            run_standalone_audit(&target, webhook.as_deref(), &output).await?;
        }
        Some(cli::Commands::Report { json: _, file }) => {
            print_report(&file)?;
        }
        Some(cli::Commands::Notify { id, webhook, file }) => {
            send_finding_notification(id, &webhook, &file).await?;
        }
        Some(cli::Commands::Connect) | None => {
            run_grpc_mode().await?;
        }
    }

    Ok(())
}

/// Standalone audit mode — runs all checks locally without the gRPC orchestrator.
async fn run_standalone_audit(
    target: &str,
    webhook: Option<&str>,
    output: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("🔍 NullStrike Standalone Audit — Target: {}", target);
    println!("────────────────────────────────────────────");

    let my_uuid = uuid::Uuid::new_v4().to_string();
    let my_host = hostname::get().unwrap().into_string().unwrap();
    let agent_id = format!("agent-{}", my_uuid);

    let mut report = poc_reporter::PocReporter::new(agent_id.clone(), my_host);

    // Build all auditors for a comprehensive sweep
    let auditors: Vec<Arc<dyn auditor::Auditor>> = vec![
        Arc::new(subdomain_audit::SubdomainAuditor {
            wordlist: vec![
                "www", "api", "dev", "staging", "admin", "mail", "ftp",
                "test", "beta", "internal", "vpn", "cdn", "app",
            ]
            .into_iter()
            .map(String::from)
            .collect(),
        }),
        Arc::new(port_prober::PortProber::default_ports()),
        Arc::new(endpoint_inspector::EndpointInspector::new(vec![])), // uses defaults
        Arc::new(header_auditor::HeaderAuditor::new()),
        Arc::new(tls_inspector::TlsInspector::new()),
        Arc::new(credential_leak_checker::CredentialLeakChecker::new()),
        Arc::new(input_reflection_detector::InputReflectionDetector::new(
            vec!["/".to_string(), "/search".to_string(), "/api".to_string()],
        )),
        Arc::new(sqli_symptom_detector::SqliSymptomDetector::new(vec![])),
        Arc::new(graphql_introspector::GraphqlIntrospector::new()),
        Arc::new(headless_dom_analyzer::HeadlessDomAnalyzer::new(vec![])),
    ];

    // Optionally set up webhook notifications for critical findings
    let notifier = webhook.map(|url| {
        notification::Notifier::new(notification::NotifyChannel::Webhook {
            url: url.to_string(),
        })
    });

    for auditor_instance in &auditors {
        println!("  ▸ Running: {}", auditor_instance.name());
        match auditor_instance.execute(target).await {
            Ok(event) => {
                // If critical and we have a notifier, fire alert
                if let Some(ref n) = notifier {
                    if event.is_vulnerable() {
                        if let Err(e) = n.notify(&event).await {
                            eprintln!("    ⚠ Notification failed: {}", e);
                        }
                    }
                }

                // Print inline result
                match &event {
                    SecurityEvent::SimulationAlert {
                        check_name,
                        severity,
                        details,
                        attack_path,
                        ..
                    } => {
                        let icon = match severity {
                            Severity::Critical => "🔴",
                            Severity::High => "🟠",
                            Severity::Medium => "🟡",
                            Severity::Low => "🔵",
                        };
                        println!("    {} [{:?}] {}", icon, severity, details);
                        for step in attack_path.iter().take(5) {
                            println!("      └─ {}", step);
                        }
                        if attack_path.len() > 5 {
                            println!("      └─ ... and {} more", attack_path.len() - 5);
                        }
                    }
                    SecurityEvent::Pass { check_name, .. } => {
                        println!("    ✅ {} — all clear", check_name);
                    }
                }

                report.add_event(&event);
            }
            Err(e) => {
                eprintln!("    ❌ {} failed: {}", auditor_instance.name(), e);
            }
        }
    }

    println!("────────────────────────────────────────────");
    report.export_json(output)?;
    
    let html_output = output.replace(".json", ".html");
    if html_output != output {
        report.export_html(&html_output)?;
    }
    
    println!("✅ Audit complete. {} checks executed.", auditors.len());

    Ok(())
}

/// Print a previously saved JSON report to stdout.
fn print_report(file: &str) -> Result<(), Box<dyn std::error::Error>> {
    let content = std::fs::read_to_string(file)?;
    let report: serde_json::Value = serde_json::from_str(&content)?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

/// Send a webhook notification for a specific finding by its index in the report.
async fn send_finding_notification(
    id: usize,
    webhook: &str,
    file: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let content = std::fs::read_to_string(file)?;
    let report: serde_json::Value = serde_json::from_str(&content)?;

    let findings = report["findings"]
        .as_array()
        .ok_or("No findings array in report")?;

    let finding = findings
        .get(id)
        .ok_or(format!("Finding index {} not found (total: {})", id, findings.len()))?;

    let notifier = notification::Notifier::new(notification::NotifyChannel::Webhook {
        url: webhook.to_string(),
    });

    // Reconstruct a SecurityEvent for notification
    let event = SecurityEvent::SimulationAlert {
        target: finding["target"].as_str().unwrap_or("unknown").to_string(),
        check_name: finding["check_name"].as_str().unwrap_or("unknown").to_string(),
        severity: Severity::Critical,
        is_vulnerable: true,
        details: finding["details"].as_str().unwrap_or("").to_string(),
        attack_path: vec![],
    };

    notifier.notify(&event).await?;
    println!("📨 Notification sent for finding #{}", id);

    Ok(())
}

/// gRPC orchestrator mode — the original NullStrike distributed agent behavior.
async fn run_grpc_mode() -> Result<(), Box<dyn std::error::Error>> {
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
            CheckType::SubdomainAudit { wordlist } => {
                auditors.push(Arc::new(subdomain_audit::SubdomainAuditor { wordlist }));
            }
            CheckType::PortProbe { ports } => {
                auditors.push(Arc::new(port_prober::PortProber::new(ports)));
            }
            CheckType::EndpointInspection { paths } => {
                auditors.push(Arc::new(endpoint_inspector::EndpointInspector::new(paths)));
            }
            CheckType::InputReflection { paths } => {
                auditors.push(Arc::new(input_reflection_detector::InputReflectionDetector::new(paths)));
            }
            CheckType::HeaderAudit => {
                auditors.push(Arc::new(header_auditor::HeaderAuditor::new()));
            }
            CheckType::TlsInspection => {
                auditors.push(Arc::new(tls_inspector::TlsInspector::new()));
            }
            CheckType::CredentialLeakCheck => {
                auditors.push(Arc::new(credential_leak_checker::CredentialLeakChecker::new()));
            }
            CheckType::SqliSymptomDetection { paths } => {
                auditors.push(Arc::new(sqli_symptom_detector::SqliSymptomDetector::new(paths)));
            }
            CheckType::GraphqlIntrospection => {
                auditors.push(Arc::new(graphql_introspector::GraphqlIntrospector::new()));
            }
            CheckType::FullAudit => {
                auditors.push(Arc::new(subdomain_audit::SubdomainAuditor { wordlist: vec!["www".into(), "api".into()] }));
                auditors.push(Arc::new(port_prober::PortProber::default_ports()));
                auditors.push(Arc::new(endpoint_inspector::EndpointInspector::new(vec![])));
                auditors.push(Arc::new(header_auditor::HeaderAuditor::new()));
                auditors.push(Arc::new(tls_inspector::TlsInspector::new()));
                auditors.push(Arc::new(credential_leak_checker::CredentialLeakChecker::new()));
                auditors.push(Arc::new(input_reflection_detector::InputReflectionDetector::new(vec!["/".into()])));
                auditors.push(Arc::new(sqli_symptom_detector::SqliSymptomDetector::new(vec![])));
                auditors.push(Arc::new(graphql_introspector::GraphqlIntrospector::new()));
                auditors.push(Arc::new(headless_dom_analyzer::HeadlessDomAnalyzer::new(vec![])));
            }
            _ => {}
        }
    }
    
    for auditor_instance in auditors {
        match auditor_instance.execute(&target).await {
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
                    check_name: auditor_instance.name(),
                    severity: "Low".to_string(),
                    is_vulnerable: false,
                    details: format!("Check failed to execute: {}", e),
                    attack_path: vec![],
                }).await;
            }
        }
    }
}
