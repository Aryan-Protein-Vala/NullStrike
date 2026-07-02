use shared::pb::null_strike_orchestrator_server::NullStrikeOrchestrator;
use shared::pb::{AgentRegistration, Job, SecurityResult, Ack};
use tonic::{Request, Response, Status};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use shared::SecurityEvent;
use shared::Severity;

#[derive(Clone)]
pub struct OrchestratorService {
    pub playbook_yaml: String,
    pub targets: Vec<String>,
    pub result_tx: mpsc::Sender<SecurityEvent>,
}

#[tonic::async_trait]
impl NullStrikeOrchestrator for OrchestratorService {
    type ConnectAgentStream = ReceiverStream<Result<Job, Status>>;

    async fn connect_agent(
        &self,
        request: Request<AgentRegistration>,
    ) -> Result<Response<Self::ConnectAgentStream>, Status> {
        let req = request.into_inner();
        let (tx, rx) = mpsc::channel(10);
        
        for (i, target) in self.targets.iter().enumerate() {
            let _ = tx.send(Ok(Job {
                job_id: format!("{}-job-{}", req.agent_id, i),
                target: target.clone(),
                playbook_yaml: self.playbook_yaml.clone(),
            })).await;
        }

        Ok(Response::new(ReceiverStream::new(rx)))
    }

    async fn stream_results(
        &self,
        request: Request<tonic::Streaming<SecurityResult>>,
    ) -> Result<Response<Ack>, Status> {
        let mut stream = request.into_inner();
        while let Some(res) = stream.message().await? {
            let severity = match res.severity.as_str() {
                "Critical" => Severity::Critical,
                "High" => Severity::High,
                "Medium" => Severity::Medium,
                "Low" => Severity::Low,
                _ => Severity::Low,
            };
            
            let event = SecurityEvent::SimulationAlert {
                target: res.target,
                check_name: res.check_name,
                severity,
                is_vulnerable: res.is_vulnerable,
                details: format!("[{}] {}", res.agent_id, res.details),
            };
            
            let _ = self.result_tx.send(event).await;
        }
        Ok(Response::new(Ack { received: true }))
    }
}
