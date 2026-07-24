use crate::auditor::Auditor;
use anyhow::Result;
use async_trait::async_trait;
use reqwest::Client;
use shared::{SecurityEvent, Severity};

/// Sensitive field names that indicate PII or secrets in a GraphQL schema.
const SENSITIVE_FIELD_NAMES: &[&str] = &[
    "password", "passwd", "secret", "token", "apiKey", "api_key",
    "accessToken", "access_token", "refreshToken", "refresh_token",
    "ssn", "socialSecurity", "creditCard", "credit_card", "cardNumber",
    "cvv", "pin", "privateKey", "private_key", "email", "phone",
];

/// The standard GraphQL introspection query.
const INTROSPECTION_QUERY: &str = r#"{"query":"{__schema{types{name kind fields{name type{name kind ofType{name}}}}}}"}"#;

/// Sends a GraphQL introspection query and parses the schema to identify
/// exposed types and sensitive field names. Read-only — no mutations.
pub struct GraphqlIntrospector {
    pub client: Client,
}

impl GraphqlIntrospector {
    pub fn new() -> Self {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap_or_default();

        Self { client }
    }
}

#[async_trait]
impl Auditor for GraphqlIntrospector {
    fn name(&self) -> String {
        "GraphQL Introspector".into()
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    async fn execute(&self, target: &str) -> Result<SecurityEvent> {
        let mut attack_path = Vec::new();
        let mut is_vulnerable = false;

        // Try common GraphQL endpoints
        let endpoints = ["/graphql", "/api/graphql", "/v1/graphql", "/query"];

        for ep in &endpoints {
            for scheme in &["https", "http"] {
                let url = format!("{}://{}{}", scheme, target, ep);

                let resp = match self
                    .client
                    .post(&url)
                    .header("Content-Type", "application/json")
                    .body(INTROSPECTION_QUERY)
                    .send()
                    .await
                {
                    Ok(r) => r,
                    Err(_) => continue,
                };

                if !resp.status().is_success() {
                    continue;
                }

                let body = match resp.text().await {
                    Ok(b) => b,
                    Err(_) => continue,
                };

                // Check if introspection was allowed
                if !body.contains("__schema") {
                    continue;
                }

                attack_path.push(format!(
                    "INTROSPECTION_ENABLED: GraphQL introspection is accessible at {}",
                    url
                ));
                is_vulnerable = true;

                // Parse the JSON response to extract types and fields
                if let Ok(json) = serde_json::from_str::<serde_json::Value>(&body) {
                    if let Some(types) = json
                        .pointer("/data/__schema/types")
                        .and_then(|v| v.as_array())
                    {
                        let mut user_types = Vec::new();
                        let mut sensitive_fields = Vec::new();

                        for type_obj in types {
                            let type_name = type_obj
                                .get("name")
                                .and_then(|n| n.as_str())
                                .unwrap_or("");

                            // Skip internal GraphQL types (prefixed with __)
                            if type_name.starts_with("__") || type_name.is_empty() {
                                continue;
                            }

                            let kind = type_obj
                                .get("kind")
                                .and_then(|k| k.as_str())
                                .unwrap_or("");

                            if kind == "OBJECT" {
                                user_types.push(type_name.to_string());

                                if let Some(fields) =
                                    type_obj.get("fields").and_then(|f| f.as_array())
                                {
                                    for field in fields {
                                        let field_name = field
                                            .get("name")
                                            .and_then(|n| n.as_str())
                                            .unwrap_or("");

                                        let field_lower = field_name.to_lowercase();
                                        for sensitive in SENSITIVE_FIELD_NAMES {
                                            if field_lower.contains(&sensitive.to_lowercase()) {
                                                sensitive_fields.push(format!(
                                                    "{}.{}",
                                                    type_name, field_name
                                                ));
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        if !user_types.is_empty() {
                            attack_path.push(format!(
                                "SCHEMA: {} user-defined types exposed: {}",
                                user_types.len(),
                                user_types
                                    .iter()
                                    .take(15)
                                    .cloned()
                                    .collect::<Vec<_>>()
                                    .join(", ")
                            ));
                        }

                        if !sensitive_fields.is_empty() {
                            for sf in &sensitive_fields {
                                attack_path.push(format!(
                                    "SENSITIVE_FIELD: {} — may expose PII or credentials",
                                    sf
                                ));
                            }
                        }
                    }
                }

                // Found introspection on this endpoint — no need to try other schemes
                break;
            }
        }

        if is_vulnerable {
            Ok(SecurityEvent::SimulationAlert {
                target: target.to_string(),
                check_name: self.name(),
                severity: Severity::High,
                is_vulnerable: true,
                details: format!(
                    "GraphQL introspection enabled on {} — full schema exposed",
                    target
                ),
                attack_path,
            })
        } else {
            Ok(SecurityEvent::Pass {
                target: target.to_string(),
                check_name: self.name(),
            })
        }
    }
}
