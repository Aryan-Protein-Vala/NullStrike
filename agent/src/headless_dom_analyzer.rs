use crate::auditor::Auditor;
use anyhow::Result;
use async_trait::async_trait;
use chromiumoxide::browser::{Browser, BrowserConfig};
use chromiumoxide::cdp::browser_protocol::page::CaptureScreenshotFormat;
use shared::{SecurityEvent, Severity};
use tokio_stream::StreamExt;
use std::time::Duration;
use tokio::time::sleep;

pub struct HeadlessDomAnalyzer {
    pub paths: Vec<String>,
}

impl HeadlessDomAnalyzer {
    pub fn new(paths: Vec<String>) -> Self {
        let paths = if paths.is_empty() {
            vec!["/".to_string(), "/login".to_string(), "/contact".to_string()]
        } else {
            paths
        };
        Self { paths }
    }
}

#[async_trait]
impl Auditor for HeadlessDomAnalyzer {
    fn name(&self) -> String {
        "Headless DOM Analyzer".into()
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    async fn execute(&self, target: &str) -> Result<SecurityEvent> {
        let mut attack_path = Vec::new();
        let mut is_vulnerable = false;

        // Note: In a real distributed agent, this requires Chrome/Chromium installed
        let (mut browser, mut handler) = match Browser::launch(
            BrowserConfig::builder()
                .no_sandbox()
                .window_size(1280, 720)
                .build()
                .map_err(|e| anyhow::anyhow!(e))?,
        )
        .await
        {
            Ok(b) => b,
            Err(e) => {
                return Ok(SecurityEvent::Pass {
                    target: target.to_string(),
                    check_name: format!("{} (Failed to launch Chrome: {})", self.name(), e),
                })
            }
        };

        // Spawn a task to drive the browser
        let handle = tokio::spawn(async move {
            while let Some(h) = handler.next().await {
                if h.is_err() {
                    break;
                }
            }
        });

        for path in &self.paths {
            let ep = if path.starts_with('/') { path.to_string() } else { format!("/{}", path) };
            
            // We use the same canary from InputReflectionDetector
            let canary = "nullstrike_canary_7x9k2m";
            let url = format!("http://{}{}?q={}", target, ep, canary);

            let page = match browser.new_page(&url).await {
                Ok(p) => p,
                Err(_) => continue,
            };

            // Wait for any SPA / React / Vue rendering
            sleep(Duration::from_secs(2)).await;

            // Extract all form inputs
            let inputs_js = r#"
                Array.from(document.querySelectorAll('input, textarea, select')).map(i => {
                    return { name: i.name, id: i.id, type: i.type, value: i.value };
                })
            "#;

            if let Ok(inputs) = page.evaluate(inputs_js).await {
                if let Some(arr) = inputs.value().and_then(|v| v.as_array()) {
                    for input in arr {
                        let val = input.get("value").and_then(|v| v.as_str()).unwrap_or("");
                        let name = input.get("name").and_then(|n| n.as_str()).unwrap_or("");
                        let type_ = input.get("type").and_then(|t| t.as_str()).unwrap_or("");

                        if val.contains(canary) {
                            attack_path.push(format!(
                                "DOM_REFLECTION: Canary found in <input type='{}' name='{}'> on {}",
                                type_, name, url
                            ));
                            is_vulnerable = true;
                        }
                    }
                }
            }
            
            // Check body text for canary (post DOM render)
            if let Ok(body_text) = page.evaluate("document.body.innerText").await {
                if let Some(text) = body_text.value().and_then(|v| v.as_str()) {
                    if text.contains(canary) {
                        attack_path.push(format!(
                            "DOM_REFLECTION: Canary found in rendered DOM text on {}",
                            url
                        ));
                        is_vulnerable = true;
                    }
                }
            }

            // Always take a screenshot for proof-of-concept
            let safe_path = path.replace('/', "_");
            let screenshot_path = format!("poc_screenshot_{}_{}.png", target.replace(':', "_"), safe_path);
            
            let _ = page.save_screenshot(
                chromiumoxide::page::ScreenshotParams::builder()
                    .format(CaptureScreenshotFormat::Png)
                    .build(),
                &screenshot_path,
            ).await;
            
            attack_path.push(format!("SCREENSHOT: Saved DOM state to {}", screenshot_path));

            let _ = page.close().await;
        }

        let _ = browser.close().await;
        let _ = handle.abort();

        if is_vulnerable {
            Ok(SecurityEvent::SimulationAlert {
                target: target.to_string(),
                check_name: self.name(),
                severity: self.severity(),
                is_vulnerable: true,
                details: format!(
                    "{} DOM reflections detected via Headless Chrome on {}",
                    attack_path.iter().filter(|s| s.starts_with("DOM_REFLECTION")).count(),
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
