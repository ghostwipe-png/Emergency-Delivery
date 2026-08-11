//! Mobitech Technologies SMS gateway (Kenya). Sender ID: FULL_CIRCLE.
//! Endpoint: POST https://app.mobitechtechnologies.com//sms/sendsms
//! Auth: `h_api_key` header. Success: status_code 1000.
//!
//! NOTE: Mobitech sometimes returns an empty array `[]` even when the SMS
//! is accepted. We treat HTTP 200 + empty response as "likely sent" and
//! NEVER retry ambiguous responses to avoid duplicate sends.

use std::time::Duration;

use crate::errors::AppError;

const DEFAULT_API_URL: &str = "https://app.mobitechtechnologies.com//sms/sendsms";

#[derive(Clone)]
pub struct MobitechClient {
    http: reqwest::Client,
    api_key: String,
    api_url: String,
    sender_id: String,
}

impl MobitechClient {
    pub fn new(api_key: String, api_url: Option<String>) -> Result<Self, AppError> {
        if api_key.trim().is_empty() {
            return Err(AppError::Config("MOBITECH_API_KEY is empty".into()));
        }
        let url = api_url.unwrap_or_else(|| DEFAULT_API_URL.into());
        if !url.starts_with("https://") {
            return Err(AppError::Config("MOBITECH_API_URL must use HTTPS".into()));
        }
        let http = reqwest::Client::builder()
            .https_only(true)
            .use_rustls_tls()
            .timeout(Duration::from_secs(30))
            .connect_timeout(Duration::from_secs(10))
            .build()
            .map_err(|e| AppError::Config(format!("http client init failed: {e}")))?;

        Ok(Self {
            http,
            api_key,
            api_url: url,
            sender_id: "FULL_CIRCLE".to_string(),
        })
    }

    /// Sends one SMS. NO retries — Mobitech occasionally sends immediately
    /// and returns `[]`, so retrying would duplicate the SMS.
    pub async fn send_sms(&self, phone: &str, message: &str) -> Result<String, AppError> {
        let phone = format!("+{phone}");
        
        let body = serde_json::json!({
            "mobile": phone,
            "response_type": "json",
            "sender_name": self.sender_id,
            "service_id": 0,
            "message": message,
        });

        let response = self
            .http
            .post(&self.api_url)
            .header("h_api_key", &self.api_key)
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .await
            .map_err(|e| {
                tracing::error!(url = %self.api_url, error = %e, "Mobitech request failed");
                AppError::Network(format!("SMS gateway unreachable: {e}"))
            })?;

        let status = response.status();
        let text = response.text().await.unwrap_or_default();

        if !status.is_success() {
            tracing::error!(http_status = %status, body = %truncate(&text, 512), "Mobitech HTTP error");
            return Err(AppError::Network(format!("SMS gateway returned HTTP {status}")));
        }

        // Try to parse the JSON array response
        let parsed: serde_json::Value = serde_json::from_str(&text).unwrap_or_else(|_| serde_json::Value::Array(vec![]));

        // Case 1: Empty array `[]` — Mobitech accepted the request and likely
        // sent the SMS, but returned no confirmation. Assume success, DON'T retry.
        if parsed.as_array().map(|a| a.is_empty()).unwrap_or(false) {
            tracing::info!(phone = %mask_phone(&phone), "Mobitech returned empty array — assuming SMS sent");
            return Ok("mobitech-accepted-no-confirmation".into());
        }

        // Case 2: Non-empty array — check status_code
        let first = match parsed.get(0) {
            Some(f) => f,
            None => {
                tracing::warn!(phone = %mask_phone(&phone), "Mobitech response malformed — assuming sent");
                return Ok("mobitech-malformed-response".into());
            }
        };

        let code = first
            .get("status_code")
            .and_then(|v| v.as_i64().map(|n| n.to_string()).or_else(|| v.as_str().map(str::to_string)))
            .unwrap_or_default();
        let desc = first.get("status_desc").and_then(|v| v.as_str()).unwrap_or("unknown");

        if code == "1000" {
            let message_id = first
                .get("message_id")
                .and_then(|v| v.as_i64().map(|n| n.to_string()).or_else(|| v.as_str().map(str::to_string)))
                .unwrap_or_else(|| "mobitech-ok".into());

            tracing::info!(phone = %mask_phone(&phone), message_id = %message_id, "SMS accepted by Mobitech");
            return Ok(message_id);
        }

        // Explicit error from Mobitech — don't retry, just report
        tracing::warn!(code = %code, desc, phone = %mask_phone(&phone), "Mobitech rejected SMS");
        Err(gateway_error(&code, desc))
    }
}

/// Maps Mobitech status codes to user-actionable errors.
fn gateway_error(code: &str, desc: &str) -> AppError {
    match code {
        "1001" => AppError::Config("SMS sender ID not approved by Mobitech (1001)".into()),
        "1003" | "1015" => AppError::Validation(format!("SMS rejected: {desc}")),
        "1004" | "1016" => AppError::Payment(format!("Mobitech account: {desc}")),
        "1006" | "1013" => AppError::Config(format!("Mobitech auth failed: {desc}")),
        "1012" => AppError::Validation(format!("SMS rejected: {desc}")),
        _ => AppError::Network(format!("SMS gateway error {code}: {desc}")),
    }
}

fn truncate(s: &str, max: usize) -> String {
    s.chars().take(max).collect()
}

/// Masks a phone number for safe logging: +2547****XX.
fn mask_phone(phone: &str) -> String {
    let chars: Vec<char> = phone.chars().collect();
    if chars.len() < 4 {
        return "****".into();
    }
    format!("{}****{}", &phone[..4], &phone[phone.len() - 2..])
}