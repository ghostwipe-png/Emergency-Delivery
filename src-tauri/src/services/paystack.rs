//! Paystack API client. HTTPS-only, bearer auth with a secret key sourced from the environment.
//! PHASE 15 HARDENING: Added strict reference matching and currency validation.

use std::time::Duration;
use serde::Deserialize;
use crate::errors::AppError;

#[derive(Clone)]
pub struct PaystackClient {
    http: reqwest::Client,
    base_url: String,
    secret_key: String,
}

#[derive(Debug, Deserialize)]
struct Envelope<T> {
    status: bool,
    #[serde(default)]
    message: String,
    data: Option<T>,
}

#[derive(Debug, Deserialize)]
pub struct InitData {
    pub authorization_url: String,
    pub reference: String,
}

#[derive(Debug, Deserialize)]
pub struct VerifyData {
    pub status: String,
    pub amount: i64,       // In lowest currency unit (cents/kobo)
    pub reference: String,
    pub currency: String,  // PHASE 15: Added for strict currency validation
}

impl PaystackClient {
    pub fn new(secret_key: String, base_url: &str) -> Result<Self, AppError> {
        if secret_key.trim().is_empty() {
            return Err(AppError::Config("PAYSTACK_SECRET_KEY is empty".into()));
        }
        if !base_url.starts_with("https://") {
            return Err(AppError::Config("PAYSTACK_BASE_URL must use HTTPS".into()));
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
            base_url: base_url.trim_end_matches('/').to_string(),
            secret_key,
        })
    }

    pub async fn initialize_transaction(
        &self,
        email: &str,
        amount_cents: i64, // Paystack expects amount in lowest denomination (KES * 100)
        reference: &str,
    ) -> Result<InitData, AppError> {
        let body = serde_json::json!({
            "email": email,
            "amount": amount_cents,
            "reference": reference,
            "currency": "KES", // PHASE 15: Hardcode currency to KES
            "channels": ["card", "bank", "ussd", "mobile_money"],
            "metadata": { "product": "emergency-delivery-credits" }
        });

        let response = self
            .http
            .post(format!("{}/transaction/initialize", self.base_url))
            .bearer_auth(&self.secret_key)
            .json(&body)
            .send()
            .await?;

        let status = response.status();
        let envelope: Envelope<InitData> = response.json().await.map_err(|e| {
            tracing::error!(http_status = %status, error = %e, "failed to parse Paystack initialize response");
            AppError::Payment("unexpected response from payment gateway".into())
        })?;

        if !status.is_success() || !envelope.status {
            tracing::warn!(http_status = %status, message = %envelope.message, "Paystack initialize rejected");
            return Err(AppError::Payment(format!(
                "payment gateway rejected the request: {}",
                envelope.message
            )));
        }

        envelope
            .data
            .ok_or_else(|| AppError::Payment("payment gateway returned no data".into()))
    }

    pub async fn verify_transaction(&self, reference: &str) -> Result<VerifyData, AppError> {
        let response = self
            .http
            .get(format!("{}/transaction/verify/{}", self.base_url, reference))
            .bearer_auth(&self.secret_key)
            .send()
            .await?;

        let status = response.status();
        let envelope: Envelope<VerifyData> = response.json().await.map_err(|e| {
            tracing::error!(http_status = %status, error = %e, "failed to parse Paystack verify response");
            AppError::Payment("unexpected response from payment gateway".into())
        })?;

        if !status.is_success() || !envelope.status {
            return Err(AppError::Payment(format!(
                "payment verification failed: {}",
                envelope.message
            )));
        }

        let data = envelope
            .data
            .ok_or_else(|| AppError::Payment("payment gateway returned no data".into()))?;

        // PHASE 15 SECURITY: Strict reference matching
        if data.reference != reference {
            tracing::error!(expected = %reference, actual = %data.reference, "SECURITY: Paystack reference mismatch!");
            return Err(AppError::Payment("Reference mismatch in Paystack response".into()));
        }

        Ok(data)
    }
}