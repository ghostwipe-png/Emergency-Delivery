//! Data models. `*Record` types map 1:1 to database rows; API types cross IPC.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::crypto;
use crate::errors::AppError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryStatus {
    Pending,
    Delivered,
    Cancelled,
    Failed,
}

impl DeliveryStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            DeliveryStatus::Pending => "pending",
            DeliveryStatus::Delivered => "delivered",
            DeliveryStatus::Cancelled => "cancelled",
            DeliveryStatus::Failed => "failed",
        }
    }
    pub fn parse(value: &str) -> Result<Self, AppError> {
        match value {
            "pending" => Ok(Self::Pending),
            "delivered" => Ok(Self::Delivered),
            "cancelled" => Ok(Self::Cancelled),
            "failed" => Ok(Self::Failed),
            other => {
                tracing::warn!(status = %other, "unknown delivery status in database");
                Err(AppError::Internal("unknown delivery status".into()))
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SenderMode {
    Anonymous,
    Identified,
}

impl SenderMode {
    pub fn as_str(self) -> &'static str {
        match self {
            SenderMode::Anonymous => "anonymous",
            SenderMode::Identified => "identified",
        }
    }
    pub fn parse(value: &str) -> Result<Self, AppError> {
        match value {
            "anonymous" => Ok(Self::Anonymous),
            "identified" => Ok(Self::Identified),
            other => {
                tracing::warn!(mode = %other, "unknown sender mode in database");
                Err(AppError::Internal("unknown sender mode".into()))
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryChannel {
    Email,
    Sms,
}

impl DeliveryChannel {
    pub fn as_str(self) -> &'static str {
        match self {
            DeliveryChannel::Email => "email",
            DeliveryChannel::Sms => "sms",
        }
    }
    pub fn parse(value: &str) -> Result<Self, AppError> {
        match value {
            "email" => Ok(Self::Email),
            "sms" => Ok(Self::Sms),
            other => {
                tracing::warn!(channel = %other, "unknown channel in database");
                Err(AppError::Internal("unknown delivery channel".into()))
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContentType {
    File,
    Text,
}

impl ContentType {
    pub fn as_str(self) -> &'static str {
        match self {
            ContentType::File => "file",
            ContentType::Text => "text",
        }
    }
    pub fn parse(value: &str) -> Result<Self, AppError> {
        match value {
            "file" => Ok(Self::File),
            "text" => Ok(Self::Text),
            other => {
                tracing::warn!(content_type = %other, "unknown content type in database");
                Err(AppError::Internal("unknown content type".into()))
            }
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct User {
    pub id: String,
    pub email: String,
    pub name: Option<String>,
    pub delivery_credits: i64,
    pub totp_enabled: bool,
    pub tos_version: i32,
    pub tos_accepted_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    // Phase 4 Additive: Dead Man's Switch
    pub heartbeat_interval_days: i32,
    pub last_heartbeat_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct UserRecord {
    pub id: String,
    pub email: String,
    pub name: Option<String>,
    pub password_hash: String,
    pub password_salt: String,
    pub delivery_credits: i64,
    pub totp_secret: Option<String>,
    pub totp_enabled: bool,
    pub tos_version: i32,
    pub tos_accepted_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    // Phase 4 Additive: Dead Man's Switch
    pub heartbeat_interval_days: i32,
    pub last_heartbeat_at: Option<DateTime<Utc>>,
}

impl UserRecord {
    pub fn to_public(&self) -> User {
        User {
            id: self.id.clone(),
            email: self.email.clone(),
            name: self.name.clone(),
            delivery_credits: self.delivery_credits,
            totp_enabled: self.totp_enabled,
            tos_version: self.tos_version,
            tos_accepted_at: self.tos_accepted_at,
            created_at: self.created_at,
            // Phase 4 Additive mappings
            heartbeat_interval_days: self.heartbeat_interval_days,
            last_heartbeat_at: self.last_heartbeat_at,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct AuthResponse {
    pub token: String,
    pub user: User,
    pub expires_at: DateTime<Utc>,
    pub two_factor_required: bool,
    pub tos_update_required: bool,
}

#[derive(Debug, Serialize)]
pub struct TwoFactorSetup {
    pub secret_base32: String,
    pub otpauth_url: String,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct UploadRecord {
    pub file_key: String,
    pub user_id: String,
    pub file_name: String,
    pub file_size: i64,
    pub file_type: String,
    pub wrapped_dek: Option<String>,
    pub dek_nonce: Option<String>,
    pub used: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize)]
pub struct UploadResult {
    pub file_key: String,
    pub file_name: String,
    pub file_size: i64,
    pub file_type: String,
    pub storage: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct PresignedUrl {
    pub url: String,
    pub file_key: String,
    pub expires_in_secs: u64,
    pub note: String,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct DeliveryRecord {
    pub id: String,
    pub user_id: String,
    pub content_type: String,
    pub channel: String,
    pub file_name: Option<String>,
    pub file_size: i64,
    pub file_type: Option<String>,
    pub file_key: Option<String>,
    pub wrapped_dek: Option<String>,
    pub dek_nonce: Option<String>,
    pub message_text: Option<String>,
    pub recipient_name: String,
    pub recipient_email: Option<String>,
    pub recipient_phone: Option<String>,
    pub sender_mode: String,
    pub sender_name: Option<String>,
    pub sender_email: Option<String>,
    pub scheduled_for: DateTime<Utc>,
    pub status: String,
    pub delivery_token: String,
    pub created_at: DateTime<Utc>,
    pub delivered_at: Option<DateTime<Utc>>,
    pub link_expires_at: Option<DateTime<Utc>>,
    pub link_max_views: Option<i64>,
    pub claim_password_hash: Option<String>,
    pub claim_password_salt: Option<String>,
    pub claim_pw_wrapped_dek: Option<String>,
    pub recurrence: Option<String>,
    pub worker_registered: i32,
    pub worker_payload_enc: Option<String>,
    // Phase 4 Additive: Dead Man's Switch
    pub is_emergency: i32,
}

#[derive(Debug, Clone, Serialize)]
pub struct Delivery {
    pub id: String,
    pub content_type: ContentType,
    pub channel: DeliveryChannel,
    pub file_name: Option<String>,
    pub file_size: i64,
    pub file_type: Option<String>,
    pub message_text: Option<String>,
    pub recipient_name: String,
    pub recipient_email: Option<String>,
    pub recipient_phone: Option<String>,
    pub sender_mode: SenderMode,
    pub sender_name: Option<String>,
    pub sender_email: Option<String>,
    pub scheduled_for: DateTime<Utc>,
    pub status: DeliveryStatus,
    pub created_at: DateTime<Utc>,
    pub delivered_at: Option<DateTime<Utc>>,
    pub link_expires_at: Option<DateTime<Utc>>,
    pub link_max_views: Option<i64>,
    pub has_claim_password: bool,
    pub recurrence: Option<String>,
    // Phase 4 Additive: Dead Man's Switch
    pub is_emergency: bool,
}

impl Delivery {
    pub fn from_record(rec: &DeliveryRecord, kek: &[u8; crypto::KEY_LEN]) -> Result<Self, AppError> {
        Ok(Self {
            id: rec.id.clone(),
            content_type: ContentType::parse(&rec.content_type)?,
            channel: DeliveryChannel::parse(&rec.channel)?,
            file_name: rec.file_name.clone(),
            file_size: rec.file_size,
            file_type: rec.file_type.clone(),
            message_text: crypto::decrypt_field_opt(kek, &rec.message_text)?,
            recipient_name: rec.recipient_name.clone(),
            recipient_email: crypto::decrypt_field_opt(kek, &rec.recipient_email)?,
            recipient_phone: crypto::decrypt_field_opt(kek, &rec.recipient_phone)?,
            sender_mode: SenderMode::parse(&rec.sender_mode)?,
            sender_name: crypto::decrypt_field_opt(kek, &rec.sender_name)?,
            sender_email: crypto::decrypt_field_opt(kek, &rec.sender_email)?,
            scheduled_for: rec.scheduled_for,
            status: DeliveryStatus::parse(&rec.status)?,
            created_at: rec.created_at,
            delivered_at: rec.delivered_at,
            link_expires_at: rec.link_expires_at,
            link_max_views: rec.link_max_views,
            has_claim_password: rec.claim_password_hash.is_some(),
            recurrence: rec.recurrence.clone(),
            // Phase 4 Additive mapping
            is_emergency: rec.is_emergency != 0,
        })
    }
}

#[derive(Debug, Deserialize)]
pub struct NewDelivery {
    pub file_key: Option<String>,
    pub message_text: Option<String>,
    #[serde(default = "default_channel")]
    pub channel: DeliveryChannel,
    pub recipient_name: String,
    pub recipient_email: Option<String>,
    #[serde(default)]
    pub recipient_emails: Option<Vec<String>>,
    pub recipient_phone: Option<String>,
    pub sender_mode: SenderMode,
    pub sender_name: Option<String>,
    pub sender_email: Option<String>,
    pub scheduled_for: DateTime<Utc>,
    #[serde(default)]
    pub link_expires_hours: Option<i64>,
    #[serde(default)]
    pub link_max_views: Option<i64>,
    #[serde(default)]
    pub claim_password: Option<String>,
    #[serde(default)]
    pub recurrence: Option<String>,
    // Phase 4 Additive: Dead Man's Switch
    #[serde(default)]
    pub is_emergency: Option<bool>,
}

fn default_channel() -> DeliveryChannel {
    DeliveryChannel::Email
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct PaymentPlan {
    pub id: String,
    pub name: String,
    pub deliveries: i64,
    pub price: f64,
    pub price_in_kobo: i64,
    pub currency: String,
}

#[derive(Debug, Deserialize)]
pub struct PaymentRequest {
    pub plan_id: String,
    #[serde(default)]
    pub user_email: Option<String>,
    #[serde(default)]
    pub user_id: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct PaymentResponse {
    pub success: bool,
    pub authorization_url: Option<String>,
    pub reference: String,
    pub message: String,
}

#[derive(Debug, Serialize)]
pub struct PaymentVerification {
    pub verified: bool,
    pub status: String,
    pub credits_added: i64,
    pub message: String,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct PaymentRecord {
    pub id: String,
    pub user_id: String,
    pub plan_id: String,
    pub reference: String,
    pub amount_kobo: i64,
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub verified_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct SmsBalance {
    pub user_id: String,
    pub free_sms_used: i64,
}

#[derive(Debug, Serialize)]
pub struct SmsStatus {
    pub free_remaining: i64,
    pub credits: i64,
    pub sms_configured: bool,
}

#[derive(Debug, Serialize)]
pub struct SmsResult {
    pub success: bool,
    pub message_id: String,
    pub used_free_sms: bool,
    pub free_remaining: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiptEvent {
    #[serde(rename = "type")]
    pub kind: String,
    pub at: String,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct AnalyticsSummary {
    pub total: i64,
    pub delivered: i64,
    pub pending: i64,
    pub cancelled: i64,
    pub failed: i64,
    pub emails: i64,
    pub sms: i64,
    pub files: i64,
    pub texts: i64,
    pub bytes_sent: i64,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct DailyStat {
    pub day: String,
    pub count: i64,
}

#[derive(Debug, Serialize)]
pub struct Analytics {
    pub summary: AnalyticsSummary,
    pub daily: Vec<DailyStat>,
}

#[derive(Debug, Serialize)]
pub struct SystemInfo {
    pub app_version: String,
    pub platform: String,
    pub arch: String,
    pub local_time: String,
    pub storage_backend: String,
    pub paystack_configured: bool,
    pub worker_configured: bool,
    pub mobitech_configured: bool,
    pub pending_deliveries: i64,
    pub delivered_deliveries: i64,
}