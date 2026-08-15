//! Data models. `*Record` types map 1:1 to database rows; API types cross IPC.
//!
//! SECURITY CONSIDERATIONS:
//! - `UserRecord` contains sensitive fields (password_hash, password_salt, totp_secret)
//!   and MUST NOT derive `Serialize` to prevent accidental exposure
//! - `Delivery::from_record` handles decryption failures gracefully (returns None for field)
//! - All input structs (`NewDelivery`, `PaymentRequest`) have validation methods
//!
//! @version 2.0.0
//! @status PRODUCTION

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;

use crate::crypto;
use crate::errors::AppError;

// =============================================================================
// ENUMS (Type-Safe Status/Channel/Mode)
// =============================================================================

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
                Err(AppError::Internal(format!(
                    "unknown delivery status: {}",
                    other
                )))
            }
        }
    }

    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Delivered | Self::Cancelled | Self::Failed)
    }
}

impl fmt::Display for DeliveryStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
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
                Err(AppError::Internal(format!("unknown sender mode: {}", other)))
            }
        }
    }
}

impl fmt::Display for SenderMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
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
                Err(AppError::Internal(format!("unknown delivery channel: {}", other)))
            }
        }
    }
}

impl fmt::Display for DeliveryChannel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
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
                Err(AppError::Internal(format!("unknown content type: {}", other)))
            }
        }
    }
}

impl fmt::Display for ContentType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecurrencePattern {
    Daily,
    Weekly,
    Monthly,
    None,
}

impl RecurrencePattern {
    pub fn as_str(self) -> &'static str {
        match self {
            RecurrencePattern::Daily => "daily",
            RecurrencePattern::Weekly => "weekly",
            RecurrencePattern::Monthly => "monthly",
            RecurrencePattern::None => "none",
        }
    }

    pub fn parse(value: &str) -> Result<Self, AppError> {
        match value.to_lowercase().as_str() {
            "daily" => Ok(Self::Daily),
            "weekly" => Ok(Self::Weekly),
            "monthly" => Ok(Self::Monthly),
            "none" | "" => Ok(Self::None),
            other => Err(AppError::Validation(format!(
                "invalid recurrence pattern: {} (use daily, weekly, monthly, or none)",
                other
            ))),
        }
    }
}

impl fmt::Display for RecurrencePattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// =============================================================================
// USER MODELS
// =============================================================================

/// Public user data (safe to send to frontend).
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct User {
    pub id: String,
    pub email: String,
    pub name: Option<String>,
    pub delivery_credits: i64,
    pub sms_balance: i64,
    pub totp_enabled: bool,
    pub tos_version: i32,
    pub tos_accepted_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub heartbeat_interval_days: i32,
    pub last_heartbeat_at: Option<DateTime<Utc>>,
    pub subscription_expires_at: Option<DateTime<Utc>>,
    pub registration_bonus_claimed: bool,
}

/// Database user record (contains sensitive fields - DO NOT serialize).
///
/// SECURITY: This struct contains `password_hash`, `password_salt`, and `totp_secret`.
/// It intentionally does NOT derive `Serialize` to prevent accidental exposure via IPC.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct UserRecord {
    pub id: String,
    pub email: String,
    pub name: Option<String>,
    pub password_hash: String,
    pub password_salt: String,
    pub delivery_credits: i64,
    pub sms_balance: i64,
    pub totp_secret: Option<String>,
    pub totp_enabled: bool,
    pub tos_version: i32,
    pub tos_accepted_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub heartbeat_interval_days: i32,
    pub last_heartbeat_at: Option<DateTime<Utc>>,
    pub subscription_expires_at: Option<String>,
    pub registration_bonus_claimed: i32,
}

impl UserRecord {
    /// Convert to public-facing `User` struct (strips sensitive fields).
    pub fn to_public(&self) -> User {
        User {
            id: self.id.clone(),
            email: self.email.clone(),
            name: self.name.clone(),
            delivery_credits: self.delivery_credits,
            sms_balance: self.sms_balance,
            totp_enabled: self.totp_enabled,
            tos_version: self.tos_version,
            tos_accepted_at: self.tos_accepted_at,
            created_at: self.created_at,
            heartbeat_interval_days: self.heartbeat_interval_days,
            last_heartbeat_at: self.last_heartbeat_at,
            subscription_expires_at: self
                .subscription_expires_at
                .as_ref()
                .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                .map(|d| d.with_timezone(&Utc)),
            registration_bonus_claimed: self.registration_bonus_claimed != 0,
        }
    }
}

// =============================================================================
// AUTHENTICATION MODELS
// =============================================================================

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct AuthResponse {
    pub token: String,
    pub user: User,
    pub expires_at: DateTime<Utc>,
    pub two_factor_required: bool,
    pub tos_update_required: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct TwoFactorSetup {
    pub secret_base32: String,
    pub otpauth_url: String,
}

// =============================================================================
// UPLOAD MODELS
// =============================================================================

#[derive(Debug, Clone, sqlx::FromRow, PartialEq)]
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

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct UploadResult {
    pub file_key: String,
    pub file_name: String,
    pub file_size: i64,
    pub file_type: String,
    pub storage: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct PresignedUrl {
    pub url: String,
    pub file_key: String,
    pub expires_in_secs: u64,
    pub note: String,
}

// =============================================================================
// DELIVERY MODELS
// =============================================================================

/// Database delivery record (stores encrypted fields as strings).
#[derive(Debug, Clone, sqlx::FromRow, PartialEq)]
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
    pub is_emergency: i32,
}

/// Public delivery data (decrypted, safe to send to frontend).
#[derive(Debug, Clone, Serialize, PartialEq)]
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
    pub recurrence: Option<RecurrencePattern>,
    pub is_emergency: bool,
}

impl Delivery {
    /// Convert database record to public delivery (decrypts sensitive fields).
    ///
    /// # Error Handling
    /// If decryption fails for a field, that field is set to `None` rather than
    /// failing the entire conversion. This prevents one corrupted record from
    /// breaking the entire delivery list.
    pub fn from_record(rec: &DeliveryRecord, kek: &[u8; crypto::KEY_LEN]) -> Result<Self, AppError> {
        // Parse enums (these should never fail if DB is consistent)
        let content_type = ContentType::parse(&rec.content_type)?;
        let channel = DeliveryChannel::parse(&rec.channel)?;
        let sender_mode = SenderMode::parse(&rec.sender_mode)?;
        let status = DeliveryStatus::parse(&rec.status)?;

        // Decrypt fields gracefully (return None on failure instead of error)
        // Note: decrypt_field_opt returns Option<Zeroizing<String>>, convert to Option<String>
        let message_text = match crypto::decrypt_field_opt(kek, &rec.message_text) {
            Ok(Some(val)) => Some(val.to_string()),
            Ok(None) => None,
            Err(e) => {
                tracing::warn!(
                    delivery_id = %rec.id,
                    error = %e,
                    "failed to decrypt message_text"
                );
                None
            }
        };

        let recipient_email = match crypto::decrypt_field_opt(kek, &rec.recipient_email) {
            Ok(Some(val)) => Some(val.to_string()),
            Ok(None) => None,
            Err(e) => {
                tracing::warn!(
                    delivery_id = %rec.id,
                    error = %e,
                    "failed to decrypt recipient_email"
                );
                None
            }
        };

        let recipient_phone = match crypto::decrypt_field_opt(kek, &rec.recipient_phone) {
            Ok(Some(val)) => Some(val.to_string()),
            Ok(None) => None,
            Err(e) => {
                tracing::warn!(
                    delivery_id = %rec.id,
                    error = %e,
                    "failed to decrypt recipient_phone"
                );
                None
            }
        };

        let sender_name = match crypto::decrypt_field_opt(kek, &rec.sender_name) {
            Ok(Some(val)) => Some(val.to_string()),
            Ok(None) => None,
            Err(e) => {
                tracing::warn!(
                    delivery_id = %rec.id,
                    error = %e,
                    "failed to decrypt sender_name"
                );
                None
            }
        };

        let sender_email = match crypto::decrypt_field_opt(kek, &rec.sender_email) {
            Ok(Some(val)) => Some(val.to_string()),
            Ok(None) => None,
            Err(e) => {
                tracing::warn!(
                    delivery_id = %rec.id,
                    error = %e,
                    "failed to decrypt sender_email"
                );
                None
            }
        };

        // Parse recurrence pattern (optional, default to None)
        let recurrence = rec
            .recurrence
            .as_ref()
            .and_then(|r| RecurrencePattern::parse(r).ok());

        Ok(Self {
            id: rec.id.clone(),
            content_type,
            channel,
            file_name: rec.file_name.clone(),
            file_size: rec.file_size,
            file_type: rec.file_type.clone(),
            message_text,
            recipient_name: rec.recipient_name.clone(),
            recipient_email,
            recipient_phone,
            sender_mode,
            sender_name,
            sender_email,
            scheduled_for: rec.scheduled_for,
            status,
            created_at: rec.created_at,
            delivered_at: rec.delivered_at,
            link_expires_at: rec.link_expires_at,
            link_max_views: rec.link_max_views,
            has_claim_password: rec.claim_password_hash.is_some(),
            recurrence,
            is_emergency: rec.is_emergency != 0,
        })
    }
}

/// Input for creating a new delivery (from frontend).
#[derive(Debug, Clone, Deserialize, PartialEq)]
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
    #[serde(default)]
    pub is_emergency: Option<bool>,
}

impl NewDelivery {
    /// Validate the delivery input.
    ///
    /// # Checks
    /// - Exactly one of `file_key` or `message_text` must be provided
    /// - At least one recipient (email or phone) must be provided
    /// - `scheduled_for` must be in the future
    /// - `link_expires_hours` must be positive if provided
    /// - `link_max_views` must be positive if provided
    pub fn validate(&self) -> Result<(), AppError> {
        // Validate content (exactly one: file OR text)
        let has_file = self.file_key.as_ref().map(|k| !k.trim().is_empty()).unwrap_or(false);
        let has_text = self.message_text.as_ref().map(|m| !m.trim().is_empty()).unwrap_or(false);

        if has_file == has_text {
            return Err(AppError::Validation(
                "provide either a file or a typed message (exactly one)".into(),
            ));
        }

        // Validate recipients
        let has_single_email = self.recipient_email.as_ref().map(|e| !e.trim().is_empty()).unwrap_or(false);
        let has_bulk_emails = self.recipient_emails.as_ref().map(|e| !e.is_empty()).unwrap_or(false);
        let has_phone = self.recipient_phone.as_ref().map(|p| !p.trim().is_empty()).unwrap_or(false);

        if !has_single_email && !has_bulk_emails && !has_phone {
            return Err(AppError::Validation(
                "at least one recipient (email or phone) is required".into(),
            ));
        }

        // Validate channel matches recipient type
        if self.channel == DeliveryChannel::Sms && !has_phone {
            return Err(AppError::Validation(
                "SMS channel requires a phone number".into(),
            ));
        }

        if self.channel == DeliveryChannel::Email && !has_single_email && !has_bulk_emails {
            return Err(AppError::Validation(
                "Email channel requires at least one email address".into(),
            ));
        }

        // Validate scheduled_for is in the future
        if self.scheduled_for <= Utc::now() {
            return Err(AppError::Validation(
                "scheduled_for must be in the future".into(),
            ));
        }

        // Validate link controls
        if let Some(hours) = self.link_expires_hours {
            if hours <= 0 {
                return Err(AppError::Validation(
                    "link_expires_hours must be positive".into(),
                ));
            }
            if hours > 24 * 365 {
                return Err(AppError::Validation(
                    "link_expires_hours cannot exceed 1 year (8760 hours)".into(),
                ));
            }
        }

        if let Some(views) = self.link_max_views {
            if views <= 0 {
                return Err(AppError::Validation(
                    "link_max_views must be positive".into(),
                ));
            }
            if views > 1000 {
                return Err(AppError::Validation(
                    "link_max_views cannot exceed 1000".into(),
                ));
            }
        }

        // Validate recurrence pattern
        if let Some(ref recurrence) = self.recurrence {
            RecurrencePattern::parse(recurrence)?;
        }

        // Validate claim password (only for files)
        if let Some(ref pw) = self.claim_password {
            if !pw.trim().is_empty() && !has_file {
                return Err(AppError::Validation(
                    "password protection is only supported for file deliveries".into(),
                ));
            }
        }

        Ok(())
    }
}

fn default_channel() -> DeliveryChannel {
    DeliveryChannel::Email
}

// =============================================================================
// PAYMENT MODELS
// =============================================================================

#[derive(Debug, Clone, Serialize, sqlx::FromRow, PartialEq)]
pub struct PaymentPlan {
    pub id: String,
    pub name: String,
    pub emails: i64,
    pub sms: i64,
    pub price_in_kobo: i64,
    pub is_subscription: bool,
    pub description: String,
    pub currency: String,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct PaymentRequest {
    pub plan_id: String,
    #[serde(default)]
    pub user_email: Option<String>,
    #[serde(default)]
    pub user_id: Option<String>,
}

impl PaymentRequest {
    pub fn validate(&self) -> Result<(), AppError> {
        if self.plan_id.trim().is_empty() {
            return Err(AppError::Validation("plan_id is required".into()));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct PaymentResponse {
    pub success: bool,
    pub authorization_url: Option<String>,
    pub reference: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct PaymentVerification {
    pub verified: bool,
    pub status: String,
    pub emails_added: i64,
    pub sms_added: i64,
    pub message: String,
}

#[derive(Debug, Clone, sqlx::FromRow, PartialEq)]
pub struct PaymentRecord {
    pub id: String,
    pub user_id: String,
    pub plan_id: String,
    pub reference: String,
    pub amount_kobo: i64,
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub verified_at: Option<DateTime<Utc>>,
    pub redeemed_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow, PartialEq)]
pub struct SmsBalance {
    pub user_id: String,
    pub free_sms_used: i64,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct SmsStatus {
    pub free_remaining: i64,
    pub credits: i64,
    pub sms_configured: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct SmsResult {
    pub success: bool,
    pub message_id: String,
    pub used_free_sms: bool,
    pub free_remaining: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ReceiptEvent {
    #[serde(rename = "type")]
    pub kind: String,
    pub at: String,
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow, PartialEq)]
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

#[derive(Debug, Clone, Serialize, sqlx::FromRow, PartialEq)]
pub struct DailyStat {
    pub day: String,
    pub count: i64,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Analytics {
    pub summary: AnalyticsSummary,
    pub daily: Vec<DailyStat>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
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

// =============================================================================
// BUILDER PATTERNS (For Complex Structs)
// =============================================================================

/// Builder for `NewDelivery` (safer than specifying all fields manually).
pub struct NewDeliveryBuilder {
    file_key: Option<String>,
    message_text: Option<String>,
    channel: DeliveryChannel,
    recipient_name: String,
    recipient_email: Option<String>,
    recipient_emails: Option<Vec<String>>,
    recipient_phone: Option<String>,
    sender_mode: SenderMode,
    sender_name: Option<String>,
    sender_email: Option<String>,
    scheduled_for: DateTime<Utc>,
    link_expires_hours: Option<i64>,
    link_max_views: Option<i64>,
    claim_password: Option<String>,
    recurrence: Option<String>,
    is_emergency: Option<bool>,
}

impl NewDeliveryBuilder {
    pub fn new(recipient_name: String, scheduled_for: DateTime<Utc>) -> Self {
        Self {
            file_key: None,
            message_text: None,
            channel: DeliveryChannel::Email,
            recipient_name,
            recipient_email: None,
            recipient_emails: None,
            recipient_phone: None,
            sender_mode: SenderMode::Anonymous,
            sender_name: None,
            sender_email: None,
            scheduled_for,
            link_expires_hours: None,
            link_max_views: None,
            claim_password: None,
            recurrence: None,
            is_emergency: None,
        }
    }

    pub fn with_file(mut self, file_key: String) -> Self {
        self.file_key = Some(file_key);
        self
    }

    pub fn with_message(mut self, message: String) -> Self {
        self.message_text = Some(message);
        self
    }

    pub fn with_channel(mut self, channel: DeliveryChannel) -> Self {
        self.channel = channel;
        self
    }

    pub fn with_email(mut self, email: String) -> Self {
        self.recipient_email = Some(email);
        self
    }

    pub fn with_bulk_emails(mut self, emails: Vec<String>) -> Self {
        self.recipient_emails = Some(emails);
        self
    }

    pub fn with_phone(mut self, phone: String) -> Self {
        self.recipient_phone = Some(phone);
        self
    }

    pub fn with_sender(mut self, name: String, email: String) -> Self {
        self.sender_mode = SenderMode::Identified;
        self.sender_name = Some(name);
        self.sender_email = Some(email);
        self
    }

    pub fn with_link_expiry(mut self, hours: i64) -> Self {
        self.link_expires_hours = Some(hours);
        self
    }

    pub fn with_max_views(mut self, views: i64) -> Self {
        self.link_max_views = Some(views);
        self
    }

    pub fn with_password(mut self, password: String) -> Self {
        self.claim_password = Some(password);
        self
    }

    pub fn with_recurrence(mut self, pattern: RecurrencePattern) -> Self {
        self.recurrence = Some(pattern.as_str().to_string());
        self
    }

    pub fn as_emergency(mut self) -> Self {
        self.is_emergency = Some(true);
        self
    }

    pub fn build(self) -> NewDelivery {
        NewDelivery {
            file_key: self.file_key,
            message_text: self.message_text,
            channel: self.channel,
            recipient_name: self.recipient_name,
            recipient_email: self.recipient_email,
            recipient_emails: self.recipient_emails,
            recipient_phone: self.recipient_phone,
            sender_mode: self.sender_mode,
            sender_name: self.sender_name,
            sender_email: self.sender_email,
            scheduled_for: self.scheduled_for,
            link_expires_hours: self.link_expires_hours,
            link_max_views: self.link_max_views,
            claim_password: self.claim_password,
            recurrence: self.recurrence,
            is_emergency: self.is_emergency,
        }
    }
}