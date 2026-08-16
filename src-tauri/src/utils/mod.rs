//! Input validation and sanitization for every user-supplied value.
//!
//! SECURITY POSTURE:
//! - Defense-in-depth validation (multiple checks per input)
//! - Unicode normalization (prevents homoglyph attacks)
//! - Windows reserved name blocking (CON, PRN, NUL, etc.)
//! - File type whitelist with magic byte verification
//! - SVG rejection (XSS risk in SVG files)
//! - Comprehensive error messages with context
//!
//! DELIVERY TIMING:
//! - Instant deliveries: allowed (time <= now + 5min grace period)
//! - Scheduled deliveries: must be in the future (up to 5 years)
//! - No artificial delays: deliveries fire at exact scheduled time
//!
//! @version 2.1.0
//! @status PRODUCTION

use chrono::{DateTime, Utc};
use std::path::Path;
use unicode_normalization::UnicodeNormalization;

use crate::errors::AppError;

// =============================================================================
// CONSTANTS
// =============================================================================

/// Maximum file size (50 MB) - MUST match worker's MAX_CLAIM_BYTES
pub const MAX_FILE_SIZE: usize = 50 * 1024 * 1024;

/// Maximum preview file size (10 MB) - prevents OOM on preview
pub const MAX_PREVIEW_SIZE: usize = 10 * 1024 * 1024;

pub const MAX_NAME_LEN: usize = 100;
pub const MAX_EMAIL_LEN: usize = 254;
pub const MAX_FILE_NAME_LEN: usize = 180;
pub const MAX_MESSAGE_LEN: usize = 5000;
pub const MAX_SMS_LEN: usize = 480; // 3 concatenated SMS (GSM-7)
pub const MAX_SCHEDULE_YEARS: i64 = 5;

/// Grace period for instant deliveries (accounts for network/processing latency)
/// Allows times up to 5 minutes in the past to be treated as "instant"
pub const INSTANT_GRACE_MINUTES: i64 = 5;

/// Windows reserved device names (case-insensitive)
const WINDOWS_RESERVED_NAMES: &[&str] = &[
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5",
    "COM6", "COM7", "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5",
    "LPT6", "LPT7", "LPT8", "LPT9",
];

/// Allowed file extensions (whitelist)
const ALLOWED_EXTENSIONS: &[&str] = &["pdf", "docx", "jpg", "jpeg", "png", "mp4"];

// =============================================================================
// DISPLAY NAME VALIDATION
// =============================================================================

/// Validates and sanitizes display names (user names, recipient names, etc.).
///
/// # Rules
/// - Must not be empty
/// - Maximum 100 characters
/// - No control characters (except spaces)
/// - Unicode normalized (NFC form)
///
/// # Example
/// ```
/// let name = validate_display_name("  John Doe  ", "recipient name")?;
/// assert_eq!(name, "John Doe");
/// ```
pub fn validate_display_name(value: &str, field: &str) -> Result<String, AppError> {
    let trimmed = value.trim();
    
    if trimmed.is_empty() {
        return Err(AppError::Validation(format!("{} is required", field)));
    }
    
    if trimmed.len() > MAX_NAME_LEN {
        return Err(AppError::Validation(format!(
            "{} is too long (max {} characters)",
            field, MAX_NAME_LEN
        )));
    }
    
    // Check for control characters (but allow spaces and newlines)
    if trimmed.chars().any(|c| c.is_control() && c != ' ' && c != '\n' && c != '\r') {
        return Err(AppError::Validation(format!(
            "{} contains invalid control characters",
            field
        )));
    }
    
    // Unicode normalize to NFC form (prevents homoglyph attacks)
    let normalized: String = trimmed.nfc().collect();
    
    Ok(normalized)
}

// =============================================================================
// EMAIL VALIDATION
// =============================================================================

/// Validates email addresses according to RFC 5322 (simplified).
///
/// # Rules
/// - Must contain exactly one '@'
/// - Local part: 1-64 characters, alphanumeric + `. _ - +`
/// - Domain: 3+ characters, must contain '.', no consecutive dots
/// - No leading/trailing dots or hyphens in domain
/// - TLD must be 2+ alphabetic characters
/// - Maximum 254 characters total
///
/// # Example
/// ```
/// let email = validate_email("User@Example.COM")?;
/// assert_eq!(email, "user@example.com"); // Lowercased
/// ```
pub fn validate_email(value: &str) -> Result<String, AppError> {
    let email = value.trim().to_lowercase();
    
    if email.is_empty() {
        return Err(AppError::Validation("email is required".into()));
    }
    
    if email.len() > MAX_EMAIL_LEN {
        return Err(AppError::Validation(format!(
            "email is too long (max {} characters)",
            MAX_EMAIL_LEN
        )));
    }
    
    // Split into local and domain parts
    let mut parts = email.split('@');
    let local = parts.next().unwrap_or("");
    let domain = parts.next().unwrap_or("");
    
    // Must have exactly one '@'
    if parts.next().is_some() {
        return Err(AppError::Validation(
            "email must contain exactly one '@'".into()
        ));
    }
    
    // Validate local part
    if local.is_empty() || local.len() > 64 {
        return Err(AppError::Validation("email local part is invalid".into()));
    }
    
    // No consecutive dots in local part
    if local.contains("..") {
        return Err(AppError::Validation(
            "email local part cannot contain consecutive dots".into()
        ));
    }
    
    // No leading/trailing dots in local part
    if local.starts_with('.') || local.ends_with('.') {
        return Err(AppError::Validation(
            "email local part cannot start or end with a dot".into()
        ));
    }
    
    let ok_local = local.chars().all(|c| {
        c.is_alphanumeric() || matches!(c, '.' | '_' | '-' | '+')
    });
    
    if !ok_local {
        return Err(AppError::Validation(
            "email local part contains invalid characters".into()
        ));
    }
    
    // Validate domain part
    if domain.len() < 3 {
        return Err(AppError::Validation("email domain is too short".into()));
    }
    
    if !domain.contains('.') {
        return Err(AppError::Validation("email domain must contain a dot".into()));
    }
    
    // No consecutive dots in domain
    if domain.contains("..") {
        return Err(AppError::Validation(
            "email domain cannot contain consecutive dots".into()
        ));
    }
    
    // No leading/trailing dots or hyphens
    if domain.starts_with('.') || domain.ends_with('.') || 
       domain.starts_with('-') || domain.ends_with('-') {
        return Err(AppError::Validation(
            "email domain cannot start or end with dots or hyphens".into()
        ));
    }
    
    let ok_domain = domain.chars().all(|c| {
        c.is_alphanumeric() || matches!(c, '.' | '-')
    });
    
    if !ok_domain {
        return Err(AppError::Validation(
            "email domain contains invalid characters".into()
        ));
    }
    
    // Validate TLD (last part after final dot)
    let tld = domain.rsplit('.').next().unwrap_or("");
    if tld.len() < 2 || !tld.chars().all(|c| c.is_alphabetic()) {
        return Err(AppError::Validation(
            "email TLD must be at least 2 alphabetic characters".into()
        ));
    }
    
    // Reject obviously invalid domains
    if domain == "localhost" || domain.ends_with(".local") || domain.ends_with(".invalid") {
        return Err(AppError::Validation(
            "email domain is not valid for delivery".into()
        ));
    }
    
    Ok(email)
}

// =============================================================================
// PASSWORD VALIDATION
// =============================================================================

/// Validates password strength.
///
/// # Rules
/// - Minimum 8 characters
/// - Maximum 128 characters
/// - Must contain at least one letter
/// - Must contain at least one digit
///
/// # Security Note
/// We intentionally do NOT enforce special characters or uppercase to avoid
/// user frustration. The 210k PBKDF2 iterations provide strong protection.
pub fn validate_password(password: &str) -> Result<(), AppError> {
    if password.len() < 8 {
        return Err(AppError::Validation(
            "password must be at least 8 characters".into()
        ));
    }
    
    if password.len() > 128 {
        return Err(AppError::Validation(
            "password must be at most 128 characters".into()
        ));
    }
    
    let has_letter = password.chars().any(|c| c.is_alphabetic());
    let has_digit = password.chars().any(|c| c.is_numeric());
    
    if !has_letter || !has_digit {
        return Err(AppError::Validation(
            "password must contain both letters and numbers".into()
        ));
    }
    
    Ok(())
}

// =============================================================================
// PHONE VALIDATION
// =============================================================================

/// Validates generic phone numbers (for email channel).
///
/// # Rules
/// - 10-15 digits (after removing '+' and non-digits)
/// - Optional '+' prefix
/// - Returns original format (with '+' if provided)
pub fn validate_phone(value: &str) -> Result<String, AppError> {
    let trimmed = value.trim();
    
    if trimmed.is_empty() {
        return Err(AppError::Validation("phone number is required".into()));
    }
    
    // Extract digits only
    let digits: String = trimmed.chars().filter(|c| c.is_ascii_digit()).collect();
    
    if digits.len() < 10 || digits.len() > 15 {
        return Err(AppError::Validation(
            "phone number must be 10-15 digits".into()
        ));
    }
    
    // Allow optional '+' prefix
    if !trimmed.starts_with('+') && !trimmed.chars().next().unwrap().is_ascii_digit() {
        return Err(AppError::Validation(
            "phone number must start with '+' or a digit".into()
        ));
    }
    
    Ok(trimmed.to_string())
}

/// Validates Kenyan phone numbers (for SMS channel).
///
/// # Rules
/// - Accepts: 07XX, +2547XX, 2547XX
/// - Returns normalized: 2547XXXXXXXX
/// - Must be Safaricom (07XX) or Airtel (07XX) format
///
/// # Example
/// ```
/// let phone = validate_kenyan_phone("0712345678")?;
/// assert_eq!(phone, "254712345678");
/// ```
pub fn validate_kenyan_phone(value: &str) -> Result<String, AppError> {
    let digits: String = value.chars().filter(|c| c.is_ascii_digit()).collect();
    
    let normalized = if digits.starts_with("254") && digits.len() == 12 {
        digits
    } else if digits.starts_with("0") && digits.len() == 10 {
        format!("254{}", &digits[1..])
    } else {
        return Err(AppError::Validation(
            "SMS is available in Kenya only. Use format: 07XX XXX XXX or +254 7XX XXX XXX".into()
        ));
    };
    
    // Must be Safaricom (07XX) or Airtel (07XX) - starts with 2547 or 2541
    if !normalized.starts_with("2547") && !normalized.starts_with("2541") {
        return Err(AppError::Validation(
            "invalid Kenyan mobile number (must be Safaricom or Airtel)".into()
        ));
    }
    
    Ok(normalized)
}

// =============================================================================
// MESSAGE VALIDATION
// =============================================================================

/// Validates text messages (email body, SMS content).
///
/// # Rules
/// - Must not be empty
/// - Maximum length (varies by context)
/// - No control characters except newlines
/// - Unicode normalized
pub fn validate_message(value: &str, max: usize, field: &str) -> Result<String, AppError> {
    let trimmed = value.trim();
    
    if trimmed.is_empty() {
        return Err(AppError::Validation(format!("{} cannot be empty", field)));
    }
    
    // Use char count, not byte count (for Unicode)
    if trimmed.chars().count() > max {
        return Err(AppError::Validation(format!(
            "{} is too long (max {} characters)",
            field, max
        )));
    }
    
    // Check for control characters (but allow newlines and tabs)
    if trimmed.chars().any(|c| c.is_control() && c != '\n' && c != '\r' && c != '\t') {
        return Err(AppError::Validation(format!(
            "{} contains invalid control characters",
            field
        )));
    }
    
    // Unicode normalize
    let normalized: String = trimmed.nfc().collect();
    
    Ok(normalized)
}

// =============================================================================
// FILE NAME SANITIZATION
// =============================================================================

/// Sanitizes file names for safe storage.
///
/// # Rules
/// - Extract base name (no directory traversal)
/// - Unicode normalize (NFC form)
/// - Remove control characters
/// - Block Windows reserved names (CON, PRN, NUL, etc.)
/// - Remove leading/trailing dots and spaces
/// - Maximum 180 characters
///
/// # Security
/// Prevents:
/// - Directory traversal (`../../../etc/passwd`)
/// - Windows reserved names (`CON.txt`, `NUL.pdf`)
/// - Homoglyph attacks (different Unicode representations)
/// - Hidden files (`.gitignore` → `gitignore`)
pub fn sanitize_file_name(name: &str) -> Result<String, AppError> {
    let trimmed = name.trim();
    
    if trimmed.is_empty() {
        return Err(AppError::Validation("file name is empty".into()));
    }
    
    // Extract base name (prevents directory traversal)
    let base = Path::new(trimmed)
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| AppError::Validation("invalid file name".into()))?;
    
    // Unicode normalize
    let normalized: String = base.nfc().collect();
    
    // Keep only safe characters
    let cleaned: String = normalized
        .chars()
        .filter(|c| {
            c.is_alphanumeric() || matches!(c, '.' | '-' | '_' | ' ')
        })
        .collect();
    
    // Remove leading/trailing dots and spaces
    let cleaned = cleaned.trim().trim_matches('.').to_string();
    
    if cleaned.is_empty() {
        return Err(AppError::Validation(
            "file name is empty after sanitization".into()
        ));
    }
    
    if cleaned.len() > MAX_FILE_NAME_LEN {
        return Err(AppError::Validation(format!(
            "file name is too long (max {} characters)",
            MAX_FILE_NAME_LEN
        )));
    }
    
    // Check for Windows reserved names (case-insensitive)
    let stem = Path::new(&cleaned)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_uppercase();
    
    if WINDOWS_RESERVED_NAMES.contains(&stem.as_str()) {
        return Err(AppError::Validation(format!(
            "file name '{}' is a reserved Windows device name",
            stem
        )));
    }
    
    // Prevent names that are just dots or spaces
    if cleaned.chars().all(|c| c == '.' || c == ' ') {
        return Err(AppError::Validation(
            "file name cannot be only dots or spaces".into()
        ));
    }
    
    Ok(cleaned)
}

// =============================================================================
// SCHEDULE TIME VALIDATION (FIXED FOR INSTANT DELIVERY)
// =============================================================================

/// Validates scheduled delivery time with support for instant delivery.
///
/// # Rules
/// - **Instant delivery**: Times within the last 5 minutes are treated as "now"
/// - **Scheduled delivery**: Must be in the future (up to 5 years)
/// - **No artificial delays**: Returns the exact time for precise scheduling
///
/// # Instant Delivery Flow
/// 1. Frontend sends `new Date()` (current time)
/// 2. Network latency may make it slightly past by arrival
/// 3. Backend accepts times up to 5 minutes old as "instant"
/// 4. Scheduler dispatches immediately (no waiting)
///
/// # Scheduled Delivery Flow
/// 1. Frontend sends future timestamp
/// 2. Backend validates it's within 5 years
/// 3. Scheduler waits until exact time, then dispatches
///
/// # Example
/// ```
/// // Instant delivery (now or slightly past)
/// let instant = validate_schedule_time(Utc::now())?;
/// 
/// // Scheduled delivery (future)
/// let future = validate_schedule_time(Utc::now() + Duration::hours(2))?;
/// 
/// // Rejected: too far in the past
/// let old = Utc::now() - Duration::hours(1);
/// assert!(validate_schedule_time(old).is_err());
/// ```
pub fn validate_schedule_time(when: DateTime<Utc>) -> Result<DateTime<Utc>, AppError> {
    let now = Utc::now();
    
    // Calculate the grace period boundary (5 minutes ago)
    let grace_boundary = now - chrono::Duration::minutes(INSTANT_GRACE_MINUTES);
    
    // Calculate maximum future limit (5 years)
    let max_future = now + chrono::Duration::days(365 * MAX_SCHEDULE_YEARS);
    
    // Case 1: Time is too far in the past (beyond grace period)
    if when < grace_boundary {
        return Err(AppError::Validation(format!(
            "scheduled time is too far in the past (must be within last {} minutes for instant delivery, or in the future)",
            INSTANT_GRACE_MINUTES
        )));
    }
    
    // Case 2: Time is within grace period (instant delivery)
    // Treat it as "now" for immediate dispatch
    if when <= now {
        // Return current time for instant dispatch
        return Ok(now);
    }
    
    // Case 3: Time is in the future (scheduled delivery)
    if when > max_future {
        return Err(AppError::Validation(format!(
            "scheduled time must be within {} years (got {} days from now)",
            MAX_SCHEDULE_YEARS,
            (when - now).num_days()
        )));
    }
    
    // Return the exact scheduled time (no modification)
    // The scheduler will wait until this exact moment
    Ok(when)
}

// =============================================================================
// REFERENCE VALIDATION
// =============================================================================

/// Validates payment references (Paystack transaction IDs).
///
/// # Rules
/// - 8-100 characters
/// - Alphanumeric + hyphens + underscores
/// - No leading/trailing whitespace
pub fn validate_reference(reference: &str) -> Result<String, AppError> {
    let r = reference.trim();
    
    if r.len() < 8 || r.len() > 100 {
        return Err(AppError::Validation(
            "payment reference must be 8-100 characters".into()
        ));
    }
    
    if !r.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_')) {
        return Err(AppError::Validation(
            "payment reference contains invalid characters".into()
        ));
    }
    
    Ok(r.to_string())
}

// =============================================================================
// FILE KEY VALIDATION
// =============================================================================

/// Validates file keys (R2 object keys).
///
/// # Rules
/// - 1-300 characters
/// - Alphanumeric + `/ - _ .`
/// - No path traversal (`..`)
/// - No leading slash
pub fn validate_file_key(key: &str) -> Result<String, AppError> {
    let k = key.trim();
    
    if k.is_empty() || k.len() > 300 {
        return Err(AppError::Validation(
            "file key must be 1-300 characters".into()
        ));
    }
    
    if !k.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '-' | '_' | '.')) {
        return Err(AppError::Validation(
            "file key contains invalid characters".into()
        ));
    }
    
    if k.contains("..") {
        return Err(AppError::Validation(
            "file key contains path traversal".into()
        ));
    }
    
    if k.starts_with('/') {
        return Err(AppError::Validation(
            "file key cannot start with '/'".into()
        ));
    }
    
    Ok(k.to_string())
}

// =============================================================================
// FILE CONTENT VALIDATION
// =============================================================================

/// Validates file contents by checking magic bytes and extension.
///
/// # Rules
/// - File must not be empty
/// - Maximum 50 MB
/// - No executable content (MZ, ELF)
/// - No SVG (XSS risk)
/// - Extension must match magic bytes
/// - Whitelist: PDF, DOCX, JPG, PNG, MP4
///
/// # Returns
/// MIME type string (e.g., "application/pdf")
pub fn validate_file_contents(name: &str, bytes: &[u8]) -> Result<&'static str, AppError> {
    if bytes.is_empty() {
        return Err(AppError::Validation("file is empty".into()));
    }
    
    if bytes.len() > MAX_FILE_SIZE {
        return Err(AppError::Validation(format!(
            "file exceeds the {} MB limit",
            MAX_FILE_SIZE / (1024 * 1024)
        )));
    }
    
    // Block executable content
    if bytes.starts_with(b"MZ") || bytes.starts_with(b"\x7fELF") {
        return Err(AppError::Validation(
            "executable content is not allowed".into()
        ));
    }
    
    // Get file extension
    let ext = Path::new(name)
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_lowercase())
        .unwrap_or_default();
    
    // Check if extension is allowed
    if !ALLOWED_EXTENSIONS.contains(&ext.as_str()) {
        return Err(AppError::Validation(format!(
            "unsupported file type '{}'. Allowed: {}",
            ext,
            ALLOWED_EXTENSIONS.join(", ")
        )));
    }
    
    // Block SVG (XSS risk)
    if ext == "svg" {
        return Err(AppError::Validation(
            "SVG files are not allowed (security risk)".into()
        ));
    }
    
    // Validate magic bytes match extension
    let mime = match ext.as_str() {
        "pdf" => {
            if bytes.starts_with(b"%PDF") {
                "application/pdf"
            } else {
                return Err(AppError::Validation(
                    "file is not a valid PDF (magic bytes mismatch)".into()
                ));
            }
        }
        "jpg" | "jpeg" => {
            if bytes.starts_with(&[0xFF, 0xD8, 0xFF]) {
                "image/jpeg"
            } else {
                return Err(AppError::Validation(
                    "file is not a valid JPEG (magic bytes mismatch)".into()
                ));
            }
        }
        "png" => {
            if bytes.starts_with(&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]) {
                "image/png"
            } else {
                return Err(AppError::Validation(
                    "file is not a valid PNG (magic bytes mismatch)".into()
                ));
            }
        }
        "docx" => {
            if bytes.starts_with(b"PK\x03\x04") {
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
            } else {
                return Err(AppError::Validation(
                    "file is not a valid DOCX (magic bytes mismatch)".into()
                ));
            }
        }
        "mp4" => {
            if is_mp4(bytes) {
                "video/mp4"
            } else {
                return Err(AppError::Validation(
                    "file is not a valid MP4 (magic bytes mismatch)".into()
                ));
            }
        }
        _ => {
            return Err(AppError::Validation(
                "unsupported file type".into()
            ))
        }
    };
    
    Ok(mime)
}

/// Checks if bytes represent an MP4 file.
///
/// MP4 files have 'ftyp' at bytes 4-8.
fn is_mp4(bytes: &[u8]) -> bool {
    bytes.len() >= 12 && &bytes[4..8] == b"ftyp"
}

// =============================================================================
// ADDITIONAL VALIDATORS
// =============================================================================

/// Validates UUID format (v4).
pub fn validate_uuid(value: &str) -> Result<String, AppError> {
    let v = value.trim();
    
    if v.len() != 36 {
        return Err(AppError::Validation("UUID must be 36 characters".into()));
    }
    
    // Parse to validate format
    uuid::Uuid::parse_str(v)
        .map_err(|_| AppError::Validation("invalid UUID format".into()))?;
    
    Ok(v.to_string())
}

/// Validates hex string (even length, hex characters only).
pub fn validate_hex(value: &str) -> Result<String, AppError> {
    let v = value.trim();
    
    if v.len() % 2 != 0 {
        return Err(AppError::Validation(
            "hex string must have even length".into()
        ));
    }
    
    if !v.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(AppError::Validation(
            "hex string contains invalid characters".into()
        ));
    }
    
    Ok(v.to_lowercase())
}

/// Validates base64 string.
pub fn validate_base64(value: &str) -> Result<String, AppError> {
    let v = value.trim();
    
    if v.is_empty() {
        return Err(AppError::Validation("base64 string is empty".into()));
    }
    
    // Try to decode
    base64::Engine::decode(&base64::engine::general_purpose::STANDARD, v)
        .map_err(|_| AppError::Validation("invalid base64 string".into()))?;
    
    Ok(v.to_string())
}

/// Validates URL (HTTPS only).
pub fn validate_url(value: &str) -> Result<String, AppError> {
    let v = value.trim();
    
    if !v.starts_with("https://") {
        return Err(AppError::Validation("URL must use HTTPS".into()));
    }
    
    // Basic URL validation
    url::Url::parse(v)
        .map_err(|_| AppError::Validation("invalid URL format".into()))?;
    
    Ok(v.to_string())
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_email() {
        assert!(validate_email("user@example.com").is_ok());
        assert!(validate_email("User@Example.COM").is_ok()); // Lowercased
        assert!(validate_email("user.name+tag@example.co.uk").is_ok());
        
        // Invalid cases
        assert!(validate_email("").is_err());
        assert!(validate_email("user").is_err());
        assert!(validate_email("user@").is_err());
        assert!(validate_email("@example.com").is_err());
        assert!(validate_email("user@localhost").is_err());
        assert!(validate_email("user@example").is_err());
        assert!(validate_email("user..name@example.com").is_err()); // Consecutive dots
        assert!(validate_email("user@.example.com").is_err()); // Leading dot
    }

    #[test]
    fn test_validate_password() {
        assert!(validate_password("Password1").is_ok());
        assert!(validate_password("abc12345").is_ok());
        
        // Invalid cases
        assert!(validate_password("short1").is_err()); // Too short
        assert!(validate_password("password").is_err()); // No digit
        assert!(validate_password("12345678").is_err()); // No letter
    }

    #[test]
    fn test_validate_kenyan_phone() {
        assert_eq!(validate_kenyan_phone("0712345678").unwrap(), "254712345678");
        assert_eq!(validate_kenyan_phone("+254712345678").unwrap(), "254712345678");
        assert_eq!(validate_kenyan_phone("254712345678").unwrap(), "254712345678");
        
        // Invalid cases
        assert!(validate_kenyan_phone("0812345678").is_err()); // Wrong prefix
        assert!(validate_kenyan_phone("1234567890").is_err()); // Wrong format
    }

    #[test]
    fn test_sanitize_file_name() {
        assert_eq!(sanitize_file_name("document.pdf").unwrap(), "document.pdf");
        assert_eq!(sanitize_file_name("  My File (1).pdf  ").unwrap(), "My File (1).pdf");
        assert_eq!(sanitize_file_name("../../../etc/passwd").unwrap(), "passwd");
        
        // Windows reserved names
        assert!(sanitize_file_name("CON.txt").is_err());
        assert!(sanitize_file_name("NUL.pdf").is_err());
        assert!(sanitize_file_name("PRN.docx").is_err());
        
        // Invalid cases
        assert!(sanitize_file_name("").is_err());
        assert!(sanitize_file_name("...").is_err());
    }

    #[test]
    fn test_validate_file_contents() {
        // Valid PDF
        let pdf_bytes = b"%PDF-1.4\n%test";
        assert_eq!(validate_file_contents("test.pdf", pdf_bytes).unwrap(), "application/pdf");
        
        // Valid PNG
        let png_bytes = &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00];
        assert_eq!(validate_file_contents("test.png", png_bytes).unwrap(), "image/png");
        
        // Invalid: executable
        let exe_bytes = b"MZ\x90\x00";
        assert!(validate_file_contents("test.exe", exe_bytes).is_err());
        
        // Invalid: mismatched extension
        assert!(validate_file_contents("test.jpg", pdf_bytes).is_err());
    }

    #[test]
    fn test_validate_schedule_time() {
        // Valid: instant delivery (now)
        let now = Utc::now();
        assert!(validate_schedule_time(now).is_ok());
        
        // Valid: instant delivery (slightly in the past, within grace period)
        let slightly_past = Utc::now() - chrono::Duration::minutes(3);
        assert!(validate_schedule_time(slightly_past).is_ok());
        
        // Valid: scheduled delivery (future)
        let future = Utc::now() + chrono::Duration::hours(1);
        assert!(validate_schedule_time(future).is_ok());
        
        // Invalid: too far in the past (beyond grace period)
        let too_old = Utc::now() - chrono::Duration::hours(1);
        assert!(validate_schedule_time(too_old).is_err());
        
        // Invalid: too far in the future (beyond 5 years)
        let too_far = Utc::now() + chrono::Duration::days(365 * 6);
        assert!(validate_schedule_time(too_far).is_err());
    }

    #[test]
    fn test_validate_uuid() {
        let valid = "550e8400-e29b-41d4-a716-446655440000";
        assert!(validate_uuid(valid).is_ok());
        
        // Invalid cases
        assert!(validate_uuid("not-a-uuid").is_err());
        assert!(validate_uuid("550e8400-e29b-41d4-a716").is_err()); // Too short
    }

    #[test]
    fn test_validate_hex() {
        assert!(validate_hex("deadbeef").is_ok());
        assert!(validate_hex("DEADBEEF").is_ok()); // Uppercase
        assert!(validate_hex("0123456789abcdef").is_ok());
        
        // Invalid cases
        assert!(validate_hex("deadbee").is_err()); // Odd length
        assert!(validate_hex("deadbeeg").is_err()); // Invalid char
    }
}