//! Input validation and sanitization for every user-supplied value.

use chrono::{DateTime, Utc};
use std::path::Path;

use crate::errors::AppError;

pub const MAX_FILE_SIZE: usize = 100 * 1024 * 1024; // 100 MB
pub const MAX_NAME_LEN: usize = 100;
pub const MAX_EMAIL_LEN: usize = 254;
pub const MAX_FILE_NAME_LEN: usize = 180;
pub const MAX_MESSAGE_LEN: usize = 5000; // typed email messages
pub const MAX_SMS_LEN: usize = 160; // single SMS segment
pub const MAX_SCHEDULE_YEARS: i64 = 5;

pub fn validate_display_name(value: &str, field: &str) -> Result<String, AppError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(AppError::Validation(format!("{field} is required")));
    }
    if trimmed.len() > MAX_NAME_LEN {
        return Err(AppError::Validation(format!(
            "{field} is too long (max {MAX_NAME_LEN} characters)"
        )));
    }
    if trimmed.chars().any(char::is_control) {
        return Err(AppError::Validation(format!("{field} contains invalid characters")));
    }
    Ok(trimmed.to_string())
}

pub fn validate_email(value: &str) -> Result<String, AppError> {
    let email = value.trim().to_lowercase();
    if email.is_empty() {
        return Err(AppError::Validation("email is required".into()));
    }
    if email.len() > MAX_EMAIL_LEN {
        return Err(AppError::Validation("email is too long".into()));
    }
    let mut parts = email.split('@');
    let local = parts.next().unwrap_or("");
    let domain = parts.next().unwrap_or("");
    if parts.next().is_some() {
        return Err(AppError::Validation("email must contain exactly one '@'".into()));
    }
    if local.is_empty() || local.len() > 64 {
        return Err(AppError::Validation("email local part is invalid".into()));
    }
    if domain.len() < 3 || !domain.contains('.') {
        return Err(AppError::Validation("email domain is invalid".into()));
    }
    if domain.starts_with('.') || domain.ends_with('.') || domain.starts_with('-') || domain.ends_with('-') {
        return Err(AppError::Validation("email domain is invalid".into()));
    }
    let ok_local = local.chars().all(|c| c.is_alphanumeric() || matches!(c, '.' | '_' | '-' | '+'));
    let ok_domain = domain.chars().all(|c| c.is_alphanumeric() || matches!(c, '.' | '-'));
    if !ok_local || !ok_domain {
        return Err(AppError::Validation("email contains invalid characters".into()));
    }
    Ok(email)
}

pub fn validate_password(password: &str) -> Result<(), AppError> {
    if password.len() < 8 {
        return Err(AppError::Validation("password must be at least 8 characters".into()));
    }
    if password.len() > 128 {
        return Err(AppError::Validation("password must be at most 128 characters".into()));
    }
    let has_letter = password.chars().any(|c| c.is_alphabetic());
    let has_digit = password.chars().any(|c| c.is_numeric());
    if !has_letter || !has_digit {
        return Err(AppError::Validation("password must contain letters and numbers".into()));
    }
    Ok(())
}

/// Generic optional phone (email channel): light validation.
pub fn validate_phone(value: &str) -> Result<String, AppError> {
    let trimmed = value.trim();
    let digits: String = trimmed.trim_start_matches('+').chars().collect();
    if !(10..=14).contains(&digits.len()) || !digits.chars().all(|c| c.is_ascii_digit()) {
        return Err(AppError::Validation("phone number is invalid".into()));
    }
    Ok(trimmed.to_string())
}

/// Kenyan-only SMS: accepts 07XX…, +2547XX…, 2547XX… → returns 2547XXXXXXXX.
pub fn validate_kenyan_phone(value: &str) -> Result<String, AppError> {
    let digits: String = value.chars().filter(|c| c.is_ascii_digit()).collect();
    let normalized = if digits.starts_with("254") && digits.len() == 12 {
        digits
    } else if digits.starts_with("0") && digits.len() == 10 {
        format!("254{}", &digits[1..])
    } else {
        return Err(AppError::Validation(
            "SMS is available in Kenya only. Use a Safaricom/Airtel format: 07XX XXX XXX".into(),
        ));
    };
    if !normalized.starts_with("2547") && !normalized.starts_with("2541") {
        return Err(AppError::Validation("invalid Kenyan mobile number".into()));
    }
    Ok(normalized)
}

pub fn validate_message(value: &str, max: usize, field: &str) -> Result<String, AppError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(AppError::Validation(format!("{field} cannot be empty")));
    }
    if trimmed.chars().count() > max {
        return Err(AppError::Validation(format!("{field} is too long (max {max} characters)")));
    }
    if trimmed.chars().any(char::is_control) && !trimmed.contains('\n') {
        return Err(AppError::Validation(format!("{field} contains invalid characters")));
    }
    Ok(trimmed.to_string())
}

pub fn sanitize_file_name(name: &str) -> Result<String, AppError> {
    let base = Path::new(name.trim())
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| AppError::Validation("invalid file name".into()))?;
    let cleaned: String = base
        .chars()
        .filter(|c| c.is_alphanumeric() || matches!(c, '.' | '-' | '_' | ' '))
        .collect();
    let cleaned = cleaned.trim().trim_matches('.').to_string();
    if cleaned.is_empty() {
        return Err(AppError::Validation("file name is empty after sanitization".into()));
    }
    if cleaned.len() > MAX_FILE_NAME_LEN {
        return Err(AppError::Validation("file name is too long".into()));
    }
    Ok(cleaned)
}

pub fn validate_schedule_time(when: DateTime<Utc>) -> Result<DateTime<Utc>, AppError> {
    let now = Utc::now();
    if when <= now {
        return Err(AppError::Validation("scheduled time must be in the future".into()));
    }
    let limit = now + chrono::Duration::days(365 * MAX_SCHEDULE_YEARS);
    if when > limit {
        return Err(AppError::Validation(format!(
            "scheduled time must be within {MAX_SCHEDULE_YEARS} years"
        )));
    }
    Ok(when)
}

pub fn validate_reference(reference: &str) -> Result<String, AppError> {
    let r = reference.trim();
    if !(8..=100).contains(&r.len()) || !r.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_')) {
        return Err(AppError::Validation("payment reference is invalid".into()));
    }
    Ok(r.to_string())
}

pub fn validate_file_key(key: &str) -> Result<String, AppError> {
    let k = key.trim();
    if k.is_empty() || k.len() > 300 {
        return Err(AppError::Validation("file key is invalid".into()));
    }
    if !k.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '-' | '_' | '.')) {
        return Err(AppError::Validation("file key contains invalid characters".into()));
    }
    if k.contains("..") {
        return Err(AppError::Validation("file key contains path traversal".into()));
    }
    Ok(k.to_string())
}

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
    if bytes.starts_with(b"MZ") || bytes.starts_with(b"\x7fELF") {
        return Err(AppError::Validation("executable content is not allowed".into()));
    }
    let ext = Path::new(name)
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_lowercase())
        .unwrap_or_default();
    let mime = match ext.as_str() {
        "pdf" if bytes.starts_with(b"%PDF") => "application/pdf",
        "jpg" | "jpeg" if bytes.starts_with(&[0xFF, 0xD8, 0xFF]) => "image/jpeg",
        "png" if bytes.starts_with(&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]) => "image/png",
        "docx" if bytes.starts_with(b"PK\x03\x04") => {
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        }
        "mp4" if is_mp4(bytes) => "video/mp4",
        _ => {
            return Err(AppError::Validation(
                "unsupported or mismatched file type (allowed: PDF, DOCX, JPG, PNG, MP4)".into(),
            ))
        }
    };
    Ok(mime)
}

fn is_mp4(bytes: &[u8]) -> bool {
    bytes.len() >= 12 && &bytes[4..8] == b"ftyp"
}