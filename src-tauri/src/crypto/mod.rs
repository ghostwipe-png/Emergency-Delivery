//! Authenticated encryption (AES-256-GCM), PBKDF2 key derivation and secure
//! random generation. All long-lived keys are wrapped in `Zeroizing` so key
//! material is wiped from memory on drop.
//!
//! # Cross-Platform Contract (Rust ↔ Web Worker Claim Page)
//!
//! When a user sends a **password-protected delivery**, the file DEK is wrapped
//! with a user-supplied password and stored in the DB column `claim_pw_wrapped_dek`.
//! The worker-side claim page MUST decrypt it with the **exact same parameters**:
//!
//! ```text
//! claim_pw_wrapped_dek format (FIELD_VERSION = "v1"):
//!   "v1:<base64(nonce)>:<base64(ciphertext_with_auth_tag)>"
//!
//! claim_password_salt format:
//!   Hex-encoded raw bytes (e.g. "a1b2c3..."), NOT the string itself.
//!
//! Key derivation (PBKDF2-HMAC-SHA256):
//!   iterations = PBKDF2_ITERATIONS (= 210_000)
//!   salt       = hex_decode(claim_password_salt)  <- RAW bytes, 16 long
//!   dkLen      = 32 bytes
//!   hash       = SHA-256
//!
//! Payload inside the wrapped field:
//!   hex-encoded 32-byte DEK (64 hex chars). After decrypting the outer AES-GCM
//!   ciphertext, hex-decode the plaintext to recover the raw DEK bytes used to
//!   decrypt the actual file.
//! ```
//!
//! Changing any of the above (iteration count, salt encoding, envelope format,
//! or inner encoding) will silently break password-protected deliveries.

use aes_gcm::aead::{Aead, AeadCore, KeyInit, OsRng};
use aes_gcm::Aes256Gcm;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use rand::RngCore;
use zeroize::Zeroizing;

use crate::errors::AppError;

/// OWASP-recommended minimum for PBKDF2-HMAC-SHA256 is 100k; we use 210k.
///
/// ⚠️  If you change this value, you MUST update the claim page's
///     `PBKDF2_ITERATIONS` constant to the identical value, otherwise
///     password-protected deliveries will permanently fail to unwrap.
pub const PBKDF2_ITERATIONS: u32 = 210_000;

pub const SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 12;
pub const KEY_LEN: usize = 32;

/// Field-level envelope version. The claim page must validate this prefix
/// and reject any other value.
const FIELD_VERSION: &str = "v1";

/// Cryptographically secure random bytes (OS CSPRNG).
pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    OsRng.fill_bytes(&mut buf);
    buf
}

pub fn random_salt() -> [u8; SALT_LEN] {
    random_bytes::<SALT_LEN>()
}

/// 256-bit random token for sessions and delivery claims.
pub fn secure_token() -> String {
    hex::encode(random_bytes::<32>())
}

/// PBKDF2-HMAC-SHA256 key derivation.
pub fn derive_key(
    password: &str,
    salt: &[u8],
    iterations: u32,
) -> Result<Zeroizing<[u8; KEY_LEN]>, AppError> {
    if password.is_empty() {
        return Err(AppError::Validation("password must not be empty".into()));
    }
    if salt.is_empty() {
        return Err(AppError::Crypto("salt must not be empty".into()));
    }
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    pbkdf2::pbkdf2_hmac::<sha2::Sha256>(password.as_bytes(), salt, iterations, key.as_mut());
    Ok(key)
}

/// AES-256-GCM encrypt. Returns (ciphertext, nonce).
pub fn encrypt(key: &[u8; KEY_LEN], plaintext: &[u8]) -> Result<(Vec<u8>, [u8; NONCE_LEN]), AppError> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| AppError::Crypto(format!("invalid key: {e}")))?;
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| AppError::Crypto(format!("encryption failed: {e}")))?;
    let mut nonce_arr = [0u8; NONCE_LEN];
    nonce_arr.copy_from_slice(nonce.as_slice());
    Ok((ciphertext, nonce_arr))
}

/// AES-256-GCM decrypt with authentication check.
pub fn decrypt(key: &[u8; KEY_LEN], ciphertext: &[u8], nonce: &[u8; NONCE_LEN]) -> Result<Vec<u8>, AppError> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| AppError::Crypto(format!("invalid key: {e}")))?;
    cipher
        .decrypt(aes_gcm::Nonce::from_slice(nonce), ciphertext)
        .map_err(|_| AppError::Crypto("decryption failed (integrity check)".into()))
}

/// Decrypts data that was stored with the nonce prepended.
/// Input format: [12-byte nonce][ciphertext with GCM auth tag]
pub fn decrypt_with_prepended_nonce(
    key: &[u8; KEY_LEN],
    blob_with_nonce: &[u8],
) -> Result<Vec<u8>, AppError> {
    if blob_with_nonce.len() < NONCE_LEN {
        return Err(AppError::Crypto("encrypted blob is too short".into()));
    }
    let (nonce_bytes, ciphertext) = blob_with_nonce.split_at(NONCE_LEN);
    let nonce: [u8; NONCE_LEN] = nonce_bytes
        .try_into()
        .map_err(|_| AppError::Crypto("invalid nonce length".into()))?;
    decrypt(key, ciphertext, &nonce)
}

pub fn b64_encode(data: &[u8]) -> String {
    STANDARD.encode(data)
}

pub fn b64_decode(data: &str) -> Result<Vec<u8>, AppError> {
    STANDARD.decode(data).map_err(AppError::from)
}

/// Serializes ciphertext + nonce into one versioned string: `v1:<nonce>:<ct>`.
///
/// Used for field-level encryption of sensitive DB columns — including the
/// password-wrapped DEK stored in `claim_pw_wrapped_dek`.
///
/// # Format contract (do not change without updating the claim page)
///
/// ```text
/// "<FIELD_VERSION>:<base64(nonce[12])>:<base64(ciphertext_with_auth_tag)>"
/// ```
///
/// The plaintext fed into this function is UTF-8 text. For password-wrapped
/// DEKs, the plaintext is the **hex-encoded 32-byte DEK** (64 hex chars).
pub fn encrypt_to_field(key: &[u8; KEY_LEN], plaintext: &str) -> Result<String, AppError> {
    let (ct, nonce) = encrypt(key, plaintext.as_bytes())?;
    Ok(format!("{FIELD_VERSION}:{}:{}", b64_encode(&nonce), b64_encode(&ct)))
}

pub fn decrypt_field(key: &[u8; KEY_LEN], encoded: &str) -> Result<String, AppError> {
    let mut parts = encoded.splitn(3, ':');
    let version = parts.next().ok_or_else(|| AppError::Crypto("malformed field".into()))?;
    let nonce_b64 = parts.next().ok_or_else(|| AppError::Crypto("malformed field".into()))?;
    let ct_b64 = parts.next().ok_or_else(|| AppError::Crypto("malformed field".into()))?;
    if version != FIELD_VERSION {
        return Err(AppError::Crypto("unsupported field version".into()));
    }
    let nonce_vec = b64_decode(nonce_b64)?;
    let nonce: [u8; NONCE_LEN] = nonce_vec
        .as_slice()
        .try_into()
        .map_err(|_| AppError::Crypto("invalid nonce length".into()))?;
    let ct = b64_decode(ct_b64)?;
    let plain = decrypt(key, &ct, &nonce)?;
    String::from_utf8(plain).map_err(|_| AppError::Crypto("decrypted field is not valid UTF-8".into()))
}

pub fn decrypt_field_opt(key: &[u8; KEY_LEN], encoded: &Option<String>) -> Result<Option<String>, AppError> {
    match encoded {
        Some(v) => Ok(Some(decrypt_field(key, v)?)),
        None => Ok(None),
    }
}

/// Constant-time comparison for secret material (prevents timing attacks).
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}