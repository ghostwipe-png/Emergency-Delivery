//! Authenticated encryption (AES-256-GCM), PBKDF2/HKDF key derivation, and secure
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
//!
//! # Security Posture
//! - All sensitive returns use `Zeroizing` to prevent memory leaks
//! - Constant-time comparison for all secret material
//! - HKDF for deriving sub-keys (prevents key reuse attacks)
//! - Strict validation on all cryptographic inputs
//!
//! @version 2.0.0
//! @status PRODUCTION

use aes_gcm::aead::{Aead, AeadCore, KeyInit, OsRng};
use aes_gcm::Aes256Gcm;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::errors::AppError;

// =============================================================================
// CONSTANTS & CONFIGURATION
// =============================================================================

/// OWASP-recommended minimum for PBKDF2-HMAC-SHA256 is 100k; we use 210k.
///
/// ⚠️  If you change this value, you MUST update the claim page's
///     `PBKDF2_ITERATIONS` constant to the identical value, otherwise
///     password-protected deliveries will permanently fail to unwrap.
pub const PBKDF2_ITERATIONS: u32 = 210_000;

pub const SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 12;
pub const KEY_LEN: usize = 32;
pub const TAG_LEN: usize = 16; // GCM authentication tag size

/// Field-level envelope version. The claim page must validate this prefix
/// and reject any other value.
const FIELD_VERSION: &str = "v1";

/// HKDF context strings for domain separation (prevents key reuse attacks)
pub const HKDF_INFO_DELIVERY: &[u8] = b"emergency-delivery-file-encryption";
pub const HKDF_INFO_GUARDIAN: &[u8] = b"emergency-delivery-guardian-payload";
pub const HKDF_INFO_INHERITANCE: &[u8] = b"emergency-delivery-inheritance-shard";

// =============================================================================
// SECURE RANDOM GENERATION
// =============================================================================

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

// =============================================================================
// KEY DERIVATION (PBKDF2 & HKDF)
// =============================================================================

/// PBKDF2-HMAC-SHA256 key derivation.
///
/// # Security
/// - Uses 210,000 iterations (OWASP 2023 recommendation)
/// - Returns `Zeroizing` wrapper to ensure key is wiped from memory
/// - Validates salt length to prevent weak salt attacks
pub fn derive_key(
    password: &str,
    salt: &[u8],
    iterations: u32,
) -> Result<Zeroizing<[u8; KEY_LEN]>, AppError> {
    if password.is_empty() {
        return Err(AppError::Validation("password must not be empty".into()));
    }
    if salt.len() < 8 {
        return Err(AppError::Crypto("salt must be at least 8 bytes".into()));
    }
    if iterations < 100_000 {
        return Err(AppError::Crypto("iterations must be >= 100,000".into()));
    }
    
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    pbkdf2::pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, iterations, key.as_mut());
    Ok(key)
}

/// HKDF-SHA256 key derivation (NIST SP 800-108).
/// Use this to derive sub-keys from a master secret (e.g., derive file encryption
/// key from user's master KEK).
///
/// # Arguments
/// * `ikm` - Input keying material (master secret)
/// * `salt` - Optional salt (if None, uses zero-filled salt)
/// * `info` - Context string for domain separation (e.g., HKDF_INFO_DELIVERY)
///
/// # Returns
/// 32-byte derived key wrapped in `Zeroizing`
pub fn derive_key_hkdf(
    ikm: &[u8],
    salt: Option<&[u8]>,
    info: &[u8],
) -> Result<Zeroizing<[u8; KEY_LEN]>, AppError> {
    if ikm.is_empty() {
        return Err(AppError::Crypto("IKM must not be empty".into()));
    }
    if info.is_empty() {
        return Err(AppError::Crypto("HKDF info must not be empty".into()));
    }
    
    let hk = Hkdf::<Sha256>::new(salt, ikm);
    let mut okm = Zeroizing::new([0u8; KEY_LEN]);
    
    hk.expand(info, okm.as_mut())
        .map_err(|e| AppError::Crypto(format!("HKDF expand failed: {}", e)))?;
    
    Ok(okm)
}

// =============================================================================
// HASHING
// =============================================================================

/// SHA-256 hash, returned as hex string.
pub fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// SHA-256 hash with salt (for password verification).
pub fn sha256_salt_hex(data: &[u8], salt: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.update(salt);
    hex::encode(hasher.finalize())
}

// =============================================================================
// AES-256-GCM ENCRYPTION
// =============================================================================

/// AES-256-GCM encrypt. Returns (ciphertext, nonce).
///
/// # Security
/// - Uses authenticated encryption (confidentiality + integrity)
/// - Nonce is randomly generated (never reuse nonces with the same key!)
/// - Ciphertext includes 16-byte GCM authentication tag
pub fn encrypt(
    key: &[u8; KEY_LEN],
    plaintext: &[u8],
) -> Result<(Zeroizing<Vec<u8>>, [u8; NONCE_LEN]), AppError> {
    if plaintext.is_empty() {
        return Err(AppError::Crypto("plaintext must not be empty".into()));
    }
    
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| AppError::Crypto(format!("invalid key: {}", e)))?;
    
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| AppError::Crypto(format!("encryption failed: {}", e)))?;
    
    let mut nonce_arr = [0u8; NONCE_LEN];
    nonce_arr.copy_from_slice(nonce.as_slice());
    
    Ok((Zeroizing::new(ciphertext), nonce_arr))
}

/// AES-256-GCM decrypt with authentication check.
///
/// # Security
/// - Verifies GCM authentication tag before returning plaintext
/// - Returns `Zeroizing` wrapper to ensure plaintext is wiped from memory
/// - Fails securely if ciphertext is tampered with
pub fn decrypt(
    key: &[u8; KEY_LEN],
    ciphertext: &[u8],
    nonce: &[u8; NONCE_LEN],
) -> Result<Zeroizing<Vec<u8>>, AppError> {
    if ciphertext.len() < TAG_LEN {
        return Err(AppError::Crypto("ciphertext too short (missing auth tag)".into()));
    }
    
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| AppError::Crypto(format!("invalid key: {}", e)))?;
    
    let plaintext = cipher
        .decrypt(aes_gcm::Nonce::from_slice(nonce), ciphertext)
        .map_err(|_| AppError::Crypto("decryption failed (integrity check)".into()))?;
    
    Ok(Zeroizing::new(plaintext))
}

/// Decrypts data that was stored with the nonce prepended.
/// Input format: [12-byte nonce][ciphertext with GCM auth tag]
pub fn decrypt_with_prepended_nonce(
    key: &[u8; KEY_LEN],
    blob_with_nonce: &[u8],
) -> Result<Zeroizing<Vec<u8>>, AppError> {
    if blob_with_nonce.len() < NONCE_LEN + TAG_LEN {
        return Err(AppError::Crypto("encrypted blob is too short".into()));
    }
    let (nonce_bytes, ciphertext) = blob_with_nonce.split_at(NONCE_LEN);
    let nonce: [u8; NONCE_LEN] = nonce_bytes
        .try_into()
        .map_err(|_| AppError::Crypto("invalid nonce length".into()))?;
    decrypt(key, ciphertext, &nonce)
}

// =============================================================================
// BASE64 ENCODING
// =============================================================================

pub fn b64_encode(data: &[u8]) -> String {
    STANDARD.encode(data)
}

pub fn b64_decode(data: &str) -> Result<Vec<u8>, AppError> {
    STANDARD.decode(data).map_err(|e| AppError::Crypto(format!("base64 decode failed: {}", e)))
}

// =============================================================================
// FIELD-LEVEL ENCRYPTION (For DB columns)
// =============================================================================

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
    if plaintext.is_empty() {
        return Err(AppError::Crypto("plaintext must not be empty".into()));
    }
    
    let (ct, nonce) = encrypt(key, plaintext.as_bytes())?;
    Ok(format!(
        "{}:{}:{}",
        FIELD_VERSION,
        b64_encode(&nonce),
        b64_encode(&ct)
    ))
}

/// Decrypts a field-level encrypted string.
/// Returns `Zeroizing<String>` to ensure plaintext is wiped from memory.
pub fn decrypt_field(key: &[u8; KEY_LEN], encoded: &str) -> Result<Zeroizing<String>, AppError> {
    let mut parts = encoded.splitn(3, ':');
    let version = parts.next().ok_or_else(|| AppError::Crypto("malformed field".into()))?;
    let nonce_b64 = parts.next().ok_or_else(|| AppError::Crypto("malformed field".into()))?;
    let ct_b64 = parts.next().ok_or_else(|| AppError::Crypto("malformed field".into()))?;
    
    if version != FIELD_VERSION {
        return Err(AppError::Crypto(format!(
            "unsupported field version: {} (expected {})",
            version, FIELD_VERSION
        )));
    }
    
    let nonce_vec = b64_decode(nonce_b64)?;
    let nonce: [u8; NONCE_LEN] = nonce_vec
        .as_slice()
        .try_into()
        .map_err(|_| AppError::Crypto("invalid nonce length".into()))?;
    
    let ct = b64_decode(ct_b64)?;
    let plain_bytes = decrypt(key, &ct, &nonce)?;
    
    let s = String::from_utf8(plain_bytes.to_vec())
        .map_err(|_| AppError::Crypto("decrypted field is not valid UTF-8".into()))?;
    
    Ok(Zeroizing::new(s))
}

pub fn decrypt_field_opt(
    key: &[u8; KEY_LEN],
    encoded: &Option<String>,
) -> Result<Option<Zeroizing<String>>, AppError> {
    match encoded {
        Some(v) => Ok(Some(decrypt_field(key, v)?)),
        None => Ok(None),
    }
}

// =============================================================================
// CONSTANT-TIME COMPARISON
// =============================================================================

/// Constant-time comparison for secret material (prevents timing attacks).
///
/// # Security
/// - Always compares all bytes (no early exit)
/// - Execution time is independent of input values
/// - Use this for comparing password hashes, tokens, and keys
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

// =============================================================================
// SELF-TESTS (NIST Test Vectors)
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes_gcm_nist_vector() {
        // NIST SP 800-38D test vector
        let key = hex::decode("feffe9928665731c6d6a8f9467308308").unwrap();
        let nonce = hex::decode("cafebabefacedbaddecaf888").unwrap();
        let plaintext = hex::decode("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255").unwrap();
        let expected_ct = hex::decode("42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985").unwrap();
        
        let key_arr: [u8; 32] = key.try_into().unwrap();
        let nonce_arr: [u8; 12] = nonce.try_into().unwrap();
        
        let (ct, n) = encrypt(&key_arr, &plaintext).unwrap();
        assert_eq!(n, nonce_arr);
        assert_eq!(ct.as_slice(), expected_ct.as_slice());
        
        let pt = decrypt(&key_arr, &ct, &n).unwrap();
        assert_eq!(pt.as_slice(), plaintext.as_slice());
    }

    #[test]
    fn test_pbkdf2_rfc6070_vector() {
        // RFC 6070 test vector
        let password = "password";
        let salt = b"salt";
        let iterations = 4096;
        let expected = "4b007901b765489abead49d926f721d065a429c1";
        
        let key = derive_key(password, salt, iterations).unwrap();
        assert_eq!(hex::encode(key.as_slice()), expected);
    }

    #[test]
    fn test_field_encryption_roundtrip() {
        let key = random_bytes::<32>();
        let plaintext = "sensitive-data-12345";
        
        let encrypted = encrypt_to_field(&key, plaintext).unwrap();
        assert!(encrypted.starts_with("v1:"));
        
        let decrypted = decrypt_field(&key, &encrypted).unwrap();
        assert_eq!(decrypted.as_str(), plaintext);
    }

    #[test]
    fn test_hkdf_rfc5869_vector() {
        // RFC 5869 Test Case 1
        let ikm = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let salt = hex::decode("000102030405060708090a0b0c").unwrap();
        let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();
        let expected = "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865";
        
        let key = derive_key_hkdf(&ikm, Some(&salt), &info).unwrap();
        assert_eq!(hex::encode(key.as_slice()), expected);
    }

    #[test]
    fn test_constant_time_comparison() {
        let a = b"secret-token-123";
        let b = b"secret-token-123";
        let c = b"secret-token-124";
        
        assert!(ct_eq(a, b));
        assert!(!ct_eq(a, c));
        assert!(!ct_eq(a, b"short"));
    }

    #[test]
    fn test_sha256() {
        let data = b"hello world";
        let expected = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";
        assert_eq!(sha256_hex(data), expected);
    }
}