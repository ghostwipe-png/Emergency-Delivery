use sha2::{Digest, Sha256};
use tracing::{debug, error, info, warn};
use zeroize::Zeroizing;

use crate::crypto;
use crate::errors::AppError;

pub const MIN_WORD_LEN: usize = 6;
pub const MAX_WORD_LEN: usize = 15;

pub const MAX_FAILED_ATTEMPTS: i64 = 5;
pub const LOCK_MINUTES: i64 = 15;

const KEYRING_SERVICE: &str = "EmergencyDelivery";
const KEYRING_DEVICE_ACCOUNT: &str = "device_secret_v1";

pub fn validate_favorite_word(word: &str) -> Result<(), AppError> {
    let len = word.chars().count();
    
    if len < MIN_WORD_LEN || len > MAX_WORD_LEN {
        return Err(AppError::Validation(
            format!("Favorite word must be {}-{} characters", MIN_WORD_LEN, MAX_WORD_LEN).into(),
        ));
    }
    
    for c in word.chars() {
        if c.is_whitespace() {
            return Err(AppError::Validation("Favorite word must not contain spaces".into()));
        }
        if c.is_control() {
            return Err(AppError::Validation("Favorite word must not contain control characters".into()));
        }
    }
    
    Ok(())
}

/// Gets or creates the device secret with keychain + file fallback
pub fn get_or_create_device_secret(data_dir: &std::path::Path) -> Result<Zeroizing<Vec<u8>>, AppError> {
    // Try keychain first
    if let Ok(entry) = keyring::Entry::new(KEYRING_SERVICE, KEYRING_DEVICE_ACCOUNT) {
        match entry.get_password() {
            Ok(hex_str) => {
                if let Ok(bytes) = hex::decode(&hex_str) {
                    if bytes.len() == 32 {
                        debug!("Loaded existing device secret from OS keychain");
                        return Ok(Zeroizing::new(bytes));
                    }
                }
                warn!("Device secret in keychain invalid, regenerating");
            }
            Err(keyring::Error::NoEntry) => {
                info!("No device secret in keychain, generating new one");
            }
            Err(e) => {
                warn!(error = %e, "Keychain read failed, trying file fallback");
            }
        }
    }

    // Try file fallback
    let fallback_path = data_dir.join("secure").join(".device_secret");
    if fallback_path.exists() {
        if let Ok(hex_str) = std::fs::read_to_string(&fallback_path) {
            if let Ok(bytes) = hex::decode(hex_str.trim()) {
                if bytes.len() == 32 {
                    info!("Loaded device secret from file fallback");
                    return Ok(Zeroizing::new(bytes));
                }
            }
        }
        warn!("Fallback file invalid, regenerating");
    }

    // Generate new secret
    let secret_array = crypto::random_bytes::<32>();
    let secret_vec = secret_array.to_vec();
    let hex_encoded = hex::encode(&secret_vec);

    // Try to save to keychain
    let keychain_saved = if let Ok(entry) = keyring::Entry::new(KEYRING_SERVICE, KEYRING_DEVICE_ACCOUNT) {
        entry.set_password(&hex_encoded).is_ok()
    } else {
        false
    };

    // Always save to file as backup
    if let Some(parent) = fallback_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Err(e) = std::fs::write(&fallback_path, &hex_encoded) {
        error!(error = %e, "Failed to write device secret to fallback file");
    } else {
        info!("Device secret saved to fallback file");
    }

    if keychain_saved {
        info!("Device secret saved to OS keychain");
    } else {
        warn!("Device secret NOT saved to keychain (using file fallback only)");
    }

    Ok(Zeroizing::new(secret_vec))
}

pub fn device_id_from_secret(device_secret: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(device_secret);
    hex::encode(h.finalize())
}

pub fn derive_quick_key(
    word: &str,
    quick_salt: &[u8],
    device_secret: &[u8],
) -> Result<Zeroizing<[u8; crypto::KEY_LEN]>, AppError> {
    let mut salt = Zeroizing::new(vec![0u8; quick_salt.len() + device_secret.len()]);
    salt[..quick_salt.len()].copy_from_slice(quick_salt);
    salt[quick_salt.len()..].copy_from_slice(device_secret);
    
    crypto::derive_key(word, &salt, crypto::PBKDF2_ITERATIONS)
}

pub fn wrap_kek(
    quick_key: &[u8; crypto::KEY_LEN], 
    kek: &[u8; crypto::KEY_LEN]
) -> Result<String, AppError> {
    let kek_hex = hex::encode(kek);
    crypto::encrypt_to_field(quick_key, &kek_hex)
}

pub fn unwrap_kek(
    quick_key: &[u8; crypto::KEY_LEN], 
    encrypted_kek: &str
) -> Result<Zeroizing<[u8; crypto::KEY_LEN]>, AppError> {
    let hex_str = crypto::decrypt_field(quick_key, encrypted_kek)?;
    let bytes = hex::decode(&hex_str)
        .map_err(|_| AppError::Crypto("Invalid KEK hex encoding".into()))?;
        
    if bytes.len() != crypto::KEY_LEN {
        return Err(AppError::Crypto(
            format!("Invalid KEK length: {}", bytes.len()).into()
        ));
    }
    
    let mut kek = Zeroizing::new([0u8; crypto::KEY_LEN]);
    kek.copy_from_slice(&bytes);
    Ok(kek)
}