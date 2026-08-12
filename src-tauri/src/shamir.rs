//! Shamir Secret Sharing over GF(2^8) — standalone cryptographic core.
//!
//! DESIGN CONSTANTS (must match the TypeScript reconstruction page exactly):
//!   - Field:        GF(256), irreducible polynomial 0x11B (AES polynomial)
//!   - x-coordinate: 1-based (shard x is in 1..=254, never 0)
//!   - Shard format: [1 byte: x] || [L bytes: y-values], hex-encoded for storage
//!   - Subtraction == XOR (characteristic-2 field)
//!
//! SECURITY PROPERTIES:
//!   - Any M of N shards reconstruct the secret.
//!   - Fewer than M shards reveal ZERO information (information-theoretic).
//!   - Interop guarantee: this math is mirrored byte-for-byte in the worker's
//!     TS reconstruction page, so shards created in Rust combine in the browser.

use rand::RngCore;
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShamirError {
    InvalidThreshold,
    EmptySecret,
    NotEnoughShards,
    DuplicateShard,
    ShardLengthMismatch,
}

impl fmt::Display for ShamirError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ShamirError::InvalidThreshold => write!(f, "invalid threshold: require 2 <= m <= n <= 254"),
            ShamirError::EmptySecret => write!(f, "secret must not be empty"),
            ShamirError::NotEnoughShards => write!(f, "not enough shards to reconstruct"),
            ShamirError::DuplicateShard => write!(f, "duplicate shard detected"),
            ShamirError::ShardLengthMismatch => write!(f, "shard length mismatch"),
        }
    }
}

// -----------------------------------------------------------------------------
// GF(2^8) field arithmetic
// -----------------------------------------------------------------------------

/// Multiply in GF(256) with reduction by 0x11B.
fn gf_mul(a: u8, b: u8) -> u8 {
    let mut p: u16 = 0;
    let mut a = a as u16;
    let mut b = b as u16;
    for _ in 0..8 {
        if b & 1 != 0 {
            p ^= a;
        }
        b >>= 1;
        let hi = a & 0x80;
        a <<= 1;
        if hi != 0 {
            a ^= 0x11B;
        }
    }
    p as u8
}

/// Multiplicative inverse in GF(256): a^254 (valid for a != 0).
fn gf_inv(a: u8) -> u8 {
    let mut result: u8 = 1;
    let mut base = a;
    let mut e: u32 = 254;
    while e > 0 {
        if e & 1 == 1 {
            result = gf_mul(result, base);
        }
        base = gf_mul(base, base);
        e >>= 1;
    }
    result
}

/// Divide in GF(256): a / b == a * b^-1.
fn gf_div(a: u8, b: u8) -> u8 {
    gf_mul(a, gf_inv(b))
}

/// Cryptographically secure random byte.
fn random_byte() -> u8 {
    let mut b = [0u8; 1];
    rand::rngs::OsRng.fill_bytes(&mut b);
    b[0]
}

/// Evaluate polynomial via Horner's method: f(x) = c0 + x*(c1 + x*(...)).
fn eval_poly(coeffs: &[u8], x: u8) -> u8 {
    let mut acc: u8 = 0;
    for &c in coeffs.iter().rev() {
        acc = gf_mul(acc, x) ^ c;
    }
    acc
}

// -----------------------------------------------------------------------------
// Public API
// -----------------------------------------------------------------------------

/// Split a secret into N shards, threshold M.
/// Returns N shards; each is [x] || [y-values].
pub fn split(secret: &[u8], n: usize, m: usize) -> Result<Vec<Vec<u8>>, ShamirError> {
    if m < 2 || m > n || n > 254 {
        return Err(ShamirError::InvalidThreshold);
    }
    if secret.is_empty() {
        return Err(ShamirError::EmptySecret);
    }

    let mut shards: Vec<Vec<u8>> = vec![Vec::with_capacity(secret.len() + 1); n];
    for (i, shard) in shards.iter_mut().enumerate() {
        shard.push((i + 1) as u8); // 1-based x-coordinate
    }

    for &byte in secret {
        let mut coeffs = vec![0u8; m];
        coeffs[0] = byte; // f(0) = secret byte
        for k in 1..m {
            coeffs[k] = random_byte(); // random coefficients a1..a_{m-1}
        }
        for i in 0..n {
            let x = (i + 1) as u8;
            shards[i].push(eval_poly(&coeffs, x));
        }
    }

    Ok(shards)
}

/// Reconstruct the secret from a set of shards (requires >= threshold M).
/// Uses Lagrange interpolation evaluated at x = 0.
pub fn combine(shards: &[Vec<u8>]) -> Result<Vec<u8>, ShamirError> {
    if shards.len() < 2 {
        return Err(ShamirError::NotEnoughShards);
    }
    let len = shards[0].len();
    if len < 2 {
        return Err(ShamirError::NotEnoughShards);
    }
    for s in shards {
        if s.len() != len {
            return Err(ShamirError::ShardLengthMismatch);
        }
    }

    let xs: Vec<u8> = shards.iter().map(|s| s[0]).collect();
    let mut seen = [false; 256];
    for &x in &xs {
        if x == 0 {
            return Err(ShamirError::InvalidThreshold);
        }
        if seen[x as usize] {
            return Err(ShamirError::DuplicateShard);
        }
        seen[x as usize] = true;
    }

    let mut out = vec![0u8; len - 1];
    for j in 1..len {
        let mut acc: u8 = 0;
        for i in 0..shards.len() {
            let xi = xs[i];
            let yi = shards[i][j];
            let mut num: u8 = 1;
            let mut den: u8 = 1;
            for k in 0..shards.len() {
                if k == i {
                    continue;
                }
                let xk = xs[k];
                num = gf_mul(num, xk);       // product of (0 - xk) == xk
                den = gf_mul(den, xi ^ xk);  // product of (xi - xk)
            }
            let basis = gf_div(num, den);
            acc ^= gf_mul(yi, basis);
        }
        out[j - 1] = acc;
    }

    Ok(out)
}

// -----------------------------------------------------------------------------
// Self-tests (run with: cargo test shamir)
// -----------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_various_thresholds() {
        let secret = b"Emergency-Delivery-Vault-2026";
        for (n, m) in [(3, 2), (5, 3), (7, 3), (7, 5)] {
            let shards = split(secret, n, m).unwrap();
            // Combine the first m shards
            let subset: Vec<Vec<u8>> = shards[..m].to_vec();
            let recovered = combine(&subset).unwrap();
            assert_eq!(recovered, secret, "failed for n={} m={}", n, m);
        }
    }

    #[test]
    fn any_m_of_n_works() {
        let secret = b"seed-phrase-1234";
        let shards = split(secret, 5, 3).unwrap();
        // Use shards 1, 3, 4 (indices 0, 2, 3)
        let subset = vec![shards[0].clone(), shards[2].clone(), shards[3].clone()];
        let recovered = combine(&subset).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn fewer_than_m_gives_wrong_secret() {
        let secret = b"top-secret-value";
        let shards = split(secret, 5, 3).unwrap();
        let subset = vec![shards[0].clone(), shards[1].clone()]; // only 2 of 3
        let recovered = combine(&subset).unwrap();
        assert_ne!(recovered, secret, "must NOT reconstruct with m-1 shards");
    }

    #[test]
    fn rejects_invalid_inputs() {
        assert_eq!(split(b"", 3, 2).unwrap_err(), ShamirError::EmptySecret);
        assert_eq!(split(b"x", 1, 1).unwrap_err(), ShamirError::InvalidThreshold);
        assert_eq!(split(b"x", 2, 3).unwrap_err(), ShamirError::InvalidThreshold);
    }
}