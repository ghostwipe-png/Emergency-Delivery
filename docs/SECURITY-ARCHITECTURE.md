# Security Architecture

## Key hierarchy
1. **KEK** (Key Encryption Key) — derived from password via PBKDF2-SHA256, 210,000 iterations + per-user salt.
2. **DEK** (Data Encryption Key) — random per file; wrapped by the KEK (AES-256-GCM).
3. **Worker FILE_KEY** — server-side key enabling claim-link decryption; never stored client-side in plaintext.

## Quick Login
- Device secret (32B) stored in OS keychain with encrypted-file fallback.
- `device_id = SHA-256(device_secret)`.
- Quick key = PBKDF2(word, salt ‖ device_secret); wraps the KEK (AES-256-GCM).
- 5 failed attempts → 15-minute lockout.

## Inheritance Vault
- Secret split with Shamir over GF(256); M-of-N required.
- Shards encrypted per beneficiary; 8-digit access codes shown once.

## Guardian
- Seal hash committed at lock time; immutable after 24h cooling-off.
- Cloudflare D1 + cron guarantees dispatch independent of the client device.

## Transport & updates
- Worker auth: `X-Worker-Secret` header + per-request validation.
- Auto-updates signed Ed25519; unsigned updates rejected.

## Audit
- Every security event appended to a hash-chained log (previous_hash included).