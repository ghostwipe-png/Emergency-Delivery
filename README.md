# Emergency Delivery

Secure, scheduled document delivery for the Nigerian market. Users upload
documents, schedule a delivery time, and the system guarantees dispatch —
even in emergencies. Built with **Tauri v2 + Rust** (memory-safe backend)
and React + TypeScript.

## Core capabilities

| Feature | Implementation |
|---|---|
| Authentication | Local-first accounts, PBKDF2-HMAC-SHA256 (210k iterations), 24h sessions |
| File upload | Drag & drop + native dialog; PDF/DOCX/JPG/PNG/MP4; 100 MB limit |
| Encryption | AES-256-GCM envelope encryption (random per-file DEK wrapped by password-derived KEK) |
| Scheduling | Immediate → custom date/time, up to 5 years; background scheduler |
| Payments | Paystack (NGN): initialize, verify, idempotent credit top-up |
| Anonymous mode | Send without revealing sender identity |
| System tray | Windows tray with close-to-tray, show/quit menu |
| Storage | Cloudflare R2 (zero egress) or local encrypted vault fallback |

## Architecture
UI (React) ──invoke──► Rust commands ──► validation ──► services
│
┌──────────────────────────┼─────────────────────┐
▼ ▼ ▼
SQLite (sqlx) AES-256-GCM crypto Paystack / R2 / Worker
parameterized KEK from password HTTPS-only, retries,
queries only DEK per file circuit breaker

## Getting started (Windows 10/11)

### Prerequisites
1. Rust (stable) + MSVC build tools: https://tauri.app/start/prerequisites/
2. Node.js 18+
3. WebView2 Runtime (preinstalled on Windows 11 / recent Windows 10)

### Setup
```bash
npm install

# 1. Generate required icons from any 1024x1024 PNG:
npx @tauri-apps/cli icon path/to/your-logo.png
#    (writes src-tauri/icons/* — required before the first build)

# 2. Configure secrets (optional — app runs fully in local mode without them)
copy .env.example src-tauri\.env
#    then edit src-tauri\.env and add your Paystack + R2 keys

# 3. Run
npm run tauri dev

# 4. Production build (NSIS + MSI installers in src-tauri/target/release/bundle)
npm run tauri build

Graceful degradation
No Paystack key → payments disabled with a clear error; everything else works.
No R2 keys → encrypted blobs are stored in the local vault (%APPDATA%/…/vault).
No worker URL → the built-in scheduler dispatches due deliveries locally.
Security model
Encryption at rest — every document is encrypted with a fresh random
256-bit DEK using AES-256-GCM (authenticated encryption). The DEK is
wrapped with a KEK derived from the user's password via PBKDF2
(210,000 iterations, per-user 16-byte salt). Keys are held in
Zeroizing buffers and wiped on logout/drop.
Field-level DB encryption — recipient email/phone and sender identity
are encrypted before being written to SQLite. Only indexed lookup columns
(ids, status, timestamps) remain in plaintext. Note: sqlx does not support
SQLCipher; full-disk encryption relies on OS-level protections (BitLocker,
user-profile ACLs). This trade-off is intentional and documented.
SQL injection — impossible by construction; every query uses ?
placeholders via sqlx.
Sessions — 256-bit CSPRNG tokens, 24h expiry, validated on every
authorized command. User identity is always derived from the session —
never from client-supplied IDs (prevents IDOR).
Input validation — length, format and range checks on every field;
file uploads validated by magic bytes (not just extension), executables
rejected, names sanitized against path traversal.
Network — HTTPS-only clients (https_only(true)), 10–120s timeouts,
exponential-backoff retries, circuit breaker (5 failures → open 60s).
Payments — server-side amount cross-check against the plan, idempotent
verification (double-credit proof), reference charset validation.
Timing attacks — constant-time hash comparison; dummy PBKDF2 work on
unknown emails prevents account enumeration.
Secrets — environment variables only; nothing hardcoded; logs never
contain keys, passwords or tokens.
CSRF — not applicable: there is no browser cookie surface. All IPC is
Tauri's origin-locked command channel, and a strict CSP is enforced.
No panics — all fallible paths return Result; release profile uses
panic = "abort" as a last-resort guard.
Tauri command surface
ping, get_system_info, register_user, login_user, logout_user,
get_current_user, get_payment_plans, initialize_payment,
verify_payment, schedule_delivery, get_deliveries, cancel_delivery,
upload_file, pick_and_upload_file, get_upload_url.
Testing payments
Use Paystack test keys (sk_test_…) and test card
4084 0840 8408 4081 (CVV 408, any future expiry, OTP 123456).
Production worker (recommended next step)
The desktop app registers deliveries with DELIVERY_WORKER_URL. A
Cloudflare Worker + Durable Object (or Cron Trigger) should store the
registration and email the recipient a claim link at the scheduled time.
Because files are AES-GCM encrypted, the worker never sees plaintext
documents unless you include a decryption flow in the claim portal.

---

## Implementation notes & deliberate deviations

1. **`get_deliveries` takes no `user_id`** — the user identity is derived from the session token. Accepting a client-supplied `user_id` would be an IDOR vulnerability; this was hardened deliberately.
2. **Schema extended** with `password_hash`/`password_salt` (auth requirement), `sessions`, `uploads`, `payments` tables, and `wrapped_dek`/`dek_nonce` columns (envelope encryption metadata). Your original tables/indexes are all present.
3. **Local-first fallback** — without R2 credentials the app stores AES-256-GCM ciphertext in a local vault, so the full flow (upload → schedule → dispatch) works out of the box for reviewers and CI.
4. **`get_upload_url`** returns a genuine SigV4-presigned R2 PUT URL, but the *recommended* path is `upload_file`/`pick_and_upload_file`, which encrypt in Rust. Files registered via direct URL without a wrapped DEK are rejected at scheduling time — plaintext can never be scheduled.
5. **Icons are binary assets** — run `npx @tauri-apps/cli icon <your-1024px-png>` once before the first build; the tray reuses the bundled window icon, so no extra tray asset is needed.
6. **Paystack webhooks** can't reach a desktop app; verification uses Paystack's verify API as the source of truth (the officially recommended fallback), with idempotency guards.

Everything compiles as a unit: Rust modules are wired through `lib.rs`'s `generate_handler!`, the frontend types mirror the serde shapes exactly (snake_case across IPC, camelCase command args), and all Tauri v2 APIs used (`TrayIconBuilder`, `Emitter`, `get_webview_window`, `app.path()`, `@tauri-apps/api/core`) are the v2 forms — no v1 APIs anywhere.