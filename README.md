# 🔐 Emergency Delivery

**Messages that arrive, no matter what.** Secure scheduled delivery with dead man's switch,
irrevocable Guardian locks, and Shamir-split inheritance vaults.

![CI](https://github.com/ghostwipe-png/Emergency-Delivery/actions/workflows/ci.yml/badge.svg)
![Release](https://github.com/ghostwipe-png/Emergency-Delivery/actions/workflows/release.yml/badge.svg)

## Features
- ✉️ Scheduled email deliveries with expiry + view limits
- 🛡️ **Guardian** — irrevocable deliveries after 24h cooling-off
- 🧬 **Inheritance Vault** — M-of-N Shamir secret sharing
- 💓 **Dead Man's Switch** — heartbeat-triggered emergency dispatch
- 🎙️ Voice notes via secure SMS links (Kenya)
- 🔓 Quick Login (device-bound) + biometrics + TOTP 2FA
- 💳 Paystack credits · 📦 Encrypted R2 storage · 📜 Hash-chained audit logs

## Download
[Latest release →](https://github.com/ghostwipe-png/Emergency-Delivery/releases/latest)
(Windows · macOS · Linux)

## Security
Zero-knowledge: AES-256-GCM envelope encryption, PBKDF2 (210k), Ed25519-signed updates.
Full model: [docs/SECURITY-ARCHITECTURE.md](docs/SECURITY-ARCHITECTURE.md) ·
Report vulnerabilities: [SECURITY.md](SECURITY.md)

## Development
```bash
npm install
# create ./.env and ./src-tauri/.env (see below)
npm run tauri dev
cargo test --manifest-path src-tauri/Cargo.toml