# 🛡️ Emergency Delivery

**Enterprise-grade secure document logistics & end-to-end encrypted real-time messenger.**

Emergency Delivery is a zero-knowledge desktop application built for secure document logistics, emergency dead-man's switch releases, and private real-time communication. It combines a highly secure delivery engine with a full-featured, WhatsApp-style encrypted messenger.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Tauri](https://img.shields.io/badge/Tauri-v2-orange.svg)
![Rust](https://img.shields.io/badge/Rust-Backend-red.svg)
![React](https://img.shields.io/badge/React-Frontend-blue.svg)

---

## ✨ Core Features

### 📦 Secure Delivery Engine
*   **Zero-Knowledge Architecture:** Files are encrypted locally (AES-256-GCM) before ever leaving the device. The server never sees plaintext.
*   **Dead Man's Switch:** Configurable heartbeat system. If the user fails to check in, emergency documents and messages are automatically released to designated recipients.
*   **Scheduled & Password-Protected Releases:** Schedule deliveries for the future or lock them behind a secondary password.
*   **Watermark Viewer:** PDFs and images are decrypted in-memory and rendered in the browser with dynamic, recipient-specific watermarks to prevent unauthorized sharing.
*   **Read Receipts & Tracking:** Invisible tracking pixels and claim-link analytics.

### 💬 End-to-End Encrypted Messenger
*   **Real-Time WebSockets:** Powered by Cloudflare Durable Objects for instant, zero-latency message delivery.
*   **True E2EE:** Messages and files are encrypted in the client using a shared Channel DEK.
*   **WhatsApp-Style Controls:** Reply, Edit, and "Delete for Everyone" via secure control packets.
*   **30-Day Auto-Purge:** Server-side KV history automatically deletes itself after 30 days for strict privacy compliance.

### 🌐 Social Layer & Calls
*   **Privacy-Preserving Discovery:** Find other users via blind SHA-256 phone number hashing. The server never sees actual phone numbers.
*   **24-Hour Status/Stories:** Upload encrypted media that automatically expires and deletes from the server after 24 hours.
*   **WebRTC Video & Voice Calls:** Peer-to-peer encrypted calls. Signaling happens via WebSockets, but media streams directly between users (DTLS/SRTP).

### 🔒 Local-First Security
*   **Offline-First SQLite Vault:** Chat history and delivery logs are stored permanently on the device.
*   **Biometric Unlock:** Secure the app vault using Windows Hello / Touch ID.
*   **CSP Hardened:** Strict Content Security Policies prevent XSS and unauthorized network requests.

---

## 🛠️ Tech Stack

*   **Desktop Framework:** [Tauri v2](https://tauri.app/)
*   **Backend:** Rust (Async/Tokio, SQLx, AES-GCM, WebRTC signaling)
*   **Frontend:** React 18, TypeScript, Vite, TailwindCSS
*   **Infrastructure:** Cloudflare Workers, Durable Objects, R2 (Storage), KV (History)
*   **Integrations:** Paystack (Payments), Mobitech (SMS), Resend (Transactional Emails)

---

## 🚀 Getting Started (Development)

### Prerequisites
*   [Node.js](https://nodejs.org/) (v18+)
*   [Rust](https://www.rust-lang.org/tools/install)
*   [Cloudflare Wrangler](https://developers.cloudflare.com/workers/wrangler/install-and-update/)

### 1. Clone and Install
```bash
git clone https://github.com/ghostwipe-png/emergency-delivery.git
cd emergency-delivery
npm install

2. Configure Environment Variables
Create a .env file inside the src-tauri directory with your infrastructure keys:

# Cloudflare Worker (Must deploy emergency-delivery-dispatch first)
DELIVERY_WORKER_URL=https://your-worker.workers.dev
DELIVERY_WORKER_SECRET=your_worker_secret

# Storage (Cloudflare R2)
R2_ACCOUNT_ID=...
R2_BUCKET=...
R2_ACCESS_KEY_ID=...
R2_SECRET_ACCESS_KEY=...
WORKER_FILE_KEY=...

# Integrations
PAYSTACK_SECRET_KEY=...
MOBITECH_API_KEY=...
MOBITECH_API_URL=...

Automated CI/CD
This project includes a GitHub Actions workflow (.github/workflows/release.yml).
To trigger a cloud build and generate a GitHub Release:
git tag v1.0.0
git push origin v1.0.0

🏗️ Architecture Notes
This application relies on a companion Cloudflare Worker (emergency-delivery-dispatch) which handles:
Email Dispatch: Sending secure claim links via Resend.
Cron Scheduling: Waking up to dispatch scheduled deliveries.
Real-Time Gateway: Routing WebSocket connections to Durable Objects.
Social Directory: Storing blind-hashed phone mappings for contact discovery.