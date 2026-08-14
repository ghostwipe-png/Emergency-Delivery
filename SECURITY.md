# Security Policy

## Supported Versions

| Version | Supported |
| ------- | --------- |
| 1.1.6   | ✅ Yes    |
| < 1.1.6 | ❌ No     |

## Reporting a Vulnerability

**Do NOT open a public issue.** Use one of:

1. **GitHub Private Vulnerability Reporting** (preferred):
   Security → Advisories → "Report a vulnerability"
2. Email: security@opinionplus.online (subject: `ED-SECURITY`)

### What to include
- Affected version + OS
- Step-by-step reproduction
- Impact assessment (what an attacker gains)
- Any proof-of-concept code

### Response timeline
- **48h** — acknowledgment
- **7 days** — triage + severity rating
- **30 days** — coordinated fix + release (criticals: 7 days)

### Safe harbor
Good-faith research on your own accounts/devices is authorized.
Never access other users' data or degrade the service.

## Security Model (summary)
- Zero-knowledge: files encrypted client-side (AES-256-GCM), keys derived via PBKDF2 (210k iterations)
- Device-bound Quick Login (KEK wrapped by word + device secret)
- Shamir M-of-N secret sharing for inheritance vaults
- Tamper-evident hash-chained audit logs
- Signed auto-updates (Ed25519)