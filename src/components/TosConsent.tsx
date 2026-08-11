import React, { useState } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { useAppContext } from '../context/AppContext';

interface TosConsentProps {
  onAccepted: () => Promise<void> | void;
}

const TOS_TEXT = `
1. Acceptance of Terms
By accessing and using Emergency Delivery ("the App"), you agree to be bound by these Terms of Service. If you do not agree, you must not use the App and should uninstall it immediately.

2. Description of Service
Emergency Delivery provides secure, scheduled, and "dead-man" style delivery of encrypted documents, typed messages, and SMS. The App operates locally on your device and utilizes cloud workers for dispatch.

3. User Responsibilities
You are responsible for maintaining the confidentiality of your account credentials and 2FA tokens. You agree not to use the App for any unlawful purposes, including but not limited to sending spam, malware, or harassing messages.

4. Emergency & "Dead-Man" Deliveries
The App allows you to schedule deliveries that trigger if you fail to check in. You acknowledge that the App relies on device connectivity and background processes. We do not guarantee delivery if your device is destroyed or loses network access before the local scheduler can sync with our cloud workers.

5. Limitation of Liability
The App is provided "as is". We are not liable for any missed, delayed, or undelivered messages, nor for any data loss resulting from cryptographic key loss or device failure.
`;

const PRIVACY_TEXT = `
1. Data Collection & Encryption
Emergency Delivery is a "local-first" application. Your master password is never sent to our servers. All messages, files, and recipient details are encrypted locally on your device using AES-256-GCM before being transmitted to our secure Cloudflare R2 storage or dispatch workers.

2. Zero-Knowledge Architecture
Because we do not possess your encryption keys, we cannot read your files or messages. Law enforcement requests for content will be met with cryptographically unreadable ciphertext.

3. Audit Logs & Metadata
We maintain tamper-evident, hash-chained audit logs of account actions (logins, 2FA changes, ToS acceptances) to ensure security and compliance. These logs contain metadata (timestamps, action types) but never your decrypted content.

4. GDPR & Right to be Forgotten
You have the absolute right to delete your account at any time via the Settings menu. This action cryptographically shreds your local keys, wipes your SQLite database, deletes your R2 files, and signals our cloud workers to purge your queue.

5. Third-Party Services
We use Cloudflare (storage/workers), Resend (email dispatch), Paystack (payments), and Mobitech (SMS). These providers only receive the minimum data necessary to execute a delivery (e.g., recipient email, encrypted payload).
`;

const TosConsent: React.FC<TosConsentProps> = ({ onAccepted }) => {
  const { sessionToken } = useAppContext();
  const [agreed, setAgreed] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleAccept = async () => {
    if (!sessionToken) {
      setError('Session expired. Please sign in again.');
      return;
    }

    setLoading(true);
    setError(null);

    try {
      // Calls Rust `accept_tos` which updates the DB and writes the hash-chained audit log
      await invoke('accept_tos', { sessionToken });
      await onAccepted();
    } catch (err: any) {
      setError(String(err?.message || err || 'Failed to save consent.'));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-[#0b141a] p-4 md:p-8 overflow-y-auto">
      <div className="w-full max-w-3xl bg-[#111b21] rounded-2xl shadow-2xl flex flex-col max-h-[90vh] fade-in border border-[#202c33]">
        
        {/* Header */}
        <div className="p-6 border-b border-[#202c33] shrink-0">
          <h2 className="text-2xl font-bold text-[#e9edef]">Legal & Privacy Consent</h2>
          <p className="text-sm text-[#8696a0] mt-1">
            Please review our Terms of Service and Privacy Policy (Version 1.0) to continue.
          </p>
        </div>

        {/* Scrollable Content */}
        <div className="flex-1 overflow-y-auto p-6 space-y-8 text-sm text-[#8696a0] leading-relaxed">
          <section>
            <h3 className="text-lg font-bold text-[#e9edef] mb-3 flex items-center gap-2">
              <span className="w-1.5 h-6 bg-[#00a884] rounded-full"></span>
              Terms of Service
            </h3>
            <div className="whitespace-pre-line bg-[#202c33] p-4 rounded-xl">
              {TOS_TEXT.trim()}
            </div>
          </section>

          <section>
            <h3 className="text-lg font-bold text-[#e9edef] mb-3 flex items-center gap-2">
              <span className="w-1.5 h-6 bg-[#53bdeb] rounded-full"></span>
              Privacy Policy
            </h3>
            <div className="whitespace-pre-line bg-[#202c33] p-4 rounded-xl">
              {PRIVACY_TEXT.trim()}
            </div>
          </section>
        </div>

        {/* Footer / Action */}
        <div className="p-6 border-t border-[#202c33] bg-[#111b21] shrink-0">
          <label className="flex items-start gap-3 cursor-pointer select-none mb-4 group">
            <div className="relative mt-0.5">
              <input
                type="checkbox"
                checked={agreed}
                onChange={(e) => setAgreed(e.target.checked)}
                className="peer sr-only"
              />
              <div className="w-5 h-5 rounded-md border-2 border-[#8696a0] bg-[#202c33] peer-checked:bg-[#00a884] peer-checked:border-[#00a884] transition-colors flex items-center justify-center">
                {agreed && (
                  <svg className="w-3 h-3 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={3}>
                    <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
                  </svg>
                )}
              </div>
            </div>
            <span className="text-sm text-[#e9edef] group-hover:text-white transition-colors">
              I have read, understand, and agree to the <span className="text-[#00a884] font-medium">Terms of Service</span> and <span className="text-[#53bdeb] font-medium">Privacy Policy</span>.
            </span>
          </label>

          {error && (
            <div className="bg-red-900/20 text-red-400 p-3 rounded-xl text-xs mb-4 border border-red-900/50">
              {error}
            </div>
          )}

          <button
            onClick={() => { void handleAccept(); }}
            disabled={!agreed || loading}
            className="btn-primary w-full bg-[#00a884] hover:bg-[#06cf9c] text-white font-bold py-3.5 rounded-xl transition-all disabled:opacity-50 disabled:cursor-not-allowed disabled:hover:bg-[#00a884] flex items-center justify-center gap-2"
          >
            {loading ? (
              <>
                <svg className="animate-spin h-4 w-4 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                </svg>
                Saving Consent...
              </>
            ) : (
              'Accept & Continue'
            )}
          </button>
        </div>
      </div>
    </div>
  );
};

export default TosConsent;