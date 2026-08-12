import React, { useState } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { useAppContext } from '../context/AppContext';
import { api } from '../services/api';
import PaymentModal from './PaymentModal';

type Step = 'warning' | 'compose' | 'locked';
type ContentMode = 'file' | 'text' | 'sms';

interface UploadInfo { file_key: string; file_name: string; file_size: number; file_type?: string | null; }

const toLocalDate = (d: Date) => {
  const p = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}`;
};
const toLocalTime = (d: Date) => {
  const p = (n: number) => String(n).padStart(2, '0');
  return `${p(d.getHours())}:${p(d.getMinutes())}`;
};

const GuardianView: React.FC = () => {
  const { sessionToken,  refreshUser } = useAppContext();

  const [step, setStep] = useState<Step>('warning');
  const [acknowledged, setAcknowledged] = useState(false);

  const [mode, setMode] = useState<ContentMode>('text');
  const [messageText, setMessageText] = useState('');
  const [fileInfo, setFileInfo] = useState<UploadInfo | null>(null);
  const [uploading, setUploading] = useState(false);

  const [recipientName, setRecipientName] = useState('');
  const [recipientEmail, setRecipientEmail] = useState('');
  const [recipientPhone, setRecipientPhone] = useState('');

  const [date, setDate] = useState(toLocalDate(new Date(Date.now() + 86400000)));
  const [time, setTime] = useState('09:00');

  const [seal1, setSeal1] = useState('');
  const [seal2, setSeal2] = useState('');

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [showPaymentModal, setShowPaymentModal] = useState(false);
  const [locks, setLocks] = useState<any[]>([]);

  const isSms = mode === 'sms';

  const applyPreset = (ms: number) => {
    const d = new Date(Date.now() + ms);
    setDate(toLocalDate(d));
    setTime(toLocalTime(d));
  };

  const handlePickFile = async () => {
    setError(null); setUploading(true);
    try {
      const raw = await invoke('pick_and_upload_file', { sessionToken });
      const src = Array.isArray(raw) ? raw[0] : raw;
      if (!src?.file_key) throw new Error('Upload failed.');
      setFileInfo({ file_key: src.file_key, file_name: src.file_name, file_size: src.file_size, file_type: src.file_type });
    } catch (e: any) {
      const m = String(e?.message || e).toLowerCase();
      if (!m.includes('cancel')) setError(String(e?.message || e));
    } finally { setUploading(false); }
  };

    const loadLocks = async () => {
    try { setLocks(await api.listGuardianLocks(sessionToken!)); } catch { /* ignore */ }
  };

  const handleCancelLock = async (id: string) => {
    if (!window.confirm('Cancel this Guardian delivery? Only possible within the 24h window.')) return;
    try { await api.cancelGuardianDelivery(sessionToken!, id); await loadLocks(); }
    catch (e: any) { setError(String(e?.message || e)); }
  };

  React.useEffect(() => { if (step === 'compose') void loadLocks(); }, [step]);


  const handleLock = async () => {
    if (!sessionToken) return; 
    setError(null);
    if (!recipientName.trim()) return setError('Enter the recipient name.');
    if (isSms) {
      const digits = recipientPhone.replace(/\D/g, '');
      if (!/^254(7|1)\d{8}$/.test(digits.startsWith('0') ? `254${digits.slice(1)}` : digits)) return setError('Enter a valid Kenyan phone number.');
    } else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/i.test(recipientEmail.trim())) {
      return setError('Enter a valid recipient email.');
    }
    if (mode === 'text' && !messageText.trim()) return setError('Enter the message to protect.');
    if (mode === 'file' && !fileInfo) return setError('Choose and upload a file first.');
    if (!/^\d{6}$/.test(seal1)) return setError('Seal code must be exactly 6 digits.');
    if (seal1 !== seal2) return setError('Seal codes do not match.');

    const scheduled = new Date(`${date}T${time}`);
    if (Number.isNaN(scheduled.getTime()) || scheduled.getTime() < Date.now()) return setError('Choose a future date & time.');

    setLoading(true);
    try {
      await api.lockGuardianDelivery(sessionToken, {
        content_type: mode,
        file_key: mode === 'file' ? fileInfo?.file_key ?? null : null,
        message_text: mode !== 'file' ? messageText.trim() : null,
        recipient_name: recipientName.trim(),
        recipient_email: isSms ? null : recipientEmail.trim(),
        recipient_phone: isSms ? recipientPhone.trim() : null,
        scheduled_for: scheduled.toISOString(),
        seal_code: seal1,
      });
      setStep('locked');
      await refreshUser();
    } catch (e: any) {
      const m = String(e?.message || e);
      if (/insufficient|credit|balance|payment/i.test(m)) setShowPaymentModal(true);
      setError(m);
    } finally { setLoading(false); }
  };

  // ---------- WARNING ----------
  if (step === 'warning') {
    return (
      <div className="mx-auto max-w-2xl p-6 fade-in">
        <div className="panel bg-[#111b21] rounded-2xl p-8 border border-yellow-900/40">
          <div className="text-5xl mb-4">🛡️</div>
          <h2 className="text-2xl font-bold text-[#e9edef]">Guardian</h2>
          <p className="text-sm text-[#8696a0] mt-2">
            A guaranteed, tamper-proof delivery that cannot be stopped once sealed.
          </p>

          <div className="mt-6 bg-yellow-900/20 border border-yellow-900/50 rounded-xl p-4 text-sm text-yellow-200 space-y-2">
            <p className="font-bold">⚠️ Irreversible after 24 hours</p>
            <p>
              You may cancel within the first <b>24 hours</b>. After that, the delivery is
              <b> permanently sealed</b> and <b>cannot be cancelled or stopped by anyone</b> —
              even if this app is deleted or this device is destroyed.
            </p>
          </div>

          <label className="flex items-start gap-3 mt-6 cursor-pointer select-none">
            <input type="checkbox" checked={acknowledged} onChange={(e) => setAcknowledged(e.target.checked)}
              className="mt-0.5 w-4 h-4 rounded bg-[#202c33] text-[#00a884] focus:ring-[#00a884]" />
            <span className="text-sm text-[#e9edef]">
              I understand that after 24 hours this delivery becomes irreversible and will reach its recipient no matter what.
            </span>
          </label>

          <button
            onClick={() => setStep('compose')}
            disabled={!acknowledged}
            className="btn-primary w-full mt-6 py-3 rounded-xl bg-[#00a884] hover:bg-[#06cf9c] text-white font-bold transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          >
            Proceed to Guardian
          </button>
        </div>
      </div>
    );
  }

  // ---------- LOCKED ----------
  if (step === 'locked') {
    return (
      <div className="mx-auto max-w-2xl p-6 fade-in">
        <div className="panel bg-[#111b21] rounded-2xl p-10 text-center border border-[#00a884]/40">
          <div className="text-6xl mb-4">🔒</div>
          <h2 className="text-2xl font-bold text-[#e9edef]">Sealed in the Vault</h2>
          <p className="text-sm text-[#8696a0] mt-3">
            Your Guardian delivery is locked. You can cancel within 24 hours.
            After that, it is <b className="text-[#00a884]">irreversible</b> and will be delivered no matter what.
          </p>
          <button onClick={() => setStep('warning')} className="btn-secondary mt-6 px-6 py-2 rounded-xl bg-[#2a3942] text-[#e9edef]">
            Create Another
          </button>
        </div>
      </div>
    );
  }

  // ---------- COMPOSE ----------
  return (
    <div className="mx-auto max-w-2xl p-6 space-y-6 fade-in">
      <div className="panel bg-[#111b21] rounded-2xl p-6">
        <h2 className="text-xl font-bold text-[#e9edef] mb-4">🛡️ Guardian</h2>
        {error && <div className="bg-red-900/20 text-red-400 p-3 rounded-xl text-sm mb-4">{error}</div>}

        {/* Content mode */}
        <div className="flex bg-[#202c33] p-1 rounded-xl mb-6">
          {(['text', 'file', 'sms'] as ContentMode[]).map((m) => (
            <button key={m} onClick={() => setMode(m)}
              className={`flex-1 py-2 rounded-lg text-sm font-medium capitalize transition-colors ${mode === m ? 'bg-[#2a3942] text-[#e9edef]' : 'text-[#8696a0]'}`}>
              {m === 'text' ? 'Typed' : m === 'file' ? 'File' : 'SMS'}
            </button>
          ))}
        </div>

        {mode === 'text' && (
          <textarea rows={5} value={messageText} onChange={(e) => setMessageText(e.target.value)}
            className="input w-full bg-[#202c33] text-[#e9edef] p-3 rounded-xl outline-none focus:ring-2 focus:ring-[#00a884] resize-none"
            placeholder="The message that must be delivered, no matter what..." />
        )}

        {mode === 'file' && (
          <div className="panel-2 bg-[#202c33] rounded-xl p-4 flex items-center justify-between gap-4">
            <div className="min-w-0">
              {fileInfo ? <p className="text-[#e9edef] truncate">{fileInfo.file_name}</p> : <p className="text-sm text-[#8696a0]">No file selected.</p>}
            </div>
            <button onClick={handlePickFile} disabled={uploading}
              className="btn-secondary px-3 py-2 rounded-lg bg-[#2a3942] text-[#e9edef] text-sm disabled:opacity-50">
              {uploading ? 'Uploading...' : fileInfo ? 'Replace' : 'Choose File'}
            </button>
          </div>
        )}

        {mode === 'sms' && (
          <textarea rows={4} maxLength={160} value={messageText} onChange={(e) => setMessageText(e.target.value)}
            className="input w-full bg-[#202c33] text-[#e9edef] p-3 rounded-xl outline-none focus:ring-2 focus:ring-[#00a884] resize-none"
            placeholder="SMS message (160 chars)..." />
        )}

        {/* Recipient */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-6">
          <div>
            <label className="label text-sm text-[#8696a0] block mb-2">Recipient name</label>
            <input value={recipientName} onChange={(e) => setRecipientName(e.target.value)}
              className="input w-full bg-[#202c33] text-[#e9edef] p-3 rounded-xl" placeholder="Jane Doe" />
          </div>
          <div>
            <label className="label text-sm text-[#8696a0] block mb-2">{isSms ? 'Phone (Kenya)' : 'Email'}</label>
            <input value={isSms ? recipientPhone : recipientEmail}
              onChange={(e) => (isSms ? setRecipientPhone(e.target.value) : setRecipientEmail(e.target.value))}
              className="input w-full bg-[#202c33] text-[#e9edef] p-3 rounded-xl"
              placeholder={isSms ? '+254712345678' : 'recipient@example.com'} />
          </div>
        </div>

        {/* Calendar scheduling */}
        <div className="mt-6">
          <label className="label text-sm text-[#8696a0] block mb-2">Delivery date & time</label>
          <div className="flex flex-wrap gap-2 mb-3">
            {[{ l: '+1h', ms: 3600000 }, { l: '+24h', ms: 86400000 }, { l: '+7d', ms: 604800000 }, { l: '+30d', ms: 2592000000 }].map((p) => (
              <button key={p.l} onClick={() => applyPreset(p.ms)} className="px-3 py-1.5 rounded-lg bg-[#202c33] text-[#8696a0] text-xs hover:bg-[#2a3942]">{p.l}</button>
            ))}
          </div>
          <div className="grid grid-cols-2 gap-4">
            <input type="date" value={date} min={toLocalDate(new Date())} onChange={(e) => setDate(e.target.value)}
              className="input bg-[#202c33] text-[#e9edef] p-3 rounded-xl" />
            <input type="time" value={time} onChange={(e) => setTime(e.target.value)}
              className="input bg-[#202c33] text-[#e9edef] p-3 rounded-xl" />
          </div>
        </div>

        {/* Seal */}
        <div className="mt-6">
          <label className="label text-sm text-[#8696a0] block mb-2">6-digit seal code</label>
          <div className="grid grid-cols-2 gap-4">
            <input inputMode="numeric" maxLength={6} value={seal1} onChange={(e) => setSeal1(e.target.value.replace(/\D/g, ''))}
              className="input bg-[#202c33] text-[#e9edef] p-3 rounded-xl tracking-widest text-center" placeholder="••••••" />
            <input inputMode="numeric" maxLength={6} value={seal2} onChange={(e) => setSeal2(e.target.value.replace(/\D/g, ''))}
              className="input bg-[#202c33] text-[#e9edef] p-3 rounded-xl tracking-widest text-center" placeholder="Confirm" />
          </div>
          <p className="text-xs text-[#8696a0] mt-2">This seals the delivery. After 24 hours, nothing can stop it.</p>
        </div>

        <button onClick={() => void handleLock()} disabled={loading || uploading}
          className="btn-primary w-full mt-6 py-3 rounded-xl bg-[#00a884] hover:bg-[#06cf9c] text-white font-bold disabled:opacity-50">
          {loading ? 'Sealing...' : '🔒 Seal Guardian Delivery'}
        </button>
      </div>

              {locks.length > 0 && (
          <div className="mt-6">
            <h3 className="text-sm font-bold text-[#e9edef] mb-2">Your Guardian Locks</h3>
            <div className="space-y-2">
              {locks.map((l) => {
                const cancellable = l.status === 'pending' && new Date(l.cooling_off_until).getTime() > Date.now();
                return (
                  <div key={l.id} className="panel-2 bg-[#202c33] rounded-xl p-3 flex items-center justify-between gap-3 text-sm">
                    <div className="min-w-0">
                      <p className="text-[#e9edef] truncate">🛡️ {l.channel.toUpperCase()} · {new Date(l.scheduled_for).toLocaleString()}</p>
                      <p className={`text-xs mt-0.5 ${l.status === 'delivered' ? 'text-[#00a884]' : l.status === 'cancelled' ? 'text-red-400' : 'text-yellow-400'}`}>
                        {l.status === 'pending' ? (cancellable ? 'Sealed · cancellable for 24h' : 'IRREVERSIBLE · will be delivered') : l.status}
                      </p>
                    </div>
                    {cancellable && (
                      <button onClick={() => void handleCancelLock(l.id)}
                        className="btn-ghost px-3 py-1.5 rounded-lg bg-[#111b21] text-red-400 text-xs shrink-0">Cancel</button>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        )}

      {showPaymentModal && (
        <PaymentModal isOpen onClose={() => setShowPaymentModal(false)} onSuccess={() => { setShowPaymentModal(false); refreshUser(); }} />
      )}
    </div>
  );
};

export default GuardianView;