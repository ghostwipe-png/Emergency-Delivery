import React, { useEffect, useState } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { LazyStore } from '@tauri-apps/plugin-store';
import { useAppContext } from '../context/AppContext';
import PaymentModal from './PaymentModal';
import { Delivery } from '../types';

type MainTab = 'email' | 'sms';
type EmailContentTab = 'file' | 'typed';
type Preset = 'now' | '1h' | '24h' | '1w' | '1m' | 'custom';
type LinkExpiry = 'none' | '24h' | '168h';
type LinkViews = 'none' | '1' | '5' | '10';

interface NewDeliveryProps {
  onDone?: () => void;
}

interface UploadInfo {
  file_key: string;
  file_name: string;
  file_size: number;
  file_type?: string | null;
  worker_dek?: string | null;
}

interface SmsStatus {
  freeRemaining: number;
  credits: number;
}

const settingsStore = new LazyStore('settings.json');

const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/i;
const MAX_MESSAGE_LEN = 5000;
const MAX_SMS_LEN = 160;
const MAX_BULK_RECIPIENTS = 50;

const PRESETS: { value: Preset; label: string }[] = [
  { value: 'now', label: 'Now' },
  { value: '1h', label: '+1 hour' },
  { value: '24h', label: '+24 hours' },
  { value: '1w', label: '+1 week' },
  { value: '1m', label: '+1 month' },
  { value: 'custom', label: 'Custom' },
];

const LINK_EXPIRY_OPTIONS: { value: LinkExpiry; label: string }[] = [
  { value: 'none', label: 'Never expires' },
  { value: '24h', label: 'Expires in 24 hours' },
  { value: '168h', label: 'Expires in 7 days' },
];

const LINK_VIEW_OPTIONS: { value: LinkViews; label: string }[] = [
  { value: 'none', label: 'Unlimited views' },
  { value: '1', label: '1 view only' },
  { value: '5', label: '5 views max' },
  { value: '10', label: '10 views max' },
];

// Phase 3: Recurring Deliveries Options (Strictly Additive)
const RECURRENCE_OPTIONS: { value: 'none' | 'daily' | 'weekly' | 'monthly'; label: string }[] = [
  { value: 'none', label: 'Send once (No recurrence)' },
  { value: 'daily', label: 'Repeat Daily' },
  { value: 'weekly', label: 'Repeat Weekly' },
  { value: 'monthly', label: 'Repeat Monthly' },
];

const toLocalInput = (date: Date): string => {
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(
    date.getHours()
  )}:${pad(date.getMinutes())}`;
};

const formatBytes = (bytes: number): string => {
  if (!bytes) return '0 B';
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1048576) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1048576).toFixed(1)} MB`;
};

const normalizePhone = (input: string): string => {
  let digits = input.replace(/\D/g, '');
  if (digits.startsWith('0')) digits = `254${digits.slice(1)}`;
  if (/^(7|1)\d{8}$/.test(digits)) digits = `254${digits}`;
  return digits;
};

const isValidKenyanPhone = (digits: string): boolean => /^254(7|1)\d{8}$/.test(digits);

const normalizeUpload = (raw: any): UploadInfo => {
  const source = Array.isArray(raw) ? raw[0] : raw;
  return {
    file_key: String(source?.file_key ?? source?.fileKey ?? source?.key ?? source?.fileId ?? ''),
    file_name: String(source?.file_name ?? source?.fileName ?? source?.name ?? 'file'),
    file_size: Number(source?.file_size ?? source?.fileSize ?? source?.size ?? 0),
    file_type: source?.file_type ?? source?.fileType ?? source?.mime ?? source?.content_type ?? null,
    worker_dek: source?.worker_dek ?? source?.workerDek ?? null,
  };
};

const NewDelivery: React.FC<NewDeliveryProps> = ({ onDone }) => {
  const { refreshUser, sessionToken, user } = useAppContext();

  // PHASE 15: Extract split balances for UI Paywall
  const emailCredits = (user as any)?.delivery_credits ?? 0;
  const smsCredits = (user as any)?.sms_balance ?? 0;

  const [mainTab, setMainTab] = useState<MainTab>('email');
  const [contentTab, setContentTab] = useState<EmailContentTab>('typed');

  const [bulkMode, setBulkMode] = useState(false);
  const [recipientEmail, setRecipientEmail] = useState('');
  const [bulkEmails, setBulkEmails] = useState('');
  const [anonymous, setAnonymous] = useState(false);

  const [messageText, setMessageText] = useState('');
  const [fileInfo, setFileInfo] = useState<UploadInfo | null>(null);
  const [uploading, setUploading] = useState(false);

  // Phase 2: Password Protection State
  const [enableClaimPassword, setEnableClaimPassword] = useState(false);
  const [claimPassword, setClaimPassword] = useState('');

  // Phase 2: Secure Preview State
  const [showPreview, setShowPreview] = useState(false);
  const [previewUrl, setPreviewUrl] = useState<string | null>(null);
  const [previewError, setPreviewError] = useState<string | null>(null);
  const [loadingPreview, setLoadingPreview] = useState(false);

  // Phase 3: Recurring Deliveries State (Strictly Additive)
  const [recurrence, setRecurrence] = useState<'none' | 'daily' | 'weekly' | 'monthly'>('none');

  // Phase 4: Emergency Delivery State (Strictly Additive)
  const [isEmergency, setIsEmergency] = useState(false);

  const [preset, setPreset] = useState<Preset>('now');
  const [customDate, setCustomDate] = useState('');
  const [linkExpiry, setLinkExpiry] = useState<LinkExpiry>('none');
  const [linkViews, setLinkViews] = useState<LinkViews>('none');

  const [phone, setPhone] = useState('');
  const [smsMessage, setSmsMessage] = useState('');
  const [smsStatus, setSmsStatus] = useState<SmsStatus | null>(null);
  const [loadingStatus, setLoadingStatus] = useState(false);

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [showPaymentModal, setShowPaymentModal] = useState(false);

  // PHASE 15: SMS Paywall Logic (Allow send if Free Tier > 0 OR Paid Credits > 0)
  const canSendSms = (smsStatus?.freeRemaining ?? 0) > 0 || smsCredits > 0;

  const parsedBulkEmails = bulkMode
    ? Array.from(
        new Set(
          bulkEmails
            .split(/[\n,;]+/)
            .map((entry) => entry.trim())
            .filter(Boolean)
        )
      )
    : [];

  useEffect(() => {
    const loadDefaultPreset = async () => {
      try {
        const saved = await settingsStore.get<string>('defaultPreset');
        if (saved && ['now', '1h', '24h', '1w', '1m', 'custom'].includes(saved)) {
          setPreset(saved as Preset);
        }
      } catch {
        // Ignore store read errors.
      }
    };

    loadDefaultPreset();
  }, []);

  useEffect(() => {
    if (mainTab === 'sms') {
      loadSmsStatus();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [mainTab]);

  const loadSmsStatus = async () => {
    setLoadingStatus(true);
    try {
      const raw: any = await invoke('get_sms_status', { sessionToken });

      if (typeof raw === 'number') {
        setSmsStatus({ freeRemaining: 0, credits: raw });
        return;
      }

      const freeRemaining = Number(
        raw?.free_remaining ??
          raw?.freeRemaining ??
          raw?.free_sms_remaining ??
          raw?.freeSmsRemaining ??
          0
      );

      const credits = Number(
        raw?.credits ??
          raw?.sms_balance ??
          raw?.smsBalance ??
          raw?.balance ??
          raw?.paid_credits ??
          raw?.paidCredits ??
          0
      );

      setSmsStatus({ freeRemaining, credits });
    } catch {
      setSmsStatus(null);
    } finally {
      setLoadingStatus(false);
    }
  };

  const selectPreset = async (value: Preset) => {
    if (value === 'custom' && !customDate) {
      setCustomDate(toLocalInput(new Date(Date.now() + 3600000)));
    }

    setPreset(value);

    try {
      await settingsStore.set('defaultPreset', value);
      await settingsStore.save();
    } catch {
      // Non-fatal preference persistence error.
    }
  };

  const handlePickFile = async () => {
    setError(null);
    setUploading(true);

    try {
      const raw = await invoke('pick_and_upload_file', { sessionToken });
      const normalized = normalizeUpload(raw);

      if (!normalized.file_key) {
        throw new Error('Upload failed: missing file key.');
      }

      setFileInfo(normalized);
    } catch (err: any) {
      const message = String(err?.message || err || '').toLowerCase();
      if (!message.includes('cancel') && !message.includes('abort')) {
        setError(String(err?.message || err || 'File upload failed.'));
      }
    } finally {
      setUploading(false);
    }
  };

  const clearFile = () => {
    setFileInfo(null);
    setEnableClaimPassword(false);
    setClaimPassword('');
  };

  // Phase 2: Secure Preview Logic
  const handlePreviewFile = async () => {
    if (!fileInfo?.file_key) return;
    setShowPreview(true);
    setLoadingPreview(true);
    setPreviewError(null);
    setPreviewUrl(null);

    try {
      // Tauri serializes Rust Vec<u8> as a standard JS number array
      const bytes = await invoke<Uint8Array | number[]>('preview_file', { 
        sessionToken, 
        fileKey: fileInfo.file_key 
      });
      
      const uint8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
      // TS 5.7+: slice() returns a fresh ArrayBuffer-backed Uint8Array, satisfying BlobPart
      const blob = new Blob([uint8.slice()], {
        type: fileInfo.file_type || 'application/octet-stream',
      });
      const url = URL.createObjectURL(blob);
      setPreviewUrl(url);
    } catch (err: any) {
      setPreviewError(String(err?.message || err || 'Failed to load preview.'));
    } finally {
      setLoadingPreview(false);
    }
  };

  const handleClosePreview = () => {
    if (previewUrl) {
      URL.revokeObjectURL(previewUrl);
    }
    setShowPreview(false);
    setPreviewUrl(null);
    setPreviewError(null);
  };

  const getScheduledDate = (): Date | null => {
    const now = new Date();

    switch (preset) {
      case 'now':
        return now;
      case '1h':
        return new Date(now.getTime() + 3600000);
      case '24h':
        return new Date(now.getTime() + 24 * 3600000);
      case '1w':
        return new Date(now.getTime() + 7 * 24 * 3600000);
      case '1m':
        return new Date(now.getTime() + 30 * 24 * 3600000);
      case 'custom': {
        if (!customDate) return null;
        const parsed = new Date(customDate);
        return Number.isNaN(parsed.getTime()) ? null : parsed;
      }
      default:
        return null;
    }
  };

  const handleScheduleEmail = async () => {
    setError(null);
    setSuccess(null);

    if (!bulkMode) {
      if (!EMAIL_REGEX.test(recipientEmail.trim())) {
        setError('Enter a valid recipient email address.');
        return;
      }
    }

    if (bulkMode) {
      if (parsedBulkEmails.length === 0) {
        setError('Enter at least one recipient email address.');
        return;
      }
      if (parsedBulkEmails.length > MAX_BULK_RECIPIENTS) {
        setError(`Bulk delivery supports up to ${MAX_BULK_RECIPIENTS} recipients.`);
        return;
      }
      const invalidEmail = parsedBulkEmails.find((email) => !EMAIL_REGEX.test(email));
      if (invalidEmail) {
        setError(`Invalid email address: ${invalidEmail}`);
        return;
      }
    }

    if (contentTab === 'typed') {
      if (!messageText.trim()) {
        setError('Enter a message to deliver.');
        return;
      }
      if (messageText.length > MAX_MESSAGE_LEN) {
        setError(`Typed messages are limited to ${MAX_MESSAGE_LEN} characters.`);
        return;
      }
    }

    if (contentTab === 'file' && !fileInfo) {
      setError('Choose and upload a file first.');
      return;
    }

    // Phase 2: Validate password if protection is enabled
    if (contentTab === 'file' && enableClaimPassword && !claimPassword.trim()) {
      setError('Please enter a password or disable password protection.');
      return;
    }

    const scheduledDate = getScheduledDate();
    if (!scheduledDate) {
      setError('Choose a valid delivery time.');
      return;
    }

    if (preset !== 'now' && scheduledDate.getTime() < Date.now() - 60000) {
      setError('Choose a future delivery time.');
      return;
    }

    const linkExpiryHours = linkExpiry === 'none' ? null : (linkExpiry === '24h' ? 24 : 168);
    const linkMaxViews = linkViews === 'none' ? null : Number(linkViews);

    const userEmail = (user as any)?.email || '';
    const userName = (user as any)?.name || userEmail.split('@')[0] || 'User';

    const payload: any = {
      channel: 'email',
      recipient_email: bulkMode ? null : recipientEmail.trim(),
      recipient_emails: bulkMode ? parsedBulkEmails : null,
      recipient_phone: null,
      recipient_name: bulkMode ? 'Bulk Recipients' : (recipientEmail.trim().split('@')[0] || 'Recipient'),
      message_text: contentTab === 'typed' ? messageText.trim() : null,
      file_key: fileInfo?.file_key ?? null,
      scheduled_for: scheduledDate.toISOString(),
      sender_mode: anonymous ? 'anonymous' : 'identified',
      sender_name: anonymous ? '' : userName,
      sender_email: anonymous ? '' : userEmail,
      link_expires_hours: linkExpiryHours,
      link_max_views: linkMaxViews,
      // Phase 2: Pass the claim password to Rust
      claim_password: (contentTab === 'file' && enableClaimPassword) ? claimPassword.trim() : null,
      // Phase 3: Pass recurrence pattern to Rust
      recurrence: recurrence === 'none' ? null : recurrence,
      // Phase 4: Pass emergency flag to Rust
      is_emergency: isEmergency,
    };

    setLoading(true);

    try {
      const created = await invoke<Delivery[]>('schedule_delivery', { sessionToken, data: payload });
      const count = Array.isArray(created) ? created.length : bulkMode ? parsedBulkEmails.length : 1;

      setSuccess(count > 1 ? `${count} deliveries scheduled successfully.` : 'Delivery scheduled successfully.');
      setRecipientEmail('');
      setBulkEmails('');
      setMessageText('');
      setFileInfo(null);
      setEnableClaimPassword(false);
      setClaimPassword('');
      setRecurrence('none'); // Phase 3: Reset recurrence
      setIsEmergency(false); // Phase 4: Reset emergency flag
      
      await refreshUser();
    } catch (err: any) {
      const message = String(err?.message || err || 'Failed to schedule delivery.');
      if (/insufficient|credit|balance|payment/i.test(message)) {
        setShowPaymentModal(true);
      }
      setError(message);
    } finally {
      setLoading(false);
    }
  };

  const handleSendSms = async () => {
    setError(null);
    setSuccess(null);

    const normalized = normalizePhone(phone);

    if (!isValidKenyanPhone(normalized)) {
      setError('Enter a valid Kenyan phone number, e.g. 254712345678.');
      return;
    }

    if (!smsMessage.trim()) {
      setError('Enter an SMS message.');
      return;
    }

    if (smsMessage.length > MAX_SMS_LEN) {
      setError(`SMS messages are limited to ${MAX_SMS_LEN} characters.`);
      return;
    }

    setLoading(true);

    const smsPayload = {
      sessionToken,
      request: {
        phone: normalized,
        mobile: normalized,
        recipient_phone: normalized,
        message: smsMessage.trim(),
        text: smsMessage.trim(),
      },
    };

    try {
      try {
        await invoke('send_sms', smsPayload);
      } catch (argError: any) {
        const rawMessage = String(argError?.message || argError || '').toLowerCase();

        if (/insufficient|credit|balance|payment/i.test(rawMessage)) {
          throw argError;
        }

        if (/unknown|invalid|missing/i.test(rawMessage)) {
          await invoke('send_sms', {
            sessionToken,
            phone: normalized,
            message: smsMessage.trim(),
          });
        } else {
          throw argError;
        }
      }

      setSuccess('SMS sent successfully.');
      setSmsMessage('');
      await refreshUser();
      await loadSmsStatus();
    } catch (err: any) {
      const message = String(err?.message || err || 'Failed to send SMS.');

      if (/insufficient|credit|balance|payment/i.test(message)) {
        setShowPaymentModal(true);
      }

      setError(message);
    } finally {
      setLoading(false);
    }
  };

  const handlePaymentSuccess = async () => {
    setShowPaymentModal(false);
    setError(null);

    try {
      await refreshUser();
      await loadSmsStatus();
    } catch {
      // Ignore refresh errors after payment.
    }
  };

  const paymentModalProps: any = {
    isOpen: showPaymentModal,
    open: showPaymentModal,
    show: showPaymentModal,
    visible: showPaymentModal,
    onClose: () => setShowPaymentModal(false),
    onCancel: () => setShowPaymentModal(false),
    onSuccess: handlePaymentSuccess,
    onPaymentSuccess: handlePaymentSuccess,
    onCompleted: handlePaymentSuccess,
    onPaid: handlePaymentSuccess,
  };

  return (
    <>
      {success && (
        <div className="fixed top-4 right-4 z-50 bg-[#00a884] text-white px-4 py-3 rounded-xl shadow-lg fade-in flex items-center gap-3">
          <span className="text-sm font-medium">{success}</span>
          <button
            onClick={() => {
              setSuccess(null);
              onDone?.();
            }}
            className="bg-white/10 hover:bg-white/20 px-3 py-1 rounded-lg text-sm font-semibold transition-colors"
          >
            Done
          </button>
        </div>
      )}

      <div className="panel bg-[#111b21] rounded-2xl p-6 fade-in">
        <h2 className="text-xl font-bold text-[#e9edef] mb-4">New Delivery</h2>

        {error && (
          <div className="bg-red-900/20 text-red-400 p-3 rounded-xl text-sm mb-4">
            {error}
          </div>
        )}

        {/* Main Channel Tabs */}
        <div className="flex bg-[#202c33] p-1 rounded-xl mb-6">
          <button
            onClick={() => {
              setMainTab('email');
              setError(null);
              setSuccess(null);
            }}
            className={`flex-1 py-2 rounded-lg font-medium transition-colors ${
              mainTab === 'email'
                ? 'bg-[#2a3942] text-[#e9edef]'
                : 'text-[#8696a0] hover:text-[#e9edef]'
            }`}
          >
            Email
          </button>
          <button
            onClick={() => {
              setMainTab('sms');
              setError(null);
              setSuccess(null);
            }}
            className={`flex-1 py-2 rounded-lg font-medium transition-colors ${
              mainTab === 'sms'
                ? 'bg-[#2a3942] text-[#e9edef]'
                : 'text-[#8696a0] hover:text-[#e9edef]'
            }`}
          >
            SMS
          </button>
        </div>

        {mainTab === 'email' ? (
          <div className="space-y-6">
            {/* Email Content Tabs */}
            <div className="flex bg-[#202c33] p-1 rounded-xl">
              <button
                onClick={() => setContentTab('typed')}
                className={`flex-1 py-2 rounded-lg text-sm font-medium transition-colors ${
                  contentTab === 'typed'
                    ? 'bg-[#2a3942] text-[#e9edef]'
                    : 'text-[#8696a0] hover:text-[#e9edef]'
                }`}
              >
                Typed Message
              </button>
              <button
                onClick={() => setContentTab('file')}
                className={`flex-1 py-2 rounded-lg text-sm font-medium transition-colors ${
                  contentTab === 'file'
                    ? 'bg-[#2a3942] text-[#e9edef]'
                    : 'text-[#8696a0] hover:text-[#e9edef]'
                }`}
              >
                File
              </button>
            </div>

            {contentTab === 'typed' ? (
              <div>
                <label className="label block text-sm text-[#8696a0] mb-2">
                  Secure message
                </label>
                <textarea
                  rows={5}
                  maxLength={MAX_MESSAGE_LEN}
                  value={messageText}
                  onChange={(e) => setMessageText(e.target.value)}
                  className="input w-full bg-[#202c33] text-[#e9edef] p-3 rounded-xl outline-none focus:ring-2 focus:ring-[#00a884] transition-all resize-none"
                  placeholder="Type the message you want delivered securely..."
                />
                <p className="text-xs text-[#8696a0] mt-1 text-right">
                  {messageText.length}/{MAX_MESSAGE_LEN}
                </p>
              </div>
            ) : (
              <div className="space-y-4">
                <div className="panel-2 bg-[#202c33] rounded-xl p-4">
                  <div className="flex items-center justify-between gap-4">
                    <div className="min-w-0">
                      {fileInfo ? (
                        <>
                          <p className="text-[#e9edef] font-medium truncate">
                            {fileInfo.file_name}
                          </p>
                          <p className="text-xs text-[#8696a0] mt-0.5">
                            {formatBytes(fileInfo.file_size)}
                          </p>
                        </>
                      ) : (
                        <p className="text-sm text-[#8696a0]">
                          No file selected. Files are encrypted before upload.
                        </p>
                      )}
                    </div>

                    <div className="flex items-center gap-2 shrink-0">
                      {fileInfo && (
                        <>
                          {/* Phase 2: Secure Preview Button */}
                          <button
                            onClick={() => void handlePreviewFile()}
                            className="btn-ghost px-3 py-2 rounded-lg bg-[#111b21] text-[#00a884] hover:text-[#06cf9c] transition-colors text-sm font-medium"
                          >
                            Preview
                          </button>
                          <button
                            onClick={clearFile}
                            className="btn-ghost px-3 py-2 rounded-lg bg-[#111b21] text-[#8696a0] hover:text-[#e9edef] transition-colors text-sm"
                          >
                            Remove
                          </button>
                        </>
                      )}
                      <button
                        onClick={handlePickFile}
                        disabled={uploading}
                        className="btn-secondary px-3 py-2 rounded-lg bg-[#2a3942] text-[#e9edef] hover:bg-[#00a884] transition-colors text-sm font-medium disabled:opacity-50"
                      >
                        {uploading ? 'Uploading...' : fileInfo ? 'Replace File' : 'Choose File'}
                      </button>
                    </div>
                  </div>
                </div>

                {/* Phase 2: Password Protection UI */}
                {contentTab === 'file' && fileInfo && (
                  <div className="panel-2 bg-[#202c33] rounded-xl p-4 space-y-3 fade-in">
                    <label className="flex items-center space-x-3 cursor-pointer select-none">
                      <input
                        type="checkbox"
                        checked={enableClaimPassword}
                        onChange={(e) => {
                          setEnableClaimPassword(e.target.checked);
                          if (!e.target.checked) setClaimPassword('');
                        }}
                        className="w-4 h-4 rounded bg-[#111b21] text-[#00a884] focus:ring-[#00a884] focus:ring-offset-0 focus:ring-offset-[#202c33]"
                      />
                      <div>
                        <p className="text-sm text-[#e9edef] font-medium">Password protect this file</p>
                        <p className="text-xs text-[#8696a0] mt-0.5">
                          Recipient will need to enter this password on the claim page to decrypt the file.
                        </p>
                      </div>
                    </label>

                    {enableClaimPassword && (
                      <input
                        type="password"
                        value={claimPassword}
                        onChange={(e) => setClaimPassword(e.target.value)}
                        className="input w-full bg-[#111b21] text-[#e9edef] p-3 rounded-xl outline-none focus:ring-2 focus:ring-[#00a884] transition-all"
                        placeholder="Enter a strong password"
                        autoComplete="new-password"
                      />
                    )}
                  </div>
                )}
              </div>
            )}

            {/* Recipient Controls */}
            <div>
              <div className="flex items-center justify-between mb-2">
                <label className="label text-sm text-[#8696a0]">
                  {bulkMode ? 'Bulk recipients' : 'Recipient email'}
                </label>
                <button
                  onClick={() => setBulkMode(!bulkMode)}
                  className="btn-ghost text-xs text-[#00a884] hover:text-[#06cf9c] transition-colors font-medium"
                >
                  {bulkMode ? 'Switch to single recipient' : 'Switch to bulk recipients'}
                </button>
              </div>

              {bulkMode ? (
                <>
                  <textarea
                    rows={4}
                    value={bulkEmails}
                    onChange={(e) => setBulkEmails(e.target.value)}
                    className="input w-full bg-[#202c33] text-[#e9edef] p-3 rounded-xl outline-none focus:ring-2 focus:ring-[#00a884] transition-all resize-none"
                    placeholder={'one@example.com\nanother@example.com'}
                  />
                  <p className="text-xs text-[#8696a0] mt-1">
                    {parsedBulkEmails.length} recipient(s) parsed · max {MAX_BULK_RECIPIENTS}
                  </p>
                </>
              ) : (
                <input
                  type="email"
                  value={recipientEmail}
                  onChange={(e) => setRecipientEmail(e.target.value)}
                  className="input w-full bg-[#202c33] text-[#e9edef] p-3 rounded-xl outline-none focus:ring-2 focus:ring-[#00a884] transition-all"
                  placeholder="recipient@example.com"
                />
              )}
            </div>

            {/* Sender Identity */}
            <div className="panel-2 bg-[#202c33] rounded-xl p-4">
              <label className="flex items-start space-x-3 cursor-pointer select-none">
                <input
                  type="checkbox"
                  checked={anonymous}
                  onChange={(e) => setAnonymous(e.target.checked)}
                  className="mt-0.5 w-4 h-4 rounded bg-[#111b21] text-[#00a884] focus:ring-[#00a884] focus:ring-offset-0 focus:ring-offset-[#202c33]"
                />
                <div>
                  <p className="text-sm text-[#e9edef] font-medium">Send anonymously</p>
                  <p className="text-xs text-[#8696a0] mt-0.5">
                    Hide your identity from the recipient. Emergency Delivery will appear as the sender.
                  </p>
                </div>
              </label>
            </div>

            {/* Delivery Time */}
            <div>
              <label className="label block text-sm text-[#8696a0] mb-2">
                Delivery time
              </label>
              <div className="flex flex-wrap gap-2">
                {PRESETS.map((item) => (
                  <button
                    key={item.value}
                    onClick={() => selectPreset(item.value)}
                    className={`px-4 py-2 rounded-xl text-sm font-medium transition-colors ${
                      preset === item.value
                        ? 'bg-[#00a884] text-white'
                        : 'bg-[#202c33] text-[#8696a0] hover:bg-[#2a3942]'
                    }`}
                  >
                    {item.label}
                  </button>
                ))}
              </div>

              {preset === 'custom' && (
                <input
                  type="datetime-local"
                  value={customDate}
                  min={toLocalInput(new Date())}
                  onChange={(e) => setCustomDate(e.target.value)}
                  className="input w-full bg-[#202c33] text-[#e9edef] p-3 rounded-xl outline-none focus:ring-2 focus:ring-[#00a884] transition-all mt-3"
                />
              )}
            </div>

            {/* Link Controls */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="label block text-sm text-[#8696a0] mb-2">
                  Link expiry
                </label>
                <select
                  value={linkExpiry}
                  onChange={(e) => setLinkExpiry(e.target.value as LinkExpiry)}
                  className="input w-full bg-[#202c33] text-[#e9edef] p-3 rounded-xl outline-none focus:ring-2 focus:ring-[#00a884] transition-all border-none"
                >
                  {LINK_EXPIRY_OPTIONS.map((option) => (
                    <option key={option.value} value={option.value}>
                      {option.label}
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label className="label block text-sm text-[#8696a0] mb-2">
                  Link views
                </label>
                <select
                  value={linkViews}
                  onChange={(e) => setLinkViews(e.target.value as LinkViews)}
                  className="input w-full bg-[#202c33] text-[#e9edef] p-3 rounded-xl outline-none focus:ring-2 focus:ring-[#00a884] transition-all border-none"
                >
                  {LINK_VIEW_OPTIONS.map((option) => (
                    <option key={option.value} value={option.value}>
                      {option.label}
                    </option>
                  ))}
                </select>
              </div>
            </div>

            {/* Phase 3: Recurring Delivery Controls (Strictly Additive) */}
            <div>
              <label className="label block text-sm text-[#8696a0] mb-2">
                Recurring delivery
              </label>
              <select
                value={recurrence}
                onChange={(e) => setRecurrence(e.target.value as any)}
                className="input w-full bg-[#202c33] text-[#e9edef] p-3 rounded-xl outline-none focus:ring-2 focus:ring-[#00a884] transition-all border-none"
              >
                {RECURRENCE_OPTIONS.map((option) => (
                  <option key={option.value} value={option.value}>
                    {option.label}
                  </option>
                ))}
              </select>
              {recurrence !== 'none' && (
                <p className="text-xs text-[#00a884] mt-2">
                  ⚡ This delivery will automatically repeat based on your selected schedule.
                </p>
              )}
            </div>

            {/* Phase 4: Emergency Delivery Toggle (Strictly Additive) */}
            <div className="panel-2 bg-[#202c33] rounded-xl p-4 border border-red-900/30">
              <label className="flex items-start space-x-3 cursor-pointer select-none">
                <input
                  type="checkbox"
                  checked={isEmergency}
                  onChange={(e) => setIsEmergency(e.target.checked)}
                  className="mt-0.5 w-4 h-4 rounded bg-[#111b21] text-red-500 focus:ring-red-500 focus:ring-offset-0 focus:ring-offset-[#202c33]"
                />
                <div>
                  <p className="text-sm text-[#e9edef] font-medium">🚨 Emergency Delivery (Dead Man's Switch)</p>
                  <p className="text-xs text-[#8696a0] mt-0.5">
                    If enabled, this delivery will be dispatched automatically if you fail to check in via Settings.
                  </p>
                </div>
              </label>
            </div>

            {/* Phase 15: Email Paywall Warning */}
            {emailCredits <= 0 && (
              <p className="text-red-400 text-xs text-center mb-2 animate-pulse font-medium">
                ⚠️ You have 0 Email credits. Please upgrade to send.
              </p>
            )}

            <button
              onClick={handleScheduleEmail}
              disabled={loading || uploading || emailCredits <= 0}
              className="btn-primary w-full bg-[#00a884] hover:bg-[#06cf9c] text-white font-bold py-3 rounded-xl transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {loading
                ? 'Scheduling...'
                : emailCredits <= 0
                ? 'Out of Email Credits'
                : preset === 'now'
                ? 'Send Now'
                : 'Schedule Delivery'}
            </button>
          </div>
        ) : (
          <div className="space-y-6">
            <div>
              <label className="label block text-sm text-[#8696a0] mb-2">
                Kenyan phone number
              </label>
              <input
                type="tel"
                value={phone}
                onChange={(e) => setPhone(e.target.value)}
                className="input w-full bg-[#202c33] text-[#e9edef] p-3 rounded-xl outline-none focus:ring-2 focus:ring-[#00a884] transition-all"
                placeholder="+254712345678"
              />
            </div>

            <div>
              <label className="label block text-sm text-[#8696a0] mb-2">
                SMS message
              </label>
              <textarea
                rows={4}
                maxLength={MAX_SMS_LEN}
                value={smsMessage}
                onChange={(e) => setSmsMessage(e.target.value)}
                className="input w-full bg-[#202c33] text-[#e9edef] p-3 rounded-xl outline-none focus:ring-2 focus:ring-[#00a884] transition-all resize-none"
                placeholder="Type your SMS message..."
              />
              <p
                className={`text-xs mt-1 text-right ${
                  smsMessage.length >= MAX_SMS_LEN ? 'text-red-400' : 'text-[#8696a0]'
                }`}
              >
                {smsMessage.length}/{MAX_SMS_LEN}
              </p>
            </div>

            <div className="panel-2 bg-[#202c33] rounded-xl p-4 text-sm">
              {loadingStatus ? (
                <p className="text-[#8696a0] animate-pulse">Loading SMS status...</p>
              ) : smsStatus ? (
                smsStatus.freeRemaining > 0 ? (
                  <p className="text-[#e9edef]">
                    Free SMS remaining:{' '}
                    <span className="text-[#00a884] font-bold">{smsStatus.freeRemaining}</span>
                  </p>
                ) : smsStatus.credits > 0 ? (
                  <p className="text-[#e9edef]">
                    Paid SMS credits:{' '}
                    <span className="text-[#00a884] font-bold">{smsStatus.credits}</span>
                  </p>
                ) : (
                  <div className="flex items-center justify-between gap-4">
                    <p className="text-red-400">No SMS credits remaining.</p>
                    <button
                      onClick={() => setShowPaymentModal(true)}
                      className="btn-secondary bg-[#2a3942] hover:bg-[#00a884] px-3 py-1.5 rounded-lg text-xs font-medium transition-colors"
                    >
                      Buy Credits
                    </button>
                  </div>
                )
              ) : (
                <p className="text-[#8696a0]">Unable to load SMS status.</p>
              )}
            </div>

            {/* Phase 15: SMS Paywall Warning */}
            {!canSendSms && !loadingStatus && (
              <p className="text-red-400 text-xs text-center mb-2 animate-pulse font-medium">
                ⚠️ You have 0 SMS credits. Please upgrade to send.
              </p>
            )}

            <button
              onClick={handleSendSms}
              disabled={
                loading || 
                smsMessage.length === 0 || 
                smsMessage.length > MAX_SMS_LEN || 
                !canSendSms
              }
              className="btn-primary w-full bg-[#00a884] hover:bg-[#06cf9c] text-white font-bold py-3 rounded-xl transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {loading 
                ? 'Sending SMS...' 
                : !canSendSms 
                ? 'Out of SMS Credits' 
                : 'Send SMS'}
            </button>

            <p className="text-xs text-[#8696a0] text-center">
              SMS delivery is Kenya-only and sent immediately. SMS is never retried automatically to prevent duplicates.
            </p>
          </div>
        )}
      </div>

      {/* Phase 2: Secure Preview Modal */}
      {showPreview && (
        <div className="fixed inset-0 z-[60] flex items-center justify-center bg-black/80 backdrop-blur-sm p-4 fade-in">
          <div className="bg-[#111b21] w-full max-w-4xl h-[85vh] rounded-2xl shadow-2xl flex flex-col border border-[#202c33]">
            <div className="p-4 border-b border-[#202c33] flex items-center justify-between">
              <h3 className="text-lg font-bold text-[#e9edef] truncate pr-4">Preview: {fileInfo?.file_name}</h3>
              <button 
                onClick={handleClosePreview} 
                className="w-8 h-8 flex items-center justify-center rounded-full bg-[#202c33] text-[#8696a0] hover:text-[#e9edef] transition-colors shrink-0"
              >
                ✕
              </button>
            </div>
            <div className="flex-1 overflow-auto p-4 flex items-center justify-center bg-[#0b141a]">
              {loadingPreview && <p className="text-[#8696a0] animate-pulse">Decrypting and loading preview...</p>}
              {previewError && <p className="text-red-400">{previewError}</p>}
              {previewUrl && !loadingPreview && (
                fileInfo?.file_type?.startsWith('image/') ? (
                  <img src={previewUrl} alt="Preview" className="max-w-full max-h-full object-contain rounded-lg" />
                ) : fileInfo?.file_type === 'application/pdf' ? (
                  <iframe src={previewUrl} className="w-full h-full rounded-lg border border-[#202c33]" title="PDF Preview" />
                ) : (
                  <div className="text-center text-[#8696a0]">
                    <p className="mb-4">Preview not available for this file type.</p>
                    <a href={previewUrl} download={fileInfo?.file_name} className="btn-primary px-4 py-2 rounded-xl bg-[#00a884] text-white font-bold inline-block">Download File</a>
                  </div>
                )
              )}
            </div>
          </div>
        </div>
      )}

      {showPaymentModal && <PaymentModal {...paymentModalProps} />}
    </>
  );
};

export default NewDelivery;