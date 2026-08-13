import React, { useState, useEffect, useCallback, useMemo, memo } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { useAppContext } from '../context/AppContext';
import { api } from '../services/api';
import PaymentModal from './PaymentModal';

// =============================================================================
// TYPES & INTERFACES
// =============================================================================

type Step = 'warning' | 'compose' | 'locked';
type ContentMode = 'file' | 'text' | 'sms';

interface UploadInfo {
  file_key: string;
  file_name: string;
  file_size: number;
  file_type?: string | null;
}

interface GuardianLock {
  id: string;
  channel: 'sms' | 'email';
  scheduled_for: string;
  cooling_off_until: string;
  status: 'pending' | 'locked' | 'delivered' | 'cancelled';
  seal_hash: string;
  created_at: string;
}

// =============================================================================
// CONSTANTS
// =============================================================================

const VALIDATION_RULES = {
  MAX_MESSAGE_LENGTH: 5000,
  MAX_SMS_LENGTH: 160,
  MAX_RECIPIENT_NAME_LENGTH: 100,
  MAX_EMAIL_LENGTH: 254,
  SEAL_CODE_LENGTH: 6,
  COOLING_OFF_HOURS: 24,
  EMAIL_REGEX: /^[^\s@]+@[^\s@]+\.[^\s@]+$/i,
  KENYA_PHONE_REGEX: /^254(7|1)\d{8}$/,
  MAX_FILE_SIZE: 50 * 1024 * 1024, // 50MB
  ALLOWED_FILE_TYPES: [
    'application/pdf',
    'image/jpeg',
    'image/png',
    'text/plain',
    'application/msword',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  ],
};

const TIME_PRESETS = [
  { label: '+1h', ms: 3600000 },
  { label: '+24h', ms: 86400000 },
  { label: '+7d', ms: 604800000 },
  { label: '+30d', ms: 2592000000 },
];

// =============================================================================
// UTILITY FUNCTIONS
// =============================================================================

/**
 * Structured logger for debugging
 */
const logger = {
  info: (msg: string, data?: any) => {
    console.log(`[GuardianView] ${msg}`, data || '');
  },
  error: (msg: string, error?: any) => {
    console.error(`[GuardianView] ${msg}`, error || '');
  },
  warn: (msg: string, data?: any) => {
    console.warn(`[GuardianView] ${msg}`, data || '');
  },
};

/**
 * Format date to local YYYY-MM-DD format
 */
const toLocalDate = (d: Date): string => {
  const p = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}`;
};

/**
 * Format date to local HH:MM format
 */
const toLocalTime = (d: Date): string => {
  const p = (n: number) => String(n).padStart(2, '0');
  return `${p(d.getHours())}:${p(d.getMinutes())}`;
};

/**
 * Validate email format
 */
function isValidEmail(email: string): boolean {
  return VALIDATION_RULES.EMAIL_REGEX.test(email);
}

/**
 * Validate Kenyan phone number
 */
function isValidKenyaPhone(phone: string): boolean {
  const digits = phone.replace(/\D/g, '');
  const normalized = digits.startsWith('0') ? `254${digits.slice(1)}` : digits;
  return VALIDATION_RULES.KENYA_PHONE_REGEX.test(normalized);
}

/**
 * Format file size for display
 */
function formatFileSize(bytes: number): string {
  if (bytes === 0) return '0 Bytes';
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return Math.round((bytes / Math.pow(k, i)) * 100) / 100 + ' ' + sizes[i];
}

/**
 * Categorize errors for better user feedback
 */
function categorizeError(error: any): { type: string; message: string } {
  const msg = String(error?.message || error || 'Unknown error').toLowerCase();
  
  if (msg.includes('validation')) {
    return { type: 'validation', message: error.message || 'Invalid input' };
  }
  if (msg.includes('network') || msg.includes('timeout')) {
    return { type: 'network', message: 'Network error. Please check your connection.' };
  }
  if (msg.includes('unauthorized') || msg.includes('session')) {
    return { type: 'auth', message: 'Session expired. Please log in again.' };
  }
  if (/insufficient|credit|balance|payment/i.test(msg)) {
    return { type: 'payment', message: 'Insufficient credits. Please purchase more.' };
  }
  if (msg.includes('database') || msg.includes('storage')) {
    return { type: 'storage', message: 'Storage error. Please try again.' };
  }
  
  return { type: 'unknown', message: error.message || 'An unexpected error occurred' };
}

/**
 * Check if a lock is still cancellable
 */
function isLockCancellable(lock: GuardianLock): boolean {
  return lock.status === 'pending' && new Date(lock.cooling_off_until).getTime() > Date.now();
}

// =============================================================================
// SUB-COMPONENTS
// =============================================================================

/**
 * Error display component with categorization
 */
const ErrorDisplay = memo(({ error, onDismiss }: { error: string; onDismiss?: () => void }) => {
  const categorized = categorizeError(error);
  
  const iconMap: Record<string, string> = {
    validation: '⚠️',
    network: '🌐',
    auth: '🔐',
    payment: '💳',
    storage: '💾',
    unknown: '❌',
  };
  
  const colorMap: Record<string, string> = {
    validation: 'border-yellow-900/50 bg-yellow-900/20 text-yellow-200',
    network: 'border-blue-900/50 bg-blue-900/20 text-blue-200',
    auth: 'border-red-900/50 bg-red-900/20 text-red-200',
    payment: 'border-purple-900/50 bg-purple-900/20 text-purple-200',
    storage: 'border-orange-900/50 bg-orange-900/20 text-orange-200',
    unknown: 'border-red-900/50 bg-red-900/20 text-red-200',
  };
  
  return (
    <div
      role="alert"
      className={`p-4 rounded-xl border ${colorMap[categorized.type]} mb-4 flex items-start gap-3`}
    >
      <span className="text-xl">{iconMap[categorized.type]}</span>
      <div className="flex-1">
        <p className="text-sm font-medium">{categorized.message}</p>
      </div>
      {onDismiss && (
        <button
          onClick={onDismiss}
          className="text-sm opacity-60 hover:opacity-100 transition-opacity"
          aria-label="Dismiss error"
        >
          ✕
        </button>
      )}
    </div>
  );
});

/**
 * Lock card component
 */
const LockCard = memo(({
  lock,
  onCancel,
}: {
  lock: GuardianLock;
  onCancel: (id: string) => void;
}) => {
  const cancellable = isLockCancellable(lock);
  
  const statusColor = useMemo(() => {
    if (lock.status === 'delivered') return 'text-[#00a884]';
    if (lock.status === 'cancelled') return 'text-red-400';
    if (lock.status === 'locked') return 'text-yellow-400';
    return cancellable ? 'text-yellow-400' : 'text-red-400';
  }, [lock.status, cancellable]);
  
  const statusText = useMemo(() => {
    if (lock.status === 'pending') {
      return cancellable ? 'Sealed · cancellable for 24h' : 'IRREVERSIBLE · will be delivered';
    }
    return lock.status;
  }, [lock.status, cancellable]);

  return (
    <div
      className="panel-2 bg-[#202c33] rounded-xl p-3 flex items-center justify-between gap-3 text-sm transition-all hover:bg-[#2a3942]"
      role="article"
      aria-label={`Guardian lock scheduled for ${new Date(lock.scheduled_for).toLocaleString()}`}
    >
      <div className="min-w-0 flex-1">
        <p className="text-[#e9edef] truncate font-medium">
          🛡️ {lock.channel.toUpperCase()} · {new Date(lock.scheduled_for).toLocaleString()}
        </p>
        <p className={`text-xs mt-0.5 font-medium ${statusColor}`}>
          {statusText}
        </p>
      </div>
      {cancellable && (
        <button
          onClick={() => onCancel(lock.id)}
          className="btn-ghost px-3 py-1.5 rounded-lg bg-[#111b21] text-red-400 text-xs shrink-0 hover:bg-red-900/20 transition-colors"
          aria-label={`Cancel Guardian lock scheduled for ${new Date(lock.scheduled_for).toLocaleString()}`}
        >
          Cancel
        </button>
      )}
    </div>
  );
});

// =============================================================================
// MAIN COMPONENT
// =============================================================================

const GuardianView: React.FC = () => {
  const { sessionToken, refreshUser } = useAppContext();

  // Core state
  const [step, setStep] = useState<Step>('warning');
  const [acknowledged, setAcknowledged] = useState(false);
  const [locks, setLocks] = useState<GuardianLock[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [showPaymentModal, setShowPaymentModal] = useState(false);

  // Form state
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

  const isSms = useMemo(() => mode === 'sms', [mode]);

  // ===========================================================================
  // DATA LOADING
  // ===========================================================================

  const loadLocks = useCallback(async () => {
    if (!sessionToken) {
      logger.warn('Cannot load locks: no session token');
      return;
    }

    try {
      logger.info('Loading Guardian locks...');
      const data = await api.listGuardianLocks(sessionToken);
      setLocks(data);
      logger.info('Locks loaded successfully', { count: data.length });
    } catch (e: any) {
      const categorized = categorizeError(e);
      logger.error('Failed to load locks', categorized);
      // Don't show error to user for background load
    }
  }, [sessionToken]);

  useEffect(() => {
    if (step === 'compose') {
      void loadLocks();
    }
  }, [step, loadLocks]);

  // ===========================================================================
  // FILE UPLOAD
  // ===========================================================================

  const handlePickFile = useCallback(async () => {
    if (!sessionToken) {
      setError('Session required to upload files');
      return;
    }

    setError(null);
    setSuccess(null);
    setUploading(true);

    try {
      logger.info('Opening file picker...');
      const raw = await invoke<any>('pick_and_upload_file', { sessionToken });

      if (!raw) {
        logger.warn('File picker cancelled or no file selected');
        return;
      }

      const src = Array.isArray(raw) ? raw[0] : raw;

      if (!src?.file_key) {
        throw new Error('Upload failed: missing file key');
      }

      // Validate file size
      if (src.file_size > VALIDATION_RULES.MAX_FILE_SIZE) {
        throw new Error(
          `File too large. Maximum size is ${formatFileSize(VALIDATION_RULES.MAX_FILE_SIZE)}`
        );
      }

      // Validate file type
      if (src.file_type && !VALIDATION_RULES.ALLOWED_FILE_TYPES.includes(src.file_type)) {
        throw new Error('File type not allowed');
      }

      const uploadInfo: UploadInfo = {
        file_key: src.file_key,
        file_name: src.file_name,
        file_size: src.file_size,
        file_type: src.file_type,
      };

      setFileInfo(uploadInfo);
      setSuccess(`File uploaded: ${src.file_name} (${formatFileSize(src.file_size)})`);
      logger.info('File uploaded successfully', uploadInfo);
    } catch (e: any) {
      const msg = String(e?.message || e).toLowerCase();
      // Don't show error if user cancelled
      if (!msg.includes('cancel')) {
        const categorized = categorizeError(e);
        logger.error('File upload failed', categorized);
        setError(categorized.message);
      }
    } finally {
      setUploading(false);
    }
  }, [sessionToken]);

  // ===========================================================================
  // TIME PRESETS
  // ===========================================================================

  const applyPreset = useCallback((ms: number) => {
    const d = new Date(Date.now() + ms);
    setDate(toLocalDate(d));
    setTime(toLocalTime(d));
    logger.info('Applied time preset', { ms, date: toLocalDate(d), time: toLocalTime(d) });
  }, []);

  // ===========================================================================
  // LOCK OPERATIONS
  // ===========================================================================

  const handleCancelLock = useCallback(async (id: string) => {
    if (!sessionToken) {
      setError('Session required');
      return;
    }

    const confirmed = window.confirm(
      'Cancel this Guardian delivery? Only possible within the 24h cooling-off window.'
    );

    if (!confirmed) {
      logger.info('Lock cancellation cancelled by user', { lockId: id });
      return;
    }

    setError(null);

    try {
      logger.info('Cancelling Guardian lock', { lockId: id });
      await api.cancelGuardianDelivery(sessionToken, id);
      setSuccess('Guardian delivery cancelled successfully.');
      logger.info('Lock cancelled successfully', { lockId: id });
      await loadLocks();
    } catch (e: any) {
      const categorized = categorizeError(e);
      logger.error('Lock cancellation failed', categorized);
      setError(categorized.message);
    }
  }, [sessionToken, loadLocks]);

  // ===========================================================================
  // FORM VALIDATION
  // ===========================================================================

  const validateForm = useCallback((): string | null => {
    // Recipient name validation
    if (!recipientName.trim()) {
      return 'Enter the recipient name';
    }
    if (recipientName.length > VALIDATION_RULES.MAX_RECIPIENT_NAME_LENGTH) {
      return `Recipient name must be less than ${VALIDATION_RULES.MAX_RECIPIENT_NAME_LENGTH} characters`;
    }

    // Contact validation
    if (isSms) {
      if (!recipientPhone.trim()) {
        return 'Enter a phone number';
      }
      if (!isValidKenyaPhone(recipientPhone)) {
        return 'Enter a valid Kenyan phone number (e.g., +254712345678)';
      }
    } else {
      if (!recipientEmail.trim()) {
        return 'Enter an email address';
      }
      if (!isValidEmail(recipientEmail)) {
        return 'Enter a valid email address';
      }
      if (recipientEmail.length > VALIDATION_RULES.MAX_EMAIL_LENGTH) {
        return `Email must be less than ${VALIDATION_RULES.MAX_EMAIL_LENGTH} characters`;
      }
    }

    // Content validation
    if (mode === 'text') {
      if (!messageText.trim()) {
        return 'Enter the message to protect';
      }
      if (messageText.length > VALIDATION_RULES.MAX_MESSAGE_LENGTH) {
        return `Message must be less than ${VALIDATION_RULES.MAX_MESSAGE_LENGTH} characters`;
      }
    } else if (mode === 'file') {
      if (!fileInfo) {
        return 'Choose and upload a file first';
      }
    } else if (mode === 'sms') {
      if (!messageText.trim()) {
        return 'Enter the SMS message';
      }
      if (messageText.length > VALIDATION_RULES.MAX_SMS_LENGTH) {
        return `SMS message must be less than ${VALIDATION_RULES.MAX_SMS_LENGTH} characters`;
      }
    }

    // Seal code validation
    if (!seal1) {
      return 'Enter a seal code';
    }
    if (seal1.length !== VALIDATION_RULES.SEAL_CODE_LENGTH) {
      return `Seal code must be exactly ${VALIDATION_RULES.SEAL_CODE_LENGTH} digits`;
    }
    if (!/^\d+$/.test(seal1)) {
      return 'Seal code must contain only digits';
    }
    if (seal1 !== seal2) {
      return 'Seal codes do not match';
    }

    // Date/time validation
    const scheduled = new Date(`${date}T${time}`);
    if (Number.isNaN(scheduled.getTime())) {
      return 'Invalid date or time';
    }
    if (scheduled.getTime() < Date.now()) {
      return 'Choose a future date & time';
    }

    return null;
  }, [recipientName, recipientPhone, recipientEmail, isSms, mode, messageText, fileInfo, seal1, seal2, date, time]);

  // ===========================================================================
  // LOCK CREATION
  // ===========================================================================

  const handleLock = useCallback(async () => {
    if (!sessionToken) {
      setError('Session required');
      return;
    }

    setError(null);
    setSuccess(null);

    const validationError = validateForm();
    if (validationError) {
      setError(validationError);
      logger.warn('Form validation failed', { error: validationError });
      return;
    }

    setLoading(true);

    try {
      const scheduled = new Date(`${date}T${time}`);

      logger.info('Sealing Guardian delivery', {
        mode,
        recipientName,
        scheduledFor: scheduled.toISOString(),
      });

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
      setSuccess('Guardian delivery sealed successfully!');
      logger.info('Guardian delivery sealed successfully');
      await refreshUser();
    } catch (e: any) {
      const categorized = categorizeError(e);
      logger.error('Guardian seal failed', categorized);

      // Show payment modal for payment-related errors
      if (categorized.type === 'payment') {
        setShowPaymentModal(true);
      }

      setError(categorized.message);
    } finally {
      setLoading(false);
    }
  }, [sessionToken, validateForm, mode, fileInfo, messageText, recipientName, recipientEmail, recipientPhone, isSms, date, time, seal1, refreshUser]);

  // ===========================================================================
  // RENDER: WARNING SCREEN
  // ===========================================================================

  if (step === 'warning') {
    return (
      <div className="mx-auto max-w-2xl p-6 fade-in">
        <div className="panel bg-[#111b21] rounded-2xl p-8 border border-yellow-900/40">
          <div className="text-5xl mb-4" role="img" aria-label="Shield emoji">🛡️</div>
          <h2 className="text-2xl font-bold text-[#e9edef]">Guardian</h2>
          <p className="text-sm text-[#8696a0] mt-2">
            A guaranteed, tamper-proof delivery that cannot be stopped once sealed.
          </p>

          <div
            className="mt-6 bg-yellow-900/20 border border-yellow-900/50 rounded-xl p-4 text-sm text-yellow-200 space-y-2"
            role="alert"
          >
            <p className="font-bold">⚠️ Irreversible after 24 hours</p>
            <p>
              You may cancel within the first <strong>24 hours</strong>. After that, the delivery is
              <strong> permanently sealed</strong> and <strong>cannot be cancelled or stopped by anyone</strong> —
              even if this app is deleted or this device is destroyed.
            </p>
          </div>

          <label className="flex items-start gap-3 mt-6 cursor-pointer select-none">
            <input
              type="checkbox"
              checked={acknowledged}
              onChange={(e) => setAcknowledged(e.target.checked)}
              className="mt-0.5 w-4 h-4 rounded bg-[#202c33] text-[#00a884] focus:ring-[#00a884]"
              aria-label="Acknowledge irreversibility warning"
            />
            <span className="text-sm text-[#e9edef]">
              I understand that after 24 hours this delivery becomes irreversible and will reach its recipient no matter what.
            </span>
          </label>

          <button
            onClick={() => setStep('compose')}
            disabled={!acknowledged}
            className="btn-primary w-full mt-6 py-3 rounded-xl bg-[#00a884] hover:bg-[#06cf9c] text-white font-bold transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
            aria-label="Proceed to Guardian compose screen"
          >
            Proceed to Guardian
          </button>
        </div>
      </div>
    );
  }

  // ===========================================================================
  // RENDER: LOCKED SCREEN
  // ===========================================================================

  if (step === 'locked') {
    return (
      <div className="mx-auto max-w-2xl p-6 fade-in">
        <div className="panel bg-[#111b21] rounded-2xl p-10 text-center border border-[#00a884]/40">
          <div className="text-6xl mb-4" role="img" aria-label="Lock emoji">🔒</div>
          <h2 className="text-2xl font-bold text-[#e9edef]">Sealed in the Vault</h2>
          <p className="text-sm text-[#8696a0] mt-3">
            Your Guardian delivery is locked. You can cancel within 24 hours.
            After that, it is <strong className="text-[#00a884]">irreversible</strong> and will be delivered no matter what.
          </p>
          <button
            onClick={() => setStep('warning')}
            className="btn-secondary mt-6 px-6 py-2 rounded-xl bg-[#2a3942] text-[#e9edef] hover:bg-[#3a4952] transition-colors"
            aria-label="Create another Guardian delivery"
          >
            Create Another
          </button>
        </div>
      </div>
    );
  }

  // ===========================================================================
  // RENDER: COMPOSE SCREEN
  // ===========================================================================

  return (
    <div className="mx-auto max-w-2xl p-6 space-y-6 fade-in">
      <div className="panel bg-[#111b21] rounded-2xl p-6">
        <h2 className="text-xl font-bold text-[#e9edef] mb-4">🛡️ Guardian</h2>

        {error && <ErrorDisplay error={error} onDismiss={() => setError(null)} />}
        {success && (
          <div
            className="bg-[#00a884]/10 border border-[#00a884]/30 text-[#06cf9c] p-4 rounded-xl text-sm mb-4"
            role="status"
            aria-live="polite"
          >
            ✅ {success}
          </div>
        )}

        {/* Content mode tabs */}
        <div className="flex bg-[#202c33] p-1 rounded-xl mb-6" role="tablist">
          {(['text', 'file', 'sms'] as ContentMode[]).map((m) => (
            <button
              key={m}
              onClick={() => setMode(m)}
              className={`flex-1 py-2 rounded-lg text-sm font-medium capitalize transition-colors ${
                mode === m ? 'bg-[#2a3942] text-[#e9edef]' : 'text-[#8696a0] hover:text-[#e9edef]'
              }`}
              role="tab"
              aria-selected={mode === m}
              aria-label={`${m === 'text' ? 'Typed message' : m === 'file' ? 'File attachment' : 'SMS message'} mode`}
            >
              {m === 'text' ? 'Typed' : m === 'file' ? 'File' : 'SMS'}
            </button>
          ))}
        </div>

        {/* Content input */}
        {mode === 'text' && (
          <div>
            <label htmlFor="message-text" className="label text-sm text-[#8696a0] block mb-2">
              Message
            </label>
            <textarea
              id="message-text"
              rows={5}
              value={messageText}
              onChange={(e) => setMessageText(e.target.value)}
              className="input w-full bg-[#202c33] text-[#e9edef] p-3 rounded-xl outline-none focus:ring-2 focus:ring-[#00a884] resize-none"
              placeholder="The message that must be delivered, no matter what..."
              maxLength={VALIDATION_RULES.MAX_MESSAGE_LENGTH}
              aria-label="Message text"
            />
            <p className="text-xs text-[#8696a0] mt-1">
              {messageText.length}/{VALIDATION_RULES.MAX_MESSAGE_LENGTH} characters
            </p>
          </div>
        )}

        {mode === 'file' && (
          <div className="panel-2 bg-[#202c33] rounded-xl p-4 flex items-center justify-between gap-4">
            <div className="min-w-0 flex-1">
              {fileInfo ? (
                <div>
                  <p className="text-[#e9edef] truncate font-medium">{fileInfo.file_name}</p>
                  <p className="text-xs text-[#8696a0]">{formatFileSize(fileInfo.file_size)}</p>
                </div>
              ) : (
                <p className="text-sm text-[#8696a0]">No file selected.</p>
              )}
            </div>
            <button
              onClick={handlePickFile}
              disabled={uploading}
              className="btn-secondary px-3 py-2 rounded-lg bg-[#2a3942] text-[#e9edef] text-sm hover:bg-[#3a4952] transition-colors disabled:opacity-50"
              aria-label={fileInfo ? 'Replace file' : 'Choose file'}
            >
              {uploading ? 'Uploading...' : fileInfo ? 'Replace' : 'Choose File'}
            </button>
          </div>
        )}

        {mode === 'sms' && (
          <div>
            <label htmlFor="sms-text" className="label text-sm text-[#8696a0] block mb-2">
              SMS Message
            </label>
            <textarea
              id="sms-text"
              rows={4}
              maxLength={VALIDATION_RULES.MAX_SMS_LENGTH}
              value={messageText}
              onChange={(e) => setMessageText(e.target.value)}
              className="input w-full bg-[#202c33] text-[#e9edef] p-3 rounded-xl outline-none focus:ring-2 focus:ring-[#00a884] resize-none"
              placeholder="SMS message (160 chars)..."
              aria-label="SMS message"
            />
            <p className="text-xs text-[#8696a0] mt-1">
              {messageText.length}/{VALIDATION_RULES.MAX_SMS_LENGTH} characters
            </p>
          </div>
        )}

        {/* Recipient */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-6">
          <div>
            <label htmlFor="recipient-name" className="label text-sm text-[#8696a0] block mb-2">
              Recipient name
            </label>
            <input
              id="recipient-name"
              value={recipientName}
              onChange={(e) => setRecipientName(e.target.value)}
              className="input w-full bg-[#202c33] text-[#e9edef] p-3 rounded-xl focus:ring-2 focus:ring-[#00a884] transition-all"
              placeholder="Jane Doe"
              maxLength={VALIDATION_RULES.MAX_RECIPIENT_NAME_LENGTH}
              aria-label="Recipient name"
            />
          </div>
          <div>
            <label htmlFor="recipient-contact" className="label text-sm text-[#8696a0] block mb-2">
              {isSms ? 'Phone (Kenya)' : 'Email'}
            </label>
            <input
              id="recipient-contact"
              value={isSms ? recipientPhone : recipientEmail}
              onChange={(e) =>
                isSms ? setRecipientPhone(e.target.value) : setRecipientEmail(e.target.value)
              }
              className="input w-full bg-[#202c33] text-[#e9edef] p-3 rounded-xl focus:ring-2 focus:ring-[#00a884] transition-all"
              placeholder={isSms ? '+254712345678' : 'recipient@example.com'}
              maxLength={isSms ? undefined : VALIDATION_RULES.MAX_EMAIL_LENGTH}
              aria-label={isSms ? 'Recipient phone number' : 'Recipient email'}
            />
          </div>
        </div>

        {/* Calendar scheduling */}
        <div className="mt-6">
          <label className="label text-sm text-[#8696a0] block mb-2">Delivery date & time</label>
          <div className="flex flex-wrap gap-2 mb-3">
            {TIME_PRESETS.map((p) => (
              <button
                key={p.label}
                onClick={() => applyPreset(p.ms)}
                className="px-3 py-1.5 rounded-lg bg-[#202c33] text-[#8696a0] text-xs hover:bg-[#2a3942] hover:text-[#e9edef] transition-colors"
                aria-label={`Set delivery time to ${p.label} from now`}
              >
                {p.label}
              </button>
            ))}
          </div>
          <div className="grid grid-cols-2 gap-4">
            <input
              type="date"
              value={date}
              min={toLocalDate(new Date())}
              onChange={(e) => setDate(e.target.value)}
              className="input bg-[#202c33] text-[#e9edef] p-3 rounded-xl focus:ring-2 focus:ring-[#00a884] transition-all"
              aria-label="Delivery date"
            />
            <input
              type="time"
              value={time}
              onChange={(e) => setTime(e.target.value)}
              className="input bg-[#202c33] text-[#e9edef] p-3 rounded-xl focus:ring-2 focus:ring-[#00a884] transition-all"
              aria-label="Delivery time"
            />
          </div>
        </div>

        {/* Seal */}
        <div className="mt-6">
          <label className="label text-sm text-[#8696a0] block mb-2">
            6-digit seal code
          </label>
          <div className="grid grid-cols-2 gap-4">
            <input
              inputMode="numeric"
              maxLength={VALIDATION_RULES.SEAL_CODE_LENGTH}
              value={seal1}
              onChange={(e) => setSeal1(e.target.value.replace(/\D/g, ''))}
              className="input bg-[#202c33] text-[#e9edef] p-3 rounded-xl tracking-widest text-center focus:ring-2 focus:ring-[#00a884] transition-all"
              placeholder="••••••"
              aria-label="Seal code"
            />
            <input
              inputMode="numeric"
              maxLength={VALIDATION_RULES.SEAL_CODE_LENGTH}
              value={seal2}
              onChange={(e) => setSeal2(e.target.value.replace(/\D/g, ''))}
              className="input bg-[#202c33] text-[#e9edef] p-3 rounded-xl tracking-widest text-center focus:ring-2 focus:ring-[#00a884] transition-all"
              placeholder="Confirm"
              aria-label="Confirm seal code"
            />
          </div>
          <p className="text-xs text-[#8696a0] mt-2">
            This seals the delivery. After 24 hours, nothing can stop it.
          </p>
        </div>

        <button
          onClick={handleLock}
          disabled={loading || uploading}
          className="btn-primary w-full mt-6 py-3 rounded-xl bg-[#00a884] hover:bg-[#06cf9c] text-white font-bold transition-colors disabled:opacity-50"
          aria-label="Seal Guardian delivery"
        >
          {loading ? 'Sealing...' : '🔒 Seal Guardian Delivery'}
        </button>
      </div>

      {/* Guardian Locks List */}
      {locks.length > 0 && (
        <div className="panel bg-[#111b21] rounded-2xl p-6">
          <h3 className="text-sm font-bold text-[#e9edef] mb-4">Your Guardian Locks</h3>
          <div className="space-y-2">
            {locks.map((lock) => (
              <LockCard key={lock.id} lock={lock} onCancel={handleCancelLock} />
            ))}
          </div>
        </div>
      )}

      {showPaymentModal && (
        <PaymentModal
          isOpen
          onClose={() => setShowPaymentModal(false)}
          onSuccess={() => {
            setShowPaymentModal(false);
            refreshUser();
          }}
        />
      )}
    </div>
  );
};

export default memo(GuardianView);