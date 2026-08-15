/**
 * Guardian View — Irrevocable Delivery Vault (Production-Grade)
 *
 * SECURITY FEATURES:
 * - 24-hour cooling-off period (cancellable window)
 * - 6-digit seal code confirmation
 * - Irreversible after cooling-off expires
 * - Structured error handling with correlation IDs
 * - Field-level validation
 * - Accessible confirmation dialogs
 *
 * @version 2.0.0
 * @status PRODUCTION
 */

import React, { useState, useEffect, useCallback, useMemo, memo } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { useAppContext } from '../context/AppContext';
import {
  api,
  ApiError,
  ValidationError,
  AuthError,
  StorageError,
  NetworkError,
  PaymentError,
  errorMessage,
} from '../services/api';
import type { GuardianLock } from '../services/api';
import type { UploadResult } from '../types';
import PaymentModal from './PaymentModal';

// =============================================================================
// TYPES & INTERFACES
// =============================================================================

type Step = 'warning' | 'compose' | 'locked';
type ContentMode = 'file' | 'text' | 'sms';
type DeliveryChannel = 'sms' | 'email';

interface UploadInfo {
  file_key: string;
  file_name: string;
  file_size: number;
  file_type?: string | null;
}

interface FormErrors {
  recipientName?: string;
  recipientContact?: string;
  message?: string;
  seal?: string;
  schedule?: string;
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
  EMAIL_REGEX: /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/,
  KENYA_PHONE_REGEX: /^254(7|1)\d{8}$/,
  MAX_FILE_SIZE: 50 * 1024 * 1024, // 50MB
  ALLOWED_FILE_TYPES: [
    'application/pdf',
    'image/jpeg',
    'image/png',
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

const logger = {
  info: (msg: string, data?: Record<string, unknown>) => {
    console.log(`[GuardianView] ${msg}`, data || '');
  },
  error: (msg: string, error?: unknown) => {
    console.error(`[GuardianView] ${msg}`, error || '');
  },
  warn: (msg: string, data?: Record<string, unknown>) => {
    console.warn(`[GuardianView] ${msg}`, data || '');
  },
};

const toLocalDate = (d: Date): string => {
  const p = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}`;
};

const toLocalTime = (d: Date): string => {
  const p = (n: number) => String(n).padStart(2, '0');
  return `${p(d.getHours())}:${p(d.getMinutes())}`;
};

function isValidEmail(email: string): boolean {
  return VALIDATION_RULES.EMAIL_REGEX.test(email.trim().toLowerCase());
}

function isValidKenyaPhone(phone: string): boolean {
  const digits = phone.replace(/\D/g, '');
  const normalized = digits.startsWith('0') ? `254${digits.slice(1)}` : digits;
  return VALIDATION_RULES.KENYA_PHONE_REGEX.test(normalized);
}

function formatFileSize(bytes: number): string {
  if (bytes === 0) return '0 Bytes';
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return Math.round((bytes / Math.pow(k, i)) * 100) / 100 + ' ' + sizes[i];
}

function isLockCancellable(lock: GuardianLock): boolean {
  return lock.status === 'pending' && new Date(lock.cooling_off_until).getTime() > Date.now();
}

/**
 * Map content mode to backend channel
 * - 'file' or 'text' → 'email' (delivered via email with claim link)
 * - 'sms' → 'sms' (delivered via SMS with claim link)
 */
function modeToChannel(mode: ContentMode): DeliveryChannel {
  return mode === 'sms' ? 'sms' : 'email';
}

// =============================================================================
// SUB-COMPONENTS
// =============================================================================

const ErrorDisplay = memo(
  ({ error, onDismiss }: { error: ApiError | string; onDismiss?: () => void }) => {
    const isErrorObject = error instanceof ApiError;
    const message = isErrorObject ? error.toUserMessage() : errorMessage(error);

    const getErrorType = () => {
      if (error instanceof ValidationError) return 'validation';
      if (error instanceof AuthError) return 'auth';
      if (error instanceof StorageError) return 'storage';
      if (error instanceof NetworkError) return 'network';
      if (error instanceof PaymentError) return 'payment';
      return 'unknown';
    };

    const errorType = isErrorObject ? getErrorType() : 'unknown';
    const correlationId = isErrorObject ? error.correlationId : undefined;

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
        className={`p-4 rounded-xl border ${colorMap[errorType]} mb-4 flex items-start gap-3`}
      >
        <span className="text-xl">{iconMap[errorType]}</span>
        <div className="flex-1 min-w-0">
          <p className="text-sm font-medium break-words">{message}</p>
          {correlationId && (
            <p className="text-xs opacity-70 mt-1 font-mono">
              Support ID: {correlationId}
            </p>
          )}
        </div>
        {onDismiss && (
          <button
            onClick={onDismiss}
            className="text-sm opacity-60 hover:opacity-100 transition-opacity shrink-0"
            aria-label="Dismiss error"
          >
            ✕
          </button>
        )}
      </div>
    );
  }
);

const LockCard = memo(
  ({ lock, onCancel }: { lock: GuardianLock; onCancel: (id: string) => void }) => {
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
          <p className={`text-xs mt-0.5 font-medium ${statusColor}`}>{statusText}</p>
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
  }
);

const ConfirmDialog = memo(
  ({
    isOpen,
    title,
    message,
    confirmText,
    cancelText,
    onConfirm,
    onCancel,
    isDestructive = false,
  }: {
    isOpen: boolean;
    title: string;
    message: string;
    confirmText: string;
    cancelText: string;
    onConfirm: () => void;
    onCancel: () => void;
    isDestructive?: boolean;
  }) => {
    if (!isOpen) return null;

    return (
      <div
        className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4"
        role="dialog"
        aria-modal="true"
        aria-labelledby="dialog-title"
      >
        <div className="panel bg-[#111b21] rounded-2xl p-6 max-w-md w-full">
          <h3 id="dialog-title" className="text-lg font-bold text-[#e9edef] mb-2">
            {title}
          </h3>
          <p className="text-sm text-[#8696a0] mb-6">{message}</p>
          <div className="flex gap-3">
            <button
              onClick={onCancel}
              className="btn-secondary flex-1 py-2 rounded-lg bg-[#2a3942] text-[#e9edef] hover:bg-[#3a4952] transition-colors"
            >
              {cancelText}
            </button>
            <button
              onClick={onConfirm}
              className={`btn-primary flex-1 py-2 rounded-lg text-white transition-colors ${
                isDestructive
                  ? 'bg-red-600 hover:bg-red-700'
                  : 'bg-[#00a884] hover:bg-[#06cf9c]'
              }`}
            >
              {confirmText}
            </button>
          </div>
        </div>
      </div>
    );
  }
);

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
  const [error, setError] = useState<ApiError | string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [showPaymentModal, setShowPaymentModal] = useState(false);
  const [formErrors, setFormErrors] = useState<FormErrors>({});

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

  // Confirmation dialog
  const [confirmDialog, setConfirmDialog] = useState<{
    isOpen: boolean;
    title: string;
    message: string;
    onConfirm: () => void;
    isDestructive?: boolean;
  } | null>(null);

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
    } catch (e) {
      const apiError = e instanceof ApiError ? e : new ApiError(errorMessage(e));
      logger.error('Failed to load locks', apiError);
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
      setError(new ValidationError('Session required to upload files'));
      return;
    }

    setError(null);
    setSuccess(null);
    setUploading(true);

    try {
      logger.info('Opening file picker...');
      const raw = await invoke<UploadResult | null>('pick_and_upload_file', { sessionToken });

      if (!raw) {
        logger.warn('File picker cancelled or no file selected');
        return;
      }

      if (!raw.file_key) {
        throw new ValidationError('Upload failed: missing file key');
      }

      // Validate file size
      if (raw.file_size > VALIDATION_RULES.MAX_FILE_SIZE) {
        throw new StorageError(
          `File too large (${formatFileSize(raw.file_size)}). Maximum size is ${formatFileSize(
            VALIDATION_RULES.MAX_FILE_SIZE
          )}`
        );
      }

      // Validate file type
      if (raw.file_type && !VALIDATION_RULES.ALLOWED_FILE_TYPES.includes(raw.file_type)) {
        throw new ValidationError('File type not allowed. Supported: PDF, JPEG, PNG, DOCX');
      }

      const uploadInfo: UploadInfo = {
        file_key: raw.file_key,
        file_name: raw.file_name,
        file_size: raw.file_size,
        file_type: raw.file_type,
      };

      setFileInfo(uploadInfo);
      setSuccess(`File uploaded: ${raw.file_name} (${formatFileSize(raw.file_size)})`);
      logger.info('File uploaded successfully', { ...uploadInfo });
    } catch (e) {
      const msg = errorMessage(e).toLowerCase();
      // Don't show error if user cancelled
      if (!msg.includes('cancel')) {
        const apiError = e instanceof ApiError ? e : new ApiError(errorMessage(e));
        logger.error('File upload failed', apiError);
        setError(apiError);
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

  const handleCancelLock = useCallback(
    (id: string) => {
      setConfirmDialog({
        isOpen: true,
        title: 'Cancel Guardian Delivery?',
        message:
          'This will cancel the delivery. Only possible within the 24-hour cooling-off window. This action cannot be undone.',
        onConfirm: async () => {
          setConfirmDialog(null);
          if (!sessionToken) {
            setError(new ValidationError('Session required'));
            return;
          }

          setError(null);

          try {
            logger.info('Cancelling Guardian lock', { lockId: id });
            await api.cancelGuardianDelivery(sessionToken, id);
            setSuccess('Guardian delivery cancelled successfully.');
            logger.info('Lock cancelled successfully', { lockId: id });
            await loadLocks();
          } catch (e) {
            const apiError = e instanceof ApiError ? e : new ApiError(errorMessage(e));
            logger.error('Lock cancellation failed', apiError);
            setError(apiError);
          }
        },
        isDestructive: true,
      });
    },
    [sessionToken, loadLocks]
  );

  // ===========================================================================
  // FORM VALIDATION
  // ===========================================================================

  const validateForm = useCallback((): boolean => {
    const errors: FormErrors = {};

    // Recipient name validation
    if (!recipientName.trim()) {
      errors.recipientName = 'Enter the recipient name';
    } else if (recipientName.length > VALIDATION_RULES.MAX_RECIPIENT_NAME_LENGTH) {
      errors.recipientName = `Recipient name must be less than ${VALIDATION_RULES.MAX_RECIPIENT_NAME_LENGTH} characters`;
    }

    // Contact validation
    if (isSms) {
      if (!recipientPhone.trim()) {
        errors.recipientContact = 'Enter a phone number';
      } else if (!isValidKenyaPhone(recipientPhone)) {
        errors.recipientContact = 'Enter a valid Kenyan phone number (e.g., +254712345678)';
      }
    } else {
      if (!recipientEmail.trim()) {
        errors.recipientContact = 'Enter an email address';
      } else if (!isValidEmail(recipientEmail)) {
        errors.recipientContact = 'Enter a valid email address';
      } else if (recipientEmail.length > VALIDATION_RULES.MAX_EMAIL_LENGTH) {
        errors.recipientContact = `Email must be less than ${VALIDATION_RULES.MAX_EMAIL_LENGTH} characters`;
      }
    }

    // Content validation
    if (mode === 'text') {
      if (!messageText.trim()) {
        errors.message = 'Enter the message to protect';
      } else if (messageText.length > VALIDATION_RULES.MAX_MESSAGE_LENGTH) {
        errors.message = `Message must be less than ${VALIDATION_RULES.MAX_MESSAGE_LENGTH} characters`;
      }
    } else if (mode === 'file') {
      if (!fileInfo) {
        errors.message = 'Choose and upload a file first';
      }
    } else if (mode === 'sms') {
      if (!messageText.trim()) {
        errors.message = 'Enter the SMS message';
      } else if (messageText.length > VALIDATION_RULES.MAX_SMS_LENGTH) {
        errors.message = `SMS message must be less than ${VALIDATION_RULES.MAX_SMS_LENGTH} characters`;
      }
    }

    // Seal code validation
    if (!seal1) {
      errors.seal = 'Enter a seal code';
    } else if (seal1.length !== VALIDATION_RULES.SEAL_CODE_LENGTH) {
      errors.seal = `Seal code must be exactly ${VALIDATION_RULES.SEAL_CODE_LENGTH} digits`;
    } else if (!/^\d+$/.test(seal1)) {
      errors.seal = 'Seal code must contain only digits';
    } else if (seal1 !== seal2) {
      errors.seal = 'Seal codes do not match';
    }

    // Date/time validation
    const scheduled = new Date(`${date}T${time}`);
    if (Number.isNaN(scheduled.getTime())) {
      errors.schedule = 'Invalid date or time';
    } else if (scheduled.getTime() < Date.now()) {
      errors.schedule = 'Choose a future date & time';
    }

    setFormErrors(errors);
    return Object.keys(errors).length === 0;
  }, [recipientName, recipientPhone, recipientEmail, isSms, mode, messageText, fileInfo, seal1, seal2, date, time]);

  // ===========================================================================
  // LOCK CREATION
  // ===========================================================================

  const handleLock = useCallback(async () => {
    if (!sessionToken) {
      setError(new ValidationError('Session required'));
      return;
    }

    setError(null);
    setSuccess(null);

    if (!validateForm()) {
      logger.warn('Form validation failed', { ...formErrors });
      return;
    }

    setLoading(true);

    try {
      const scheduled = new Date(`${date}T${time}`);
      const channel = modeToChannel(mode);

      logger.info('Sealing Guardian delivery', {
        mode,
        channel,
        recipientName,
        scheduledFor: scheduled.toISOString(),
      });

      // Build the Guardian lock payload matching backend's expected structure
      const lockPayload = {
        channel,
        file_key: mode === 'file' ? fileInfo?.file_key ?? undefined : undefined,
        message_text: mode !== 'file' ? messageText.trim() : undefined,
        recipient_name: recipientName.trim(),
        recipient_email: isSms ? undefined : recipientEmail.trim(),
        recipient_phone: isSms ? recipientPhone.trim() : undefined,
        scheduled_for: scheduled.toISOString(),
        seal_code: seal1,
      };

      await api.lockGuardianDelivery(sessionToken, lockPayload as any);

      setStep('locked');
      setSuccess('Guardian delivery sealed successfully!');
      setFormErrors({});
      logger.info('Guardian delivery sealed successfully');
      await refreshUser();
    } catch (e) {
      const apiError = e instanceof ApiError ? e : new ApiError(errorMessage(e));
      logger.error('Guardian seal failed', apiError);

      // Show payment modal for payment-related errors
      if (apiError instanceof PaymentError) {
        setShowPaymentModal(true);
      }

      setError(apiError);
    } finally {
      setLoading(false);
    }
  }, [sessionToken, validateForm, mode, fileInfo, messageText, recipientName, recipientEmail, recipientPhone, isSms, date, time, seal1, refreshUser, formErrors]);

  // ===========================================================================
  // RENDER: WARNING SCREEN
  // ===========================================================================

  if (step === 'warning') {
    return (
      <div className="mx-auto max-w-2xl p-6 fade-in">
        <div className="panel bg-[#111b21] rounded-2xl p-8 border border-yellow-900/40">
          <div className="text-5xl mb-4" role="img" aria-label="Shield emoji">
            🛡️
          </div>
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
              You may cancel within the first <strong>24 hours</strong>. After that, the delivery is{' '}
              <strong>permanently sealed</strong> and{' '}
              <strong>cannot be cancelled or stopped by anyone</strong> — even if this app is
              deleted or this device is destroyed.
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
              I understand that after 24 hours this delivery becomes irreversible and will reach its
              recipient no matter what.
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
          <div className="text-6xl mb-4" role="img" aria-label="Lock emoji">
            🔒
          </div>
          <h2 className="text-2xl font-bold text-[#e9edef]">Sealed in the Vault</h2>
          <p className="text-sm text-[#8696a0] mt-3">
            Your Guardian delivery is locked. You can cancel within 24 hours. After that, it is{' '}
            <strong className="text-[#00a884]">irreversible</strong> and will be delivered no matter
            what.
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
              onChange={(e) => {
                setMessageText(e.target.value);
                if (formErrors.message) {
                  setFormErrors((prev) => ({ ...prev, message: undefined }));
                }
              }}
              className={`input w-full bg-[#202c33] text-[#e9edef] p-3 rounded-xl outline-none focus:ring-2 focus:ring-[#00a884] resize-none ${
                formErrors.message ? 'border-red-500' : ''
              }`}
              placeholder="The message that must be delivered, no matter what..."
              maxLength={VALIDATION_RULES.MAX_MESSAGE_LENGTH}
              aria-label="Message text"
              aria-invalid={!!formErrors.message}
              aria-describedby={formErrors.message ? 'message-error' : undefined}
            />
            <div className="flex justify-between mt-1">
              {formErrors.message ? (
                <p id="message-error" className="text-xs text-red-400" role="alert">
                  {formErrors.message}
                </p>
              ) : (
                <span />
              )}
              <p className="text-xs text-[#8696a0]">
                {messageText.length}/{VALIDATION_RULES.MAX_MESSAGE_LENGTH}
              </p>
            </div>
          </div>
        )}

        {mode === 'file' && (
          <div>
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
            {formErrors.message && (
              <p className="text-xs text-red-400 mt-1" role="alert">
                {formErrors.message}
              </p>
            )}
            <p className="text-xs text-[#8696a0] mt-2">
              Max file size: {formatFileSize(VALIDATION_RULES.MAX_FILE_SIZE)}
            </p>
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
              onChange={(e) => {
                setMessageText(e.target.value);
                if (formErrors.message) {
                  setFormErrors((prev) => ({ ...prev, message: undefined }));
                }
              }}
              className={`input w-full bg-[#202c33] text-[#e9edef] p-3 rounded-xl outline-none focus:ring-2 focus:ring-[#00a884] resize-none ${
                formErrors.message ? 'border-red-500' : ''
              }`}
              placeholder="SMS message (160 chars)..."
              aria-label="SMS message"
              aria-invalid={!!formErrors.message}
              aria-describedby={formErrors.message ? 'sms-error' : undefined}
            />
            <div className="flex justify-between mt-1">
              {formErrors.message ? (
                <p id="sms-error" className="text-xs text-red-400" role="alert">
                  {formErrors.message}
                </p>
              ) : (
                <span />
              )}
              <p className="text-xs text-[#8696a0]">
                {messageText.length}/{VALIDATION_RULES.MAX_SMS_LENGTH}
              </p>
            </div>
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
              onChange={(e) => {
                setRecipientName(e.target.value);
                if (formErrors.recipientName) {
                  setFormErrors((prev) => ({ ...prev, recipientName: undefined }));
                }
              }}
              className={`input w-full bg-[#202c33] text-[#e9edef] p-3 rounded-xl focus:ring-2 focus:ring-[#00a884] transition-all ${
                formErrors.recipientName ? 'border-red-500' : ''
              }`}
              placeholder="Jane Doe"
              maxLength={VALIDATION_RULES.MAX_RECIPIENT_NAME_LENGTH}
              aria-label="Recipient name"
              aria-invalid={!!formErrors.recipientName}
              aria-describedby={formErrors.recipientName ? 'recipient-name-error' : undefined}
            />
            {formErrors.recipientName && (
              <p id="recipient-name-error" className="text-xs text-red-400 mt-1" role="alert">
                {formErrors.recipientName}
              </p>
            )}
          </div>
          <div>
            <label htmlFor="recipient-contact" className="label text-sm text-[#8696a0] block mb-2">
              {isSms ? 'Phone (Kenya)' : 'Email'}
            </label>
            <input
              id="recipient-contact"
              value={isSms ? recipientPhone : recipientEmail}
              onChange={(e) => {
                if (isSms) {
                  setRecipientPhone(e.target.value);
                } else {
                  setRecipientEmail(e.target.value);
                }
                if (formErrors.recipientContact) {
                  setFormErrors((prev) => ({ ...prev, recipientContact: undefined }));
                }
              }}
              className={`input w-full bg-[#202c33] text-[#e9edef] p-3 rounded-xl focus:ring-2 focus:ring-[#00a884] transition-all ${
                formErrors.recipientContact ? 'border-red-500' : ''
              }`}
              placeholder={isSms ? '+254712345678' : 'recipient@example.com'}
              maxLength={isSms ? undefined : VALIDATION_RULES.MAX_EMAIL_LENGTH}
              aria-label={isSms ? 'Recipient phone number' : 'Recipient email'}
              aria-invalid={!!formErrors.recipientContact}
              aria-describedby={formErrors.recipientContact ? 'recipient-contact-error' : undefined}
            />
            {formErrors.recipientContact && (
              <p id="recipient-contact-error" className="text-xs text-red-400 mt-1" role="alert">
                {formErrors.recipientContact}
              </p>
            )}
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
              onChange={(e) => {
                setDate(e.target.value);
                if (formErrors.schedule) {
                  setFormErrors((prev) => ({ ...prev, schedule: undefined }));
                }
              }}
              className={`input bg-[#202c33] text-[#e9edef] p-3 rounded-xl focus:ring-2 focus:ring-[#00a884] transition-all ${
                formErrors.schedule ? 'border-red-500' : ''
              }`}
              aria-label="Delivery date"
              aria-invalid={!!formErrors.schedule}
            />
            <input
              type="time"
              value={time}
              onChange={(e) => {
                setTime(e.target.value);
                if (formErrors.schedule) {
                  setFormErrors((prev) => ({ ...prev, schedule: undefined }));
                }
              }}
              className={`input bg-[#202c33] text-[#e9edef] p-3 rounded-xl focus:ring-2 focus:ring-[#00a884] transition-all ${
                formErrors.schedule ? 'border-red-500' : ''
              }`}
              aria-label="Delivery time"
              aria-invalid={!!formErrors.schedule}
              aria-describedby={formErrors.schedule ? 'schedule-error' : undefined}
            />
          </div>
          {formErrors.schedule && (
            <p id="schedule-error" className="text-xs text-red-400 mt-1" role="alert">
              {formErrors.schedule}
            </p>
          )}
        </div>

        {/* Seal */}
        <div className="mt-6">
          <label className="label text-sm text-[#8696a0] block mb-2">6-digit seal code</label>
          <div className="grid grid-cols-2 gap-4">
            <input
              inputMode="numeric"
              maxLength={VALIDATION_RULES.SEAL_CODE_LENGTH}
              value={seal1}
              onChange={(e) => {
                setSeal1(e.target.value.replace(/\D/g, ''));
                if (formErrors.seal) {
                  setFormErrors((prev) => ({ ...prev, seal: undefined }));
                }
              }}
              className={`input bg-[#202c33] text-[#e9edef] p-3 rounded-xl tracking-widest text-center focus:ring-2 focus:ring-[#00a884] transition-all ${
                formErrors.seal ? 'border-red-500' : ''
              }`}
              placeholder="••••••"
              aria-label="Seal code"
              aria-invalid={!!formErrors.seal}
            />
            <input
              inputMode="numeric"
              maxLength={VALIDATION_RULES.SEAL_CODE_LENGTH}
              value={seal2}
              onChange={(e) => {
                setSeal2(e.target.value.replace(/\D/g, ''));
                if (formErrors.seal) {
                  setFormErrors((prev) => ({ ...prev, seal: undefined }));
                }
              }}
              className={`input bg-[#202c33] text-[#e9edef] p-3 rounded-xl tracking-widest text-center focus:ring-2 focus:ring-[#00a884] transition-all ${
                formErrors.seal ? 'border-red-500' : ''
              }`}
              placeholder="Confirm"
              aria-label="Confirm seal code"
              aria-invalid={!!formErrors.seal}
              aria-describedby={formErrors.seal ? 'seal-error' : undefined}
            />
          </div>
          <div className="flex justify-between mt-2">
            {formErrors.seal ? (
              <p id="seal-error" className="text-xs text-red-400" role="alert">
                {formErrors.seal}
              </p>
            ) : (
              <p className="text-xs text-[#8696a0]">
                This seals the delivery. After 24 hours, nothing can stop it.
              </p>
            )}
          </div>
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

      {/* Confirmation Dialog */}
      {confirmDialog && (
        <ConfirmDialog
          isOpen={confirmDialog.isOpen}
          title={confirmDialog.title}
          message={confirmDialog.message}
          confirmText="Confirm"
          cancelText="Cancel"
          onConfirm={confirmDialog.onConfirm}
          onCancel={() => setConfirmDialog(null)}
          isDestructive={confirmDialog.isDestructive}
        />
      )}
    </div>
  );
};

export default memo(GuardianView);