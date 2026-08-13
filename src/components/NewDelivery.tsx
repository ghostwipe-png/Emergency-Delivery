import React, { useState, useEffect, useCallback, useMemo, useRef, memo } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { LazyStore } from '@tauri-apps/plugin-store';
import { useAppContext } from '../context/AppContext';
import { api } from '../services/api';
import PaymentModal from './PaymentModal';
import type { Delivery } from '../types';

// =============================================================================
// TYPES & INTERFACES
// =============================================================================

type MainTab = 'email' | 'sms' | 'voice';
type EmailContentTab = 'file' | 'typed';
type Preset = 'now' | '1h' | '24h' | '1w' | '1m' | 'custom';
type LinkExpiry = 'none' | '24h' | '168h';
type LinkViews = 'none' | '1' | '5' | '10';
type Recurrence = 'none' | 'daily' | 'weekly' | 'monthly';

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

interface User {
  email?: string;
  name?: string;
  delivery_credits?: number;
  sms_balance?: number;
}

// =============================================================================
// CONSTANTS
// =============================================================================

const settingsStore = new LazyStore('settings.json');

const VALIDATION_RULES = {
  EMAIL_REGEX: /^[^\s@]+@[^\s@]+\.[^\s@]+$/i,
  KENYA_PHONE_REGEX: /^254(7|1)\d{8}$/,
  MAX_MESSAGE_LEN: 5000,
  MAX_SMS_LEN: 160,
  MAX_BULK_RECIPIENTS: 50,
  MAX_FILE_SIZE: 50 * 1024 * 1024, // 50MB
  MIN_PASSWORD_LENGTH: 8,
};

const PRESETS: Array<{ value: Preset; label: string }> = [
  { value: 'now', label: 'Now' },
  { value: '1h', label: '+1 hour' },
  { value: '24h', label: '+24 hours' },
  { value: '1w', label: '+1 week' },
  { value: '1m', label: '+1 month' },
  { value: 'custom', label: 'Custom' },
];

const LINK_EXPIRY_OPTIONS: Array<{ value: LinkExpiry; label: string }> = [
  { value: 'none', label: 'Never expires' },
  { value: '24h', label: 'Expires in 24 hours' },
  { value: '168h', label: 'Expires in 7 days' },
];

const LINK_VIEW_OPTIONS: Array<{ value: LinkViews; label: string }> = [
  { value: 'none', label: 'Unlimited views' },
  { value: '1', label: '1 view only' },
  { value: '5', label: '5 views max' },
  { value: '10', label: '10 views max' },
];

const RECURRENCE_OPTIONS: Array<{ value: Recurrence; label: string }> = [
  { value: 'none', label: 'Send once (No recurrence)' },
  { value: 'daily', label: 'Repeat Daily' },
  { value: 'weekly', label: 'Repeat Weekly' },
  { value: 'monthly', label: 'Repeat Monthly' },
];

// =============================================================================
// UTILITY FUNCTIONS
// =============================================================================

/**
 * Structured logger for debugging
 */
const logger = {
  info: (msg: string, data?: any) => {
    console.log(`[NewDelivery] ${msg}`, data || '');
  },
  error: (msg: string, error?: any) => {
    console.error(`[NewDelivery] ${msg}`, error || '');
  },
  warn: (msg: string, data?: any) => {
    console.warn(`[NewDelivery] ${msg}`, data || '');
  },
};

/**
 * Format date to local datetime-local input format
 */
const toLocalInput = (date: Date): string => {
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(
    date.getHours()
  )}:${pad(date.getMinutes())}`;
};

/**
 * Format bytes to human-readable string
 */
const formatBytes = (bytes: number): string => {
  if (!bytes) return '0 B';
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1048576) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1048576).toFixed(1)} MB`;
};

/**
 * Normalize phone number to Kenyan format
 */
const normalizePhone = (input: string): string => {
  let digits = input.replace(/\D/g, '');
  if (digits.startsWith('0')) digits = `254${digits.slice(1)}`;
  if (/^(7|1)\d{8}$/.test(digits)) digits = `254${digits}`;
  return digits;
};

/**
 * Validate Kenyan phone number
 */
const isValidKenyanPhone = (digits: string): boolean => 
  VALIDATION_RULES.KENYA_PHONE_REGEX.test(digits);

/**
 * Validate email format
 */
const isValidEmail = (email: string): boolean => 
  VALIDATION_RULES.EMAIL_REGEX.test(email);

/**
 * Normalize upload response from backend
 */
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
  if (msg.includes('upload') || msg.includes('file')) {
    return { type: 'upload', message: error.message || 'File upload error' };
  }
  if (msg.includes('microphone') || msg.includes('permission')) {
    return { type: 'permission', message: 'Microphone access denied. Please allow permissions.' };
  }
  
  return { type: 'unknown', message: error.message || 'An unexpected error occurred' };
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
    upload: '📁',
    permission: '🎤',
    unknown: '❌',
  };
  
  const colorMap: Record<string, string> = {
    validation: 'border-yellow-900/50 bg-yellow-900/20 text-yellow-200',
    network: 'border-blue-900/50 bg-blue-900/20 text-blue-200',
    auth: 'border-red-900/50 bg-red-900/20 text-red-200',
    payment: 'border-purple-900/50 bg-purple-900/20 text-purple-200',
    upload: 'border-orange-900/50 bg-orange-900/20 text-orange-200',
    permission: 'border-pink-900/50 bg-pink-900/20 text-pink-200',
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
 * Success notification component
 */
const SuccessNotification = memo(({
  message,
  onDone,
}: {
  message: string;
  onDone: () => void;
}) => (
  <div
    className="fixed top-4 right-4 z-50 bg-[#00a884] text-white px-4 py-3 rounded-xl shadow-lg fade-in flex items-center gap-3"
    role="status"
    aria-live="polite"
  >
    <span className="text-sm font-medium">{message}</span>
    <button
      onClick={onDone}
      className="bg-white/10 hover:bg-white/20 px-3 py-1 rounded-lg text-sm font-semibold transition-colors"
      aria-label="Close notification"
    >
      Done
    </button>
  </div>
));

// =============================================================================
// MAIN COMPONENT
// =============================================================================

const NewDelivery: React.FC<NewDeliveryProps> = ({ onDone }) => {
  const { refreshUser, sessionToken, user } = useAppContext();

  // Core state
  const [mainTab, setMainTab] = useState<MainTab>('email');
  const [contentTab, setContentTab] = useState<EmailContentTab>('typed');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [showPaymentModal, setShowPaymentModal] = useState(false);

  // Email state
  const [bulkMode, setBulkMode] = useState(false);
  const [recipientEmail, setRecipientEmail] = useState('');
  const [bulkEmails, setBulkEmails] = useState('');
  const [anonymous, setAnonymous] = useState(false);
  const [messageText, setMessageText] = useState('');
  const [fileInfo, setFileInfo] = useState<UploadInfo | null>(null);
  const [uploading, setUploading] = useState(false);

  // Password protection state
  const [enableClaimPassword, setEnableClaimPassword] = useState(false);
  const [claimPassword, setClaimPassword] = useState('');

  // Preview state
  const [showPreview, setShowPreview] = useState(false);
  const [previewUrl, setPreviewUrl] = useState<string | null>(null);
  const [previewError, setPreviewError] = useState<string | null>(null);
  const [loadingPreview, setLoadingPreview] = useState(false);

  // Scheduling state
  const [recurrence, setRecurrence] = useState<Recurrence>('none');
  const [isEmergency, setIsEmergency] = useState(false);
  const [preset, setPreset] = useState<Preset>('now');
  const [customDate, setCustomDate] = useState('');
  const [linkExpiry, setLinkExpiry] = useState<LinkExpiry>('none');
  const [linkViews, setLinkViews] = useState<LinkViews>('none');

  // SMS state
  const [phone, setPhone] = useState('');
  const [smsMessage, setSmsMessage] = useState('');
  const [smsStatus, setSmsStatus] = useState<SmsStatus | null>(null);
  const [loadingStatus, setLoadingStatus] = useState(false);

  // Voice recording state
  const [recording, setRecording] = useState(false);
  const [recordedBlob, setRecordedBlob] = useState<Blob | null>(null);
  const [audioUrl, setAudioUrl] = useState<string | null>(null);
  const [voiceRecipientName, setVoiceRecipientName] = useState('');
  const mediaRecorderRef = useRef<MediaRecorder | null>(null);
  const chunksRef = useRef<Blob[]>([]);

  // Memoized user data
  const userData = useMemo(() => user as User | null, [user]);
  const emailCredits = useMemo(() => userData?.delivery_credits ?? 0, [userData]);
  const smsCredits = useMemo(() => userData?.sms_balance ?? 0, [userData]);
  const userEmail = useMemo(() => userData?.email || '', [userData]);
  const userName = useMemo(() => userData?.name || userEmail.split('@')[0] || 'User', [userData, userEmail]);

  // SMS paywall logic
  const canSendSms = useMemo(
    () => (smsStatus?.freeRemaining ?? 0) > 0 || smsCredits > 0,
    [smsStatus, smsCredits]
  );

  // Parse bulk emails
  const parsedBulkEmails = useMemo(() => {
    if (!bulkMode) return [];
    return Array.from(
      new Set(
        bulkEmails
          .split(/[\n,;]+/)
          .map((entry) => entry.trim())
          .filter(Boolean)
      )
    );
  }, [bulkMode, bulkEmails]);

  // ===========================================================================
  // CLEANUP
  // ===========================================================================

  useEffect(() => {
    return () => {
      if (audioUrl) {
        URL.revokeObjectURL(audioUrl);
        logger.info('Cleaned up audio URL on unmount');
      }
    };
  }, [audioUrl]);

  // ===========================================================================
  // DATA LOADING
  // ===========================================================================

  const loadDefaultPreset = useCallback(async () => {
    try {
      const saved = await settingsStore.get<string>('defaultPreset');
      if (saved && ['now', '1h', '24h', '1w', '1m', 'custom'].includes(saved)) {
        setPreset(saved as Preset);
        logger.info('Loaded default preset', { preset: saved });
      }
    } catch (e) {
      logger.warn('Failed to load default preset', e);
    }
  }, []);

  const loadSmsStatus = useCallback(async () => {
    if (!sessionToken) return;

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
      logger.info('SMS status loaded', { freeRemaining, credits });
    } catch (e) {
      logger.error('Failed to load SMS status', e);
      setSmsStatus(null);
    } finally {
      setLoadingStatus(false);
    }
  }, [sessionToken]);

  useEffect(() => {
    void loadDefaultPreset();
  }, [loadDefaultPreset]);

  useEffect(() => {
    if (mainTab === 'sms' || mainTab === 'voice') {
      void loadSmsStatus();
    }
  }, [mainTab, loadSmsStatus]);

  // ===========================================================================
  // PRESET SELECTION
  // ===========================================================================

  const selectPreset = useCallback(async (value: Preset) => {
    if (value === 'custom' && !customDate) {
      setCustomDate(toLocalInput(new Date(Date.now() + 3600000)));
    }

    setPreset(value);

    try {
      await settingsStore.set('defaultPreset', value);
      await settingsStore.save();
      logger.info('Preset saved', { preset: value });
    } catch (e) {
      logger.warn('Failed to save preset', e);
    }
  }, [customDate]);

  // ===========================================================================
  // SCHEDULED DATE CALCULATION
  // ===========================================================================

  const getScheduledDate = useCallback((): Date | null => {
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
  }, [preset, customDate]);

  // ===========================================================================
  // FILE MANAGEMENT
  // ===========================================================================

  const handlePickFile = useCallback(async () => {
    if (!sessionToken) {
      setError('Session required');
      return;
    }

    setError(null);
    setUploading(true);

    try {
      logger.info('Opening file picker');
      const raw = await invoke('pick_and_upload_file', { sessionToken });
      const normalized = normalizeUpload(raw);

      if (!normalized.file_key) {
        throw new Error('Upload failed: missing file key.');
      }

      // Validate file size
      if (normalized.file_size > VALIDATION_RULES.MAX_FILE_SIZE) {
        throw new Error(
          `File too large. Maximum size is ${formatBytes(VALIDATION_RULES.MAX_FILE_SIZE)}`
        );
      }

      setFileInfo(normalized);
      logger.info('File uploaded successfully', {
        fileName: normalized.file_name,
        fileSize: normalized.file_size,
      });
    } catch (err: any) {
      const message = String(err?.message || err || '').toLowerCase();
      if (!message.includes('cancel') && !message.includes('abort')) {
        const categorized = categorizeError(err);
        logger.error('File upload failed', categorized);
        setError(categorized.message);
      }
    } finally {
      setUploading(false);
    }
  }, [sessionToken]);

  const clearFile = useCallback(() => {
    setFileInfo(null);
    setEnableClaimPassword(false);
    setClaimPassword('');
    logger.info('File cleared');
  }, []);

  // ===========================================================================
  // PREVIEW MANAGEMENT
  // ===========================================================================

  const handlePreviewFile = useCallback(async () => {
    if (!fileInfo?.file_key || !sessionToken) return;

    setShowPreview(true);
    setLoadingPreview(true);
    setPreviewError(null);
    setPreviewUrl(null);

    try {
      logger.info('Loading file preview', { fileKey: fileInfo.file_key });
      const bytes = await invoke<Uint8Array | number[]>('preview_file', {
        sessionToken,
        fileKey: fileInfo.file_key,
      });

      const uint8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
      const blob = new Blob([uint8.slice()], {
        type: fileInfo.file_type || 'application/octet-stream',
      });
      const url = URL.createObjectURL(blob);
      setPreviewUrl(url);
      logger.info('Preview loaded successfully');
    } catch (err: any) {
      const categorized = categorizeError(err);
      logger.error('Preview failed', categorized);
      setPreviewError(categorized.message);
    } finally {
      setLoadingPreview(false);
    }
  }, [fileInfo, sessionToken]);

  const handleClosePreview = useCallback(() => {
    if (previewUrl) {
      URL.revokeObjectURL(previewUrl);
      logger.info('Preview closed and URL revoked');
    }
    setShowPreview(false);
    setPreviewUrl(null);
    setPreviewError(null);
  }, [previewUrl]);

  // ===========================================================================
  // EMAIL VALIDATION
  // ===========================================================================

  const validateEmailForm = useCallback((): string | null => {
    if (!bulkMode) {
      if (!isValidEmail(recipientEmail.trim())) {
        return 'Enter a valid recipient email address';
      }
    } else {
      if (parsedBulkEmails.length === 0) {
        return 'Enter at least one recipient email address';
      }
      if (parsedBulkEmails.length > VALIDATION_RULES.MAX_BULK_RECIPIENTS) {
        return `Bulk delivery supports up to ${VALIDATION_RULES.MAX_BULK_RECIPIENTS} recipients`;
      }
      const invalidEmail = parsedBulkEmails.find((email) => !isValidEmail(email));
      if (invalidEmail) {
        return `Invalid email address: ${invalidEmail}`;
      }
    }

    if (contentTab === 'typed') {
      if (!messageText.trim()) {
        return 'Enter a message to deliver';
      }
      if (messageText.length > VALIDATION_RULES.MAX_MESSAGE_LEN) {
        return `Typed messages are limited to ${VALIDATION_RULES.MAX_MESSAGE_LEN} characters`;
      }
    }

    if (contentTab === 'file' && !fileInfo) {
      return 'Choose and upload a file first';
    }

    if (contentTab === 'file' && enableClaimPassword && !claimPassword.trim()) {
      return 'Please enter a password or disable password protection';
    }

    if (contentTab === 'file' && enableClaimPassword && claimPassword.length < VALIDATION_RULES.MIN_PASSWORD_LENGTH) {
      return `Password must be at least ${VALIDATION_RULES.MIN_PASSWORD_LENGTH} characters`;
    }

    const scheduledDate = getScheduledDate();
    if (!scheduledDate) {
      return 'Choose a valid delivery time';
    }

    if (preset !== 'now' && scheduledDate.getTime() < Date.now() - 60000) {
      return 'Choose a future delivery time';
    }

    return null;
  }, [
    bulkMode,
    recipientEmail,
    parsedBulkEmails,
    contentTab,
    messageText,
    fileInfo,
    enableClaimPassword,
    claimPassword,
    getScheduledDate,
    preset,
  ]);

  // ===========================================================================
  // EMAIL SCHEDULING
  // ===========================================================================

  const handleScheduleEmail = useCallback(async () => {
    if (!sessionToken) {
      setError('Session required');
      return;
    }

    setError(null);
    setSuccess(null);

    const validationError = validateEmailForm();
    if (validationError) {
      setError(validationError);
      logger.warn('Email form validation failed', { error: validationError });
      return;
    }

    const scheduledDate = getScheduledDate()!;
    const linkExpiryHours = linkExpiry === 'none' ? null : linkExpiry === '24h' ? 24 : 168;
    const linkMaxViews = linkViews === 'none' ? null : Number(linkViews);

    const payload: any = {
      channel: 'email',
      recipient_email: bulkMode ? null : recipientEmail.trim(),
      recipient_emails: bulkMode ? parsedBulkEmails : null,
      recipient_phone: null,
      recipient_name: bulkMode ? 'Bulk Recipients' : recipientEmail.trim().split('@')[0] || 'Recipient',
      message_text: contentTab === 'typed' ? messageText.trim() : null,
      file_key: fileInfo?.file_key ?? null,
      scheduled_for: scheduledDate.toISOString(),
      sender_mode: anonymous ? 'anonymous' : 'identified',
      sender_name: anonymous ? '' : userName,
      sender_email: anonymous ? '' : userEmail,
      link_expires_hours: linkExpiryHours,
      link_max_views: linkMaxViews,
      claim_password: contentTab === 'file' && enableClaimPassword ? claimPassword.trim() : null,
      recurrence: recurrence === 'none' ? null : recurrence,
      is_emergency: isEmergency,
    };

    setLoading(true);

    try {
      logger.info('Scheduling email delivery', {
        bulkMode,
        recipientCount: bulkMode ? parsedBulkEmails.length : 1,
        scheduledFor: scheduledDate.toISOString(),
      });

      const created = await invoke<Delivery[]>('schedule_delivery', { sessionToken, data: payload });
      const count = Array.isArray(created) ? created.length : bulkMode ? parsedBulkEmails.length : 1;

      setSuccess(count > 1 ? `${count} deliveries scheduled successfully.` : 'Delivery scheduled successfully.');
      
      // Reset form
      setRecipientEmail('');
      setBulkEmails('');
      setMessageText('');
      setFileInfo(null);
      setEnableClaimPassword(false);
      setClaimPassword('');
      setRecurrence('none');
      setIsEmergency(false);

      await refreshUser();
      logger.info('Email scheduled successfully', { count });
    } catch (err: any) {
      const categorized = categorizeError(err);
      logger.error('Email scheduling failed', categorized);

      if (categorized.type === 'payment') {
        setShowPaymentModal(true);
      }

      setError(categorized.message);
    } finally {
      setLoading(false);
    }
  }, [
    sessionToken,
    validateEmailForm,
    getScheduledDate,
    linkExpiry,
    linkViews,
    bulkMode,
    recipientEmail,
    parsedBulkEmails,
    contentTab,
    messageText,
    fileInfo,
    anonymous,
    userName,
    userEmail,
    enableClaimPassword,
    claimPassword,
    recurrence,
    isEmergency,
    refreshUser,
  ]);

  // ===========================================================================
  // SMS VALIDATION
  // ===========================================================================

  const validateSmsForm = useCallback((): string | null => {
    const normalized = normalizePhone(phone);

    if (!isValidKenyanPhone(normalized)) {
      return 'Enter a valid Kenyan phone number, e.g. 254712345678';
    }

    if (!smsMessage.trim()) {
      return 'Enter an SMS message';
    }

    if (smsMessage.length > VALIDATION_RULES.MAX_SMS_LEN) {
      return `SMS messages are limited to ${VALIDATION_RULES.MAX_SMS_LEN} characters`;
    }

    return null;
  }, [phone, smsMessage]);

  // ===========================================================================
  // SMS SENDING
  // ===========================================================================

  const handleSendSms = useCallback(async () => {
    if (!sessionToken) {
      setError('Session required');
      return;
    }

    setError(null);
    setSuccess(null);

    const validationError = validateSmsForm();
    if (validationError) {
      setError(validationError);
      logger.warn('SMS form validation failed', { error: validationError });
      return;
    }

    const normalized = normalizePhone(phone);

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
      logger.info('Sending SMS', { phone: normalized });

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
      logger.info('SMS sent successfully');
    } catch (err: any) {
      const categorized = categorizeError(err);
      logger.error('SMS sending failed', categorized);

      if (categorized.type === 'payment') {
        setShowPaymentModal(true);
      }

      setError(categorized.message);
    } finally {
      setLoading(false);
    }
  }, [sessionToken, validateSmsForm, phone, smsMessage, refreshUser, loadSmsStatus]);

  // ===========================================================================
  // VOICE RECORDING
  // ===========================================================================

  const startRecording = useCallback(async () => {
    setError(null);

    try {
      logger.info('Starting voice recording');
      const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
      const recorder = new MediaRecorder(stream);
      chunksRef.current = [];

      recorder.ondataavailable = (e) => {
        if (e.data.size > 0) chunksRef.current.push(e.data);
      };

      recorder.onstop = () => {
        const blob = new Blob(chunksRef.current, { type: 'audio/webm' });
        setRecordedBlob(blob);
        if (audioUrl) URL.revokeObjectURL(audioUrl);
        setAudioUrl(URL.createObjectURL(blob));
        stream.getTracks().forEach((t) => t.stop());
        logger.info('Voice recording stopped', { size: blob.size });
      };

      mediaRecorderRef.current = recorder;
      recorder.start();
      setRecording(true);
    } catch (err) {
      const categorized = categorizeError(err);
      logger.error('Failed to start recording', categorized);
      setError(categorized.message);
    }
  }, [audioUrl]);

  const stopRecording = useCallback(() => {
    if (mediaRecorderRef.current && mediaRecorderRef.current.state !== 'inactive') {
      mediaRecorderRef.current.stop();
    }
    setRecording(false);
  }, []);

  const discardRecording = useCallback(() => {
    if (audioUrl) URL.revokeObjectURL(audioUrl);
    setRecordedBlob(null);
    setAudioUrl(null);
    chunksRef.current = [];
    logger.info('Recording discarded');
  }, [audioUrl]);

  // ===========================================================================
  // VOICE SCHEDULING
  // ===========================================================================

  const handleScheduleVoice = useCallback(async () => {
    if (!sessionToken) {
      setError('Session required');
      return;
    }

    setError(null);
    setSuccess(null);

    if (!recordedBlob) {
      setError('Please record a voice message first');
      return;
    }

    const normalized = normalizePhone(phone);
    if (!isValidKenyanPhone(normalized)) {
      setError('Enter a valid Kenyan phone number, e.g. 254712345678');
      return;
    }

    if (!voiceRecipientName.trim()) {
      setError('Enter the recipient name');
      return;
    }

    const scheduledDate = getScheduledDate();
    if (!scheduledDate) {
      setError('Choose a valid delivery time');
      return;
    }

    if (!canSendSms) {
      setShowPaymentModal(true);
      setError('Insufficient SMS credits to schedule voice delivery');
      return;
    }

    setLoading(true);

    try {
      logger.info('Scheduling voice delivery', { phone: normalized });

      const arrayBuffer = await recordedBlob.arrayBuffer();
      const bytes = new Uint8Array(arrayBuffer);

      const uploadResult = await invoke<UploadInfo>('upload_file', {
        sessionToken,
        fileName: `voice-${Date.now()}.webm`,
        fileBytes: bytes,
      });

      const info = normalizeUpload(uploadResult);
      if (!info.file_key) {
        throw new Error('Upload failed: missing file key.');
      }

      await api.scheduleVoiceDelivery(
        sessionToken,
        info.file_key,
        normalized,
        voiceRecipientName.trim(),
        scheduledDate.toISOString(),
        userName || null
      );

      setSuccess('Voice delivery scheduled! The recipient will receive a secure SMS link at the chosen time.');

      discardRecording();
      setPhone('');
      setVoiceRecipientName('');
      await refreshUser();
      logger.info('Voice delivery scheduled successfully');
    } catch (err: any) {
      const categorized = categorizeError(err);
      logger.error('Voice scheduling failed', categorized);

      if (categorized.type === 'payment') {
        setShowPaymentModal(true);
      }

      setError(categorized.message);
    } finally {
      setLoading(false);
    }
  }, [sessionToken, recordedBlob, phone, voiceRecipientName, getScheduledDate, canSendSms, userName, discardRecording, refreshUser]);

  // ===========================================================================
  // PAYMENT HANDLING
  // ===========================================================================

  const handlePaymentSuccess = useCallback(async () => {
    setShowPaymentModal(false);
    setError(null);

    try {
      await refreshUser();
      await loadSmsStatus();
      logger.info('Payment successful, user data refreshed');
    } catch (e) {
      logger.warn('Failed to refresh after payment', e);
    }
  }, [refreshUser, loadSmsStatus]);

  const paymentModalProps = useMemo(
    () => ({
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
    }),
    [showPaymentModal, handlePaymentSuccess]
  );

  // ===========================================================================
  // RENDER
  // ===========================================================================

  return (
    <>
      {success && (
        <SuccessNotification
          message={success}
          onDone={() => {
            setSuccess(null);
            onDone?.();
          }}
        />
      )}

      <div className="panel bg-[#111b21] rounded-2xl p-6 fade-in">
        <h2 className="text-xl font-bold text-[#e9edef] mb-4">New Delivery</h2>

        {error && <ErrorDisplay error={error} onDismiss={() => setError(null)} />}

        {/* Main Channel Tabs */}
        <div className="flex bg-[#202c33] p-1 rounded-xl mb-6" role="tablist">
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
            role="tab"
            aria-selected={mainTab === 'email'}
            aria-label="Email delivery"
          >
            ✉️ Email
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
            role="tab"
            aria-selected={mainTab === 'sms'}
            aria-label="SMS delivery"
          >
            📱 SMS
          </button>
          <button
            onClick={() => {
              setMainTab('voice');
              setError(null);
              setSuccess(null);
            }}
            className={`flex-1 py-2 rounded-lg font-medium transition-colors ${
              mainTab === 'voice'
                ? 'bg-[#2a3942] text-[#e9edef]'
                : 'text-[#8696a0] hover:text-[#e9edef]'
            }`}
            role="tab"
            aria-selected={mainTab === 'voice'}
            aria-label="Voice delivery"
          >
            🎙️ Voice
          </button>
        </div>

        {mainTab === 'email' ? (
          <div className="space-y-6">
            {/* Email Content Tabs */}
            <div className="flex bg-[#202c33] p-1 rounded-xl" role="tablist">
              <button
                onClick={() => setContentTab('typed')}
                className={`flex-1 py-2 rounded-lg text-sm font-medium transition-colors ${
                  contentTab === 'typed'
                    ? 'bg-[#2a3942] text-[#e9edef]'
                    : 'text-[#8696a0] hover:text-[#e9edef]'
                }`}
                role="tab"
                aria-selected={contentTab === 'typed'}
                aria-label="Typed message"
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
                role="tab"
                aria-selected={contentTab === 'file'}
                aria-label="File attachment"
              >
                File
              </button>
            </div>

            {contentTab === 'typed' ? (
              <div>
                <label htmlFor="message-text" className="label block text-sm text-[#8696a0] mb-2">
                  Secure message
                </label>
                <textarea
                  id="message-text"
                  rows={5}
                  maxLength={VALIDATION_RULES.MAX_MESSAGE_LEN}
                  value={messageText}
                  onChange={(e) => setMessageText(e.target.value)}
                  className="input w-full bg-[#202c33] text-[#e9edef] p-3 rounded-xl outline-none focus:ring-2 focus:ring-[#00a884] transition-all resize-none"
                  placeholder="Type the message you want delivered securely..."
                  aria-label="Message text"
                />
                <p className="text-xs text-[#8696a0] mt-1 text-right">
                  {messageText.length}/{VALIDATION_RULES.MAX_MESSAGE_LEN}
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
                          <button
                            onClick={handlePreviewFile}
                            className="btn-ghost px-3 py-2 rounded-lg bg-[#111b21] text-[#00a884] hover:text-[#06cf9c] transition-colors text-sm font-medium"
                            aria-label="Preview file"
                          >
                            Preview
                          </button>
                          <button
                            onClick={clearFile}
                            className="btn-ghost px-3 py-2 rounded-lg bg-[#111b21] text-[#8696a0] hover:text-[#e9edef] transition-colors text-sm"
                            aria-label="Remove file"
                          >
                            Remove
                          </button>
                        </>
                      )}
                      <button
                        onClick={handlePickFile}
                        disabled={uploading}
                        className="btn-secondary px-3 py-2 rounded-lg bg-[#2a3942] text-[#e9edef] hover:bg-[#00a884] transition-colors text-sm font-medium disabled:opacity-50"
                        aria-label={fileInfo ? 'Replace file' : 'Choose file'}
                      >
                        {uploading ? 'Uploading...' : fileInfo ? 'Replace File' : 'Choose File'}
                      </button>
                    </div>
                  </div>
                </div>

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
                        aria-label="Enable password protection"
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
                        placeholder={`Enter a strong password (min ${VALIDATION_RULES.MIN_PASSWORD_LENGTH} characters)`}
                        autoComplete="new-password"
                        aria-label="Claim password"
                      />
                    )}
                  </div>
                )}
              </div>
            )}

            <div>
              <div className="flex items-center justify-between mb-2">
                <label
                  htmlFor={bulkMode ? 'bulk-emails' : 'recipient-email'}
                  className="label text-sm text-[#8696a0]"
                >
                  {bulkMode ? 'Bulk recipients' : 'Recipient email'}
                </label>
                <button
                  onClick={() => setBulkMode(!bulkMode)}
                  className="btn-ghost text-xs text-[#00a884] hover:text-[#06cf9c] transition-colors font-medium"
                  aria-label={bulkMode ? 'Switch to single recipient' : 'Switch to bulk recipients'}
                >
                  {bulkMode ? 'Switch to single recipient' : 'Switch to bulk recipients'}
                </button>
              </div>

              {bulkMode ? (
                <>
                  <textarea
                    id="bulk-emails"
                    rows={4}
                    value={bulkEmails}
                    onChange={(e) => setBulkEmails(e.target.value)}
                    className="input w-full bg-[#202c33] text-[#e9edef] p-3 rounded-xl outline-none focus:ring-2 focus:ring-[#00a884] transition-all resize-none"
                    placeholder={'one@example.com\nanother@example.com'}
                    aria-label="Bulk recipient emails"
                  />
                  <p className="text-xs text-[#8696a0] mt-1">
                    {parsedBulkEmails.length} recipient(s) parsed · max {VALIDATION_RULES.MAX_BULK_RECIPIENTS}
                  </p>
                </>
              ) : (
                <input
                  id="recipient-email"
                  type="email"
                  value={recipientEmail}
                  onChange={(e) => setRecipientEmail(e.target.value)}
                  className="input w-full bg-[#202c33] text-[#e9edef] p-3 rounded-xl outline-none focus:ring-2 focus:ring-[#00a884] transition-all"
                  placeholder="recipient@example.com"
                  aria-label="Recipient email"
                />
              )}
            </div>

            <div className="panel-2 bg-[#202c33] rounded-xl p-4">
              <label className="flex items-start space-x-3 cursor-pointer select-none">
                <input
                  type="checkbox"
                  checked={anonymous}
                  onChange={(e) => setAnonymous(e.target.checked)}
                  className="mt-0.5 w-4 h-4 rounded bg-[#111b21] text-[#00a884] focus:ring-[#00a884] focus:ring-offset-0 focus:ring-offset-[#202c33]"
                  aria-label="Send anonymously"
                />
                <div>
                  <p className="text-sm text-[#e9edef] font-medium">Send anonymously</p>
                  <p className="text-xs text-[#8696a0] mt-0.5">
                    Hide your identity from the recipient. Emergency Delivery will appear as the sender.
                  </p>
                </div>
              </label>
            </div>

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
                    aria-label={`Set delivery time to ${item.label}`}
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
                  aria-label="Custom delivery date and time"
                />
              )}
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label htmlFor="link-expiry" className="label block text-sm text-[#8696a0] mb-2">
                  Link expiry
                </label>
                <select
                  id="link-expiry"
                  value={linkExpiry}
                  onChange={(e) => setLinkExpiry(e.target.value as LinkExpiry)}
                  className="input w-full bg-[#202c33] text-[#e9edef] p-3 rounded-xl outline-none focus:ring-2 focus:ring-[#00a884] transition-all border-none"
                  aria-label="Link expiry duration"
                >
                  {LINK_EXPIRY_OPTIONS.map((option) => (
                    <option key={option.value} value={option.value}>
                      {option.label}
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label htmlFor="link-views" className="label block text-sm text-[#8696a0] mb-2">
                  Link views
                </label>
                <select
                  id="link-views"
                  value={linkViews}
                  onChange={(e) => setLinkViews(e.target.value as LinkViews)}
                  className="input w-full bg-[#202c33] text-[#e9edef] p-3 rounded-xl outline-none focus:ring-2 focus:ring-[#00a884] transition-all border-none"
                  aria-label="Maximum link views"
                >
                  {LINK_VIEW_OPTIONS.map((option) => (
                    <option key={option.value} value={option.value}>
                      {option.label}
                    </option>
                  ))}
                </select>
              </div>
            </div>

            <div>
              <label htmlFor="recurrence" className="label block text-sm text-[#8696a0] mb-2">
                Recurring delivery
              </label>
              <select
                id="recurrence"
                value={recurrence}
                onChange={(e) => setRecurrence(e.target.value as Recurrence)}
                className="input w-full bg-[#202c33] text-[#e9edef] p-3 rounded-xl outline-none focus:ring-2 focus:ring-[#00a884] transition-all border-none"
                aria-label="Recurrence pattern"
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

            <div className="panel-2 bg-[#202c33] rounded-xl p-4 border border-red-900/30">
              <label className="flex items-start space-x-3 cursor-pointer select-none">
                <input
                  type="checkbox"
                  checked={isEmergency}
                  onChange={(e) => setIsEmergency(e.target.checked)}
                  className="mt-0.5 w-4 h-4 rounded bg-[#111b21] text-red-500 focus:ring-red-500 focus:ring-offset-0 focus:ring-offset-[#202c33]"
                  aria-label="Enable emergency delivery"
                />
                <div>
                  <p className="text-sm text-[#e9edef] font-medium">🚨 Emergency Delivery (Dead Man's Switch)</p>
                  <p className="text-xs text-[#8696a0] mt-0.5">
                    If enabled, this delivery will be dispatched automatically if you fail to check in via Settings.
                  </p>
                </div>
              </label>
            </div>

            {emailCredits <= 0 && (
              <p className="text-red-400 text-xs text-center mb-2 animate-pulse font-medium" role="alert">
                ⚠️ You have 0 Email credits. Please upgrade to send.
              </p>
            )}

            <button
              onClick={handleScheduleEmail}
              disabled={loading || uploading || emailCredits <= 0}
              className="btn-primary w-full bg-[#00a884] hover:bg-[#06cf9c] text-white font-bold py-3 rounded-xl transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
              aria-label={
                loading
                  ? 'Scheduling delivery'
                  : emailCredits <= 0
                  ? 'Out of email credits'
                  : preset === 'now'
                  ? 'Send now'
                  : 'Schedule delivery'
              }
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
        ) : mainTab === 'sms' ? (
          <div className="space-y-6">
            <div>
              <label htmlFor="phone" className="label block text-sm text-[#8696a0] mb-2">
                Kenyan phone number
              </label>
              <input
                id="phone"
                type="tel"
                value={phone}
                onChange={(e) => setPhone(e.target.value)}
                className="input w-full bg-[#202c33] text-[#e9edef] p-3 rounded-xl outline-none focus:ring-2 focus:ring-[#00a884] transition-all"
                placeholder="+254712345678"
                aria-label="Recipient phone number"
              />
            </div>

            <div>
              <label htmlFor="sms-message" className="label block text-sm text-[#8696a0] mb-2">
                SMS message
              </label>
              <textarea
                id="sms-message"
                rows={4}
                maxLength={VALIDATION_RULES.MAX_SMS_LEN}
                value={smsMessage}
                onChange={(e) => setSmsMessage(e.target.value)}
                className="input w-full bg-[#202c33] text-[#e9edef] p-3 rounded-xl outline-none focus:ring-2 focus:ring-[#00a884] transition-all resize-none"
                placeholder="Type your SMS message..."
                aria-label="SMS message"
              />
              <p
                className={`text-xs mt-1 text-right ${
                  smsMessage.length >= VALIDATION_RULES.MAX_SMS_LEN ? 'text-red-400' : 'text-[#8696a0]'
                }`}
              >
                {smsMessage.length}/{VALIDATION_RULES.MAX_SMS_LEN}
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
                      aria-label="Buy SMS credits"
                    >
                      Buy Credits
                    </button>
                  </div>
                )
              ) : (
                <p className="text-[#8696a0]">Unable to load SMS status.</p>
              )}
            </div>

            {!canSendSms && !loadingStatus && (
              <p className="text-red-400 text-xs text-center mb-2 animate-pulse font-medium" role="alert">
                ⚠️ You have 0 SMS credits. Please upgrade to send.
              </p>
            )}

            <button
              onClick={handleSendSms}
              disabled={
                loading ||
                smsMessage.length === 0 ||
                smsMessage.length > VALIDATION_RULES.MAX_SMS_LEN ||
                !canSendSms
              }
              className="btn-primary w-full bg-[#00a884] hover:bg-[#06cf9c] text-white font-bold py-3 rounded-xl transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
              aria-label={
                loading
                  ? 'Sending SMS'
                  : !canSendSms
                  ? 'Out of SMS credits'
                  : 'Send SMS'
              }
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
        ) : (
          <div className="space-y-6">
            <div className="panel-2 bg-[#202c33] rounded-xl p-6 text-center space-y-4">
              <h3 className="text-lg font-bold text-[#e9edef]">Record Voice Message</h3>

              <div className="flex items-center justify-center gap-4">
                {!recording && !audioUrl && (
                  <button
                    onClick={startRecording}
                    className="w-20 h-20 mx-auto rounded-full bg-[#00a884] hover:bg-[#06cf9c] text-white text-3xl shadow-lg hover:scale-105 transition-transform"
                    aria-label="Start recording"
                  >
                    🎙️
                  </button>
                )}

                {recording && (
                  <button
                    onClick={stopRecording}
                    className="w-20 h-20 mx-auto rounded-full bg-red-500 hover:bg-red-600 text-white text-2xl shadow-lg animate-pulse"
                    aria-label="Stop recording"
                  >
                    ■
                  </button>
                )}

                {audioUrl && !recording && (
                  <button
                    onClick={discardRecording}
                    className="w-20 h-20 mx-auto rounded-full bg-red-500 hover:bg-red-600 text-white text-xl shadow-lg"
                    aria-label="Discard recording"
                  >
                    🗑️
                  </button>
                )}
              </div>

              <p className="text-sm text-[#8696a0]">
                {recording
                  ? '🔴 Recording... Tap stop when finished'
                  : audioUrl
                  ? 'Recording ready. Tap play to preview or trash to discard.'
                  : 'Tap microphone to start recording'}
              </p>

              {audioUrl && !recording && (
                <audio controls src={audioUrl} className="w-full mt-4 rounded-lg" aria-label="Voice recording preview" />
              )}

              {recordedBlob && (
                <p className="text-xs text-[#8696a0]">
                  Size: {formatBytes(recordedBlob.size)}
                </p>
              )}
            </div>

            <div>
              <label htmlFor="voice-recipient-name" className="label block text-sm text-[#8696a0] mb-2">
                Recipient name
              </label>
              <input
                id="voice-recipient-name"
                value={voiceRecipientName}
                onChange={(e) => setVoiceRecipientName(e.target.value)}
                className="input w-full bg-[#202c33] text-[#e9edef] p-3 rounded-xl outline-none focus:ring-2 focus:ring-[#00a884]"
                placeholder="e.g. Jane Doe"
                aria-label="Voice recipient name"
              />
            </div>

            <div>
              <label htmlFor="voice-phone" className="label block text-sm text-[#8696a0] mb-2">
                Kenyan phone number
              </label>
              <input
                id="voice-phone"
                type="tel"
                value={phone}
                onChange={(e) => setPhone(e.target.value)}
                className="input w-full bg-[#202c33] text-[#e9edef] p-3 rounded-xl outline-none focus:ring-2 focus:ring-[#00a884]"
                placeholder="+254712345678"
                aria-label="Voice recipient phone number"
              />
            </div>

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
                    aria-label={`Set delivery time to ${item.label}`}
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
                  className="input w-full bg-[#202c33] text-[#e9edef] p-3 rounded-xl outline-none focus:ring-2 focus:ring-[#00a884] mt-3"
                  aria-label="Custom delivery date and time"
                />
              )}
            </div>

            <div className="panel-2 bg-[#202c33] rounded-xl p-4 text-sm">
              {smsStatus ? (
                smsStatus.freeRemaining > 0 ? (
                  <p className="text-[#e9edef]">
                    Free SMS remaining:{' '}
                    <span className="text-[#00a884] font-bold">{smsStatus.freeRemaining}</span>
                    {' '}(Voice delivery uses 1 SMS credit)
                  </p>
                ) : smsStatus.credits > 0 ? (
                  <p className="text-[#e9edef]">
                    Paid SMS credits:{' '}
                    <span className="text-[#00a884] font-bold">{smsStatus.credits}</span>
                    {' '}(Voice delivery uses 1 SMS credit)
                  </p>
                ) : (
                  <div className="flex items-center justify-between gap-4">
                    <p className="text-red-400">No SMS credits remaining.</p>
                    <button
                      onClick={() => setShowPaymentModal(true)}
                      className="btn-secondary bg-[#2a3942] hover:bg-[#00a884] px-3 py-1.5 rounded-lg text-xs font-medium transition-colors"
                      aria-label="Buy SMS credits"
                    >
                      Buy Credits
                    </button>
                  </div>
                )
              ) : (
                <p className="text-[#8696a0]">Unable to load SMS status.</p>
              )}
            </div>

            {!canSendSms && (
              <p className="text-red-400 text-xs text-center mb-2 animate-pulse font-medium" role="alert">
                ⚠️ You have 0 SMS credits. Voice delivery requires 1 SMS credit.
              </p>
            )}

            <button
              onClick={handleScheduleVoice}
              disabled={loading || recording || !recordedBlob || !canSendSms}
              className="btn-primary w-full bg-[#00a884] hover:bg-[#06cf9c] text-white font-bold py-3 rounded-xl transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
              aria-label={
                loading
                  ? 'Scheduling voice delivery'
                  : !recordedBlob
                  ? 'Record a message first'
                  : !canSendSms
                  ? 'Out of SMS credits'
                  : preset === 'now'
                  ? 'Send voice now'
                  : 'Schedule voice delivery'
              }
            >
              {loading
                ? 'Scheduling...'
                : !recordedBlob
                ? 'Record a message first'
                : !canSendSms
                ? 'Out of SMS Credits'
                : preset === 'now'
                ? 'Send Voice Now (1 SMS)'
                : 'Schedule Voice Delivery (1 SMS)'}
            </button>

            <p className="text-xs text-[#8696a0] text-center">
              🔐 Your voice is encrypted before upload. The recipient receives a secure SMS link to listen.
            </p>
          </div>
        )}
      </div>

      {showPreview && (
        <div
          className="fixed inset-0 z-[60] flex items-center justify-center bg-black/80 backdrop-blur-sm p-4 fade-in"
          role="dialog"
          aria-modal="true"
          aria-labelledby="preview-title"
        >
          <div className="bg-[#111b21] w-full max-w-4xl h-[85vh] rounded-2xl shadow-2xl flex flex-col border border-[#202c33]">
            <div className="p-4 border-b border-[#202c33] flex items-center justify-between">
              <h3 id="preview-title" className="text-lg font-bold text-[#e9edef] truncate pr-4">
                Preview: {fileInfo?.file_name}
              </h3>
              <button
                onClick={handleClosePreview}
                className="w-8 h-8 flex items-center justify-center rounded-full bg-[#202c33] text-[#8696a0] hover:text-[#e9edef] transition-colors shrink-0"
                aria-label="Close preview"
              >
                ✕
              </button>
            </div>
            <div className="flex-1 overflow-auto p-4 flex items-center justify-center bg-[#0b141a]">
              {loadingPreview && <p className="text-[#8696a0] animate-pulse">Decrypting and loading preview...</p>}
              {previewError && <p className="text-red-400" role="alert">{previewError}</p>}
              {previewUrl && !loadingPreview && (
                fileInfo?.file_type?.startsWith('image/') ? (
                  <img src={previewUrl} alt="Preview" className="max-w-full max-h-full object-contain rounded-lg" />
                ) : fileInfo?.file_type === 'application/pdf' ? (
                  <iframe src={previewUrl} className="w-full h-full rounded-lg border border-[#202c33]" title="PDF Preview" />
                ) : (
                  <div className="text-center text-[#8696a0]">
                    <p className="mb-4">Preview not available for this file type.</p>
                    <a
                      href={previewUrl}
                      download={fileInfo?.file_name}
                      className="btn-primary px-4 py-2 rounded-xl bg-[#00a884] text-white font-bold inline-block"
                      aria-label="Download file"
                    >
                      Download File
                    </a>
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

export default memo(NewDelivery);