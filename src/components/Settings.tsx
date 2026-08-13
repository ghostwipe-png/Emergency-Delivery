import React, { useState, useEffect, useCallback, useMemo, memo } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { LazyStore } from '@tauri-apps/plugin-store';
import QRCode from 'qrcode';
import { useAppContext } from '../context/AppContext';

// =============================================================================
// TYPES & INTERFACES
// =============================================================================

type Preset = 'now' | '1h' | '24h' | '1w' | '1m' | 'custom';

interface SmsStatus {
  freeRemaining: number;
  credits: number;
}

interface AuditLog {
  id: string;
  user_id: string;
  action: string;
  details: string | null;
  current_hash: string;
  previous_hash: string | null;
  created_at: string;
}

interface TwoFactorSetupResponse {
  secret_base32?: string;
  secretBase32?: string;
  secret?: string;
  base32?: string;
  totp_secret?: string;
  otpauth_url?: string;
  otpauthUrl?: string;
  otpauth?: string;
  otpauth_uri?: string;
  otpauthUri?: string;
  url?: string;
}

interface User {
  id: string;
  email: string;
  name?: string;
  totp_enabled?: boolean;
  totpEnabled?: boolean;
  heartbeat_interval_days?: number;
  heartbeatIntervalDays?: number;
  last_heartbeat_at?: string;
  lastHeartbeatAt?: string;
}

// =============================================================================
// CONSTANTS
// =============================================================================

const settingsStore = new LazyStore('settings.json');

const VALIDATION_RULES = {
  MIN_QUICK_WORD_LENGTH: 6,
  MAX_QUICK_WORD_LENGTH: 15,
  MIN_EXPORT_PASSWORD_LENGTH: 4,
  MIN_IMPORT_PASSWORD_LENGTH: 4,
  TOTP_CODE_LENGTH: 6,
  TOTP_CODE_REGEX: /^\d{6}$/,
  QUICK_WORD_REGEX: /^\S+$/, // No spaces
  DELETE_CONFIRMATION: 'DELETE',
};

const PRESET_OPTIONS: Array<{ value: Preset; label: string }> = [
  { value: 'now', label: 'Immediate / Now' },
  { value: '1h', label: '1 hour' },
  { value: '24h', label: '24 hours' },
  { value: '1w', label: '1 week' },
  { value: '1m', label: '1 month' },
  { value: 'custom', label: 'Custom' },
];

const HEARTBEAT_OPTIONS = [
  { value: 0, label: 'Disabled' },
  { value: 3, label: 'Every 3 days' },
  { value: 7, label: 'Every 7 days (1 week)' },
  { value: 14, label: 'Every 14 days (2 weeks)' },
  { value: 30, label: 'Every 30 days (1 month)' },
  { value: 90, label: 'Every 90 days (3 months)' },
];

const SECURITY_ITEMS = [
  'Envelope encryption using AES-256-GCM.',
  'Per-file data encryption keys (DEK) wrapped by a password-derived KEK.',
  'PBKDF2 key derivation with 210,000 iterations.',
  'Worker dispatch protected by secret-header authentication.',
  'Claim links support expiry time and maximum view limits.',
  'Optional TOTP two-factor authentication for account sign-in.',
  'SMS is sent exactly once and never automatically retried.',
  'File uploads are stored in Cloudflare R2 with controlled access.',
];

// =============================================================================
// UTILITY FUNCTIONS
// =============================================================================

/**
 * Structured logger for debugging
 */
const logger = {
  info: (msg: string, data?: any) => {
    console.log(`[Settings] ${msg}`, data || '');
  },
  error: (msg: string, error?: any) => {
    console.error(`[Settings] ${msg}`, error || '');
  },
  warn: (msg: string, data?: any) => {
    console.warn(`[Settings] ${msg}`, data || '');
  },
};

/**
 * Format key for display (snake_case to Title Case)
 */
const formatKey = (key: string): string =>
  key
    .replace(/_/g, ' ')
    .replace(/\b\w/g, (char) => char.toUpperCase());

/**
 * Format value for display
 */
const formatValue = (value: any): string => {
  if (value === null || value === undefined) return '—';
  if (typeof value === 'object') return JSON.stringify(value);
  return String(value);
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
  if (msg.includes('database') || msg.includes('storage')) {
    return { type: 'storage', message: 'Storage error. Please try again.' };
  }
  if (msg.includes('2fa') || msg.includes('totp')) {
    return { type: '2fa', message: error.message || '2FA error' };
  }
  
  return { type: 'unknown', message: error.message || 'An unexpected error occurred' };
}

/**
 * Validate quick login word
 */
function validateQuickWord(word: string): string | null {
  if (!word) return 'Favorite word is required';
  if (word.length < VALIDATION_RULES.MIN_QUICK_WORD_LENGTH) {
    return `Word must be at least ${VALIDATION_RULES.MIN_QUICK_WORD_LENGTH} characters`;
  }
  if (word.length > VALIDATION_RULES.MAX_QUICK_WORD_LENGTH) {
    return `Word must not exceed ${VALIDATION_RULES.MAX_QUICK_WORD_LENGTH} characters`;
  }
  if (!VALIDATION_RULES.QUICK_WORD_REGEX.test(word)) {
    return 'Word must not contain spaces';
  }
  return null;
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
    storage: '💾',
    '2fa': '🔢',
    unknown: '❌',
  };
  
  const colorMap: Record<string, string> = {
    validation: 'border-yellow-900/50 bg-yellow-900/20 text-yellow-200',
    network: 'border-blue-900/50 bg-blue-900/20 text-blue-200',
    auth: 'border-red-900/50 bg-red-900/20 text-red-200',
    storage: 'border-purple-900/50 bg-purple-900/20 text-purple-200',
    '2fa': 'border-orange-900/50 bg-orange-900/20 text-orange-200',
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
 * Success message display
 */
const SuccessDisplay = memo(({ message, onDismiss }: { message: string; onDismiss?: () => void }) => (
  <div
    role="status"
    aria-live="polite"
    className="bg-[#00a884]/10 border border-[#00a884]/30 text-[#06cf9c] p-4 rounded-xl text-sm mb-4 flex items-start gap-3"
  >
    <span className="text-xl">✅</span>
    <div className="flex-1">
      <p className="text-sm font-medium">{message}</p>
    </div>
    {onDismiss && (
      <button
        onClick={onDismiss}
        className="text-sm opacity-60 hover:opacity-100 transition-opacity"
        aria-label="Dismiss message"
      >
        ✕
      </button>
    )}
  </div>
));

// =============================================================================
// MAIN COMPONENT
// =============================================================================

const Settings: React.FC = () => {
  const { user, sessionToken, refreshUser, logout } = useAppContext();

  // Core state
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  // SMS state
  const [smsStatus, setSmsStatus] = useState<SmsStatus | null>(null);
  const [loadingSms, setLoadingSms] = useState(false);

  // System info state
  const [systemInfo, setSystemInfo] = useState<Record<string, any> | null>(null);
  const [loadingSystem, setLoadingSystem] = useState(false);

  // Preferences state
  const [defaultPreset, setDefaultPreset] = useState<Preset>('now');

  // 2FA state
  const [enabling, setEnabling] = useState(false);
  const [confirming, setConfirming] = useState(false);
  const [setupQrUrl, setSetupQrUrl] = useState<string | null>(null);
  const [setupSecret, setSetupSecret] = useState<string | null>(null);
  const [setupCode, setSetupCode] = useState('');
  const [showDisableForm, setShowDisableForm] = useState(false);
  const [disabling, setDisabling] = useState(false);
  const [disablePassword, setDisablePassword] = useState('');
  const [disableCode, setDisableCode] = useState('');

  // Audit logs state
  const [showAuditLogs, setShowAuditLogs] = useState(false);
  const [auditLogs, setAuditLogs] = useState<AuditLog[]>([]);
  const [loadingLogs, setLoadingLogs] = useState(false);

  // Danger zone state
  const [showDeleteModal, setShowDeleteModal] = useState(false);
  const [deleteConfirmation, setDeleteConfirmation] = useState('');
  const [deletingAccount, setDeletingAccount] = useState(false);

  // Dead man's switch state
  const [heartbeatInterval, setHeartbeatInterval] = useState<number>(0);
  const [lastHeartbeatAt, setLastHeartbeatAt] = useState<string | null>(null);
  const [savingHeartbeat, setSavingHeartbeat] = useState(false);
  const [checkingIn, setCheckingIn] = useState(false);

  // Vault backup state
  const [exportPw, setExportPw] = useState('');
  const [importPw, setImportPw] = useState('');
  const [backupLoading, setBackupLoading] = useState(false);

  // Quick login state
  const [isSettingUpQuick, setIsSettingUpQuick] = useState(false);
  const [newQuickWord, setNewQuickWord] = useState('');
  const [quickSetupError, setQuickSetupError] = useState('');
  const [quickSetupLoading, setQuickSetupLoading] = useState(false);

  // Memoized user data
  const totpEnabled = useMemo(() => {
    const u = user as User | null;
    return Boolean(u?.totp_enabled ?? u?.totpEnabled ?? false);
  }, [user]);

  const email = useMemo(() => {
    const u = user as User | null;
    return String(u?.email || '');
  }, [user]);

  const userId = useMemo(() => {
    const u = user as User | null;
    return String(u?.id || '');
  }, [user]);

  // ===========================================================================
  // DATA LOADING
  // ===========================================================================

  const loadPreferences = useCallback(async () => {
    try {
      const saved = await settingsStore.get<string>('defaultPreset');
      if (saved && ['now', '1h', '24h', '1w', '1m', 'custom'].includes(saved)) {
        setDefaultPreset(saved as Preset);
      }
    } catch (e) {
      logger.warn('Failed to load preferences', e);
    }
  }, []);

  const loadSmsStatus = useCallback(async () => {
    if (!sessionToken) return;

    setLoadingSms(true);

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
    } catch (e) {
      logger.error('Failed to load SMS status', e);
      setSmsStatus(null);
    } finally {
      setLoadingSms(false);
    }
  }, [sessionToken]);

  const loadSystemInfo = useCallback(async () => {
    if (!sessionToken) return;

    setLoadingSystem(true);

    try {
      const raw: any = await invoke('get_system_info', { sessionToken });

      if (Array.isArray(raw)) {
        setSystemInfo({ items: raw });
      } else if (raw && typeof raw === 'object') {
        setSystemInfo(raw);
      } else {
        setSystemInfo({ info: String(raw) });
      }
    } catch (e) {
      logger.error('Failed to load system info', e);
      setSystemInfo(null);
    } finally {
      setLoadingSystem(false);
    }
  }, [sessionToken]);

  useEffect(() => {
    void loadPreferences();
    void loadSmsStatus();
    void loadSystemInfo();
  }, [loadPreferences, loadSmsStatus, loadSystemInfo]);

  useEffect(() => {
    if (user) {
      const u = user as User;
      setHeartbeatInterval(u?.heartbeat_interval_days ?? u?.heartbeatIntervalDays ?? 0);
      setLastHeartbeatAt(u?.last_heartbeat_at ?? u?.lastHeartbeatAt ?? null);
    }
  }, [user]);

  // ===========================================================================
  // PREFERENCES
  // ===========================================================================

  const handlePresetChange = useCallback(async (value: Preset) => {
    setDefaultPreset(value);

    try {
      await settingsStore.set('defaultPreset', value);
      await settingsStore.save();
      setSuccess('Preference saved.');
      setError(null);
      logger.info('Preference saved', { preset: value });
    } catch (e) {
      logger.error('Failed to save preference', e);
      setError('Could not save preference.');
      setSuccess(null);
    }
  }, []);

  // ===========================================================================
  // 2FA MANAGEMENT
  // ===========================================================================

  const handleStartEnable2FA = useCallback(async () => {
    if (!sessionToken) return;

    setError(null);
    setSuccess(null);
    setEnabling(true);

    try {
      logger.info('Starting 2FA setup');
      const raw: TwoFactorSetupResponse = await invoke('two_factor_setup', { sessionToken });

      const secret = String(
        raw?.secret_base32 ??
          raw?.secretBase32 ??
          raw?.secret ??
          raw?.base32 ??
          raw?.totp_secret ??
          ''
      );

      let otpauthUrl = String(
        raw?.otpauth_url ??
          raw?.otpauthUrl ??
          raw?.otpauth ??
          raw?.otpauth_uri ??
          raw?.otpauthUri ??
          raw?.url ??
          ''
      );

      if (!otpauthUrl && secret) {
        const account = email || 'account';
        otpauthUrl = `otpauth://totp/Emergency%20Delivery:${encodeURIComponent(
          account
        )}?secret=${encodeURIComponent(secret)}&issuer=Emergency%20Delivery`;
      }

      if (!otpauthUrl || !secret) {
        throw new Error('2FA setup response was missing required fields.');
      }

      const qrUrl = await QRCode.toDataURL(otpauthUrl, {
        width: 240,
        margin: 1,
        color: {
          dark: '#111b21',
          light: '#e9edef',
        },
      });

      setSetupQrUrl(qrUrl);
      setSetupSecret(secret);
      setSetupCode('');
      logger.info('2FA setup started successfully');
    } catch (err: any) {
      const categorized = categorizeError(err);
      logger.error('Failed to start 2FA setup', categorized);
      setError(categorized.message);
    } finally {
      setEnabling(false);
    }
  }, [sessionToken, email]);

  const handleCancelEnable2FA = useCallback(() => {
    setSetupQrUrl(null);
    setSetupSecret(null);
    setSetupCode('');
    setError(null);
    setSuccess(null);
    logger.info('2FA setup cancelled');
  }, []);

  const handleCopySecret = useCallback(async () => {
    if (!setupSecret) return;

    try {
      await navigator.clipboard.writeText(setupSecret);
      setSuccess('2FA secret copied to clipboard.');
      setError(null);
      logger.info('2FA secret copied');
    } catch (e) {
      logger.error('Failed to copy 2FA secret', e);
      setError('Could not copy the 2FA secret.');
      setSuccess(null);
    }
  }, [setupSecret]);

  const handleConfirmEnable2FA = useCallback(async () => {
    if (!sessionToken || !setupSecret) return;

    setError(null);
    setSuccess(null);

    if (!VALIDATION_RULES.TOTP_CODE_REGEX.test(setupCode)) {
      setError(`Enter the ${VALIDATION_RULES.TOTP_CODE_LENGTH}-digit code from your authenticator app.`);
      return;
    }

    setConfirming(true);

    try {
      logger.info('Confirming 2FA setup');
      await invoke('two_factor_confirm', {
        sessionToken,
        secretBase32: setupSecret,
        code: setupCode,
      });

      setSuccess('Two-factor authentication enabled successfully.');
      setSetupQrUrl(null);
      setSetupSecret(null);
      setSetupCode('');

      await refreshUser();
      logger.info('2FA enabled successfully');
    } catch (err: any) {
      const categorized = categorizeError(err);
      logger.error('Failed to confirm 2FA', categorized);
      setError(categorized.message);
    } finally {
      setConfirming(false);
    }
  }, [sessionToken, setupSecret, setupCode, refreshUser]);

  const handleDisable2FA = useCallback(async () => {
    if (!sessionToken) return;

    setError(null);
    setSuccess(null);

    if (!disablePassword.trim() && !disableCode.trim()) {
      setError('Enter your account password or current 2FA code to disable 2FA.');
      return;
    }

    setDisabling(true);

    try {
      logger.info('Disabling 2FA');
      const args: Record<string, string> = {};
      args.sessionToken = sessionToken;

      if (disablePassword.trim()) {
        args.password = disablePassword.trim();
        args.current_password = disablePassword.trim();
      }

      if (disableCode.trim()) {
        args.code = disableCode.trim();
        args.totp_code = disableCode.trim();
        args.token = disableCode.trim();
        args.otp = disableCode.trim();
      }

      await invoke('two_factor_disable', args);

      setSuccess('Two-factor authentication disabled.');
      setShowDisableForm(false);
      setDisablePassword('');
      setDisableCode('');

      await refreshUser();
      logger.info('2FA disabled successfully');
    } catch (err: any) {
      const categorized = categorizeError(err);
      logger.error('Failed to disable 2FA', categorized);
      setError(categorized.message);
    } finally {
      setDisabling(false);
    }
  }, [sessionToken, disablePassword, disableCode, refreshUser]);

  // ===========================================================================
  // AUDIT LOGS
  // ===========================================================================

  const handleFetchAuditLogs = useCallback(async () => {
    if (!sessionToken) return;

    setShowAuditLogs(true);
    setLoadingLogs(true);
    setError(null);

    try {
      logger.info('Fetching audit logs');
      const logs = await invoke<AuditLog[]>('get_audit_logs', { sessionToken });
      setAuditLogs(Array.isArray(logs) ? logs : []);
      logger.info('Audit logs loaded', { count: logs.length });
    } catch (err: any) {
      const categorized = categorizeError(err);
      logger.error('Failed to load audit logs', categorized);
      setError(categorized.message);
      setAuditLogs([]);
    } finally {
      setLoadingLogs(false);
    }
  }, [sessionToken]);

  // ===========================================================================
  // DANGER ZONE
  // ===========================================================================

  const handleDeleteAccount = useCallback(async () => {
    if (!sessionToken || deleteConfirmation !== VALIDATION_RULES.DELETE_CONFIRMATION) return;

    setDeletingAccount(true);
    setError(null);

    try {
      logger.warn('Deleting account');
      await invoke('delete_account', { sessionToken, confirmation: VALIDATION_RULES.DELETE_CONFIRMATION });
      
      await logout();
      
      logger.info('Account deleted successfully');
      window.location.reload();
    } catch (err: any) {
      const categorized = categorizeError(err);
      logger.error('Failed to delete account', categorized);
      setError(categorized.message);
      setDeletingAccount(false);
    }
  }, [sessionToken, deleteConfirmation, logout]);

  // ===========================================================================
  // DEAD MAN'S SWITCH
  // ===========================================================================

  const handleSaveHeartbeat = useCallback(async () => {
    if (!sessionToken) return;

    setSavingHeartbeat(true);
    setError(null);
    setSuccess(null);

    try {
      logger.info('Saving heartbeat interval', { interval: heartbeatInterval });
      await invoke('update_heartbeat', { sessionToken, intervalDays: heartbeatInterval });
      setSuccess(heartbeatInterval > 0 ? `Heartbeat updated to ${heartbeatInterval} days.` : 'Heartbeat disabled.');
      await refreshUser();
      setLastHeartbeatAt(new Date().toISOString());
      logger.info('Heartbeat saved successfully');
    } catch (err: any) {
      const categorized = categorizeError(err);
      logger.error('Failed to update heartbeat', categorized);
      setError(categorized.message);
    } finally {
      setSavingHeartbeat(false);
    }
  }, [sessionToken, heartbeatInterval, refreshUser]);

  const handleManualCheckIn = useCallback(async () => {
    if (!sessionToken) return;

    setCheckingIn(true);
    setError(null);
    setSuccess(null);

    try {
      logger.info('Manual check-in');
      await invoke('manual_heartbeat', { sessionToken });
      setSuccess('Check-in recorded! You are safe.');
      await refreshUser();
      setLastHeartbeatAt(new Date().toISOString());
      logger.info('Manual check-in successful');
    } catch (err: any) {
      const categorized = categorizeError(err);
      logger.error('Failed to check in', categorized);
      setError(categorized.message);
    } finally {
      setCheckingIn(false);
    }
  }, [sessionToken, refreshUser]);

  // ===========================================================================
  // VAULT BACKUP
  // ===========================================================================

  const handleExportVault = useCallback(async () => {
    if (!sessionToken) return;

    if (exportPw.length < VALIDATION_RULES.MIN_EXPORT_PASSWORD_LENGTH) {
      setError(`Export password must be at least ${VALIDATION_RULES.MIN_EXPORT_PASSWORD_LENGTH} characters.`);
      return;
    }

    setBackupLoading(true);
    setError(null);
    setSuccess(null);

    try {
      logger.info('Exporting vault');
      await invoke('export_vault', { sessionToken, password: exportPw });
      setSuccess('Vault exported successfully! Keep your .edbak file and password safe.');
      setExportPw('');
      logger.info('Vault exported successfully');
    } catch (err: any) {
      const categorized = categorizeError(err);
      logger.error('Failed to export vault', categorized);
      setError(categorized.message);
    } finally {
      setBackupLoading(false);
    }
  }, [sessionToken, exportPw]);

  const handleImportVault = useCallback(async () => {
    if (!sessionToken) return;

    if (importPw.length < VALIDATION_RULES.MIN_IMPORT_PASSWORD_LENGTH) {
      setError(`Import password must be at least ${VALIDATION_RULES.MIN_IMPORT_PASSWORD_LENGTH} characters.`);
      return;
    }

    setBackupLoading(true);
    setError(null);
    setSuccess(null);

    try {
      logger.info('Importing vault');
      await invoke('import_vault', { sessionToken, password: importPw });
      setSuccess('Vault imported successfully! Please restart the app to load the restored data.');
      setImportPw('');
      logger.info('Vault imported successfully');
    } catch (err: any) {
      const categorized = categorizeError(err);
      logger.error('Failed to import vault', categorized);
      setError(categorized.message);
    } finally {
      setBackupLoading(false);
    }
  }, [sessionToken, importPw]);

  // ===========================================================================
  // QUICK LOGIN
  // ===========================================================================

  const handleEnableQuickLogin = useCallback(async () => {
    if (!sessionToken) return;

    setQuickSetupError('');
    const validationError = validateQuickWord(newQuickWord);
    if (validationError) {
      setQuickSetupError(validationError);
      return;
    }

    setQuickSetupLoading(true);

    try {
      logger.info('Enabling quick login');
      await invoke('setup_quick_login', { sessionToken, favoriteWord: newQuickWord });
      setSuccess('Quick Login enabled! Next time, just type this word on the login screen.');
      setIsSettingUpQuick(false);
      setNewQuickWord('');
      logger.info('Quick login enabled successfully');
    } catch (e: any) {
      const categorized = categorizeError(e);
      logger.error('Failed to enable quick login', categorized);
      setQuickSetupError(categorized.message.replace('Error: ', ''));
    } finally {
      setQuickSetupLoading(false);
    }
  }, [sessionToken, newQuickWord]);

  const handleDisableQuickLogin = useCallback(async () => {
    if (!sessionToken) return;

    if (!window.confirm('Disable quick login on this device?')) return;

    setError(null);
    setSuccess(null);

    try {
      logger.info('Disabling quick login');
      await invoke('disable_quick_login', { sessionToken });
      setSuccess('Quick login disabled on this device.');
      logger.info('Quick login disabled successfully');
    } catch (e: any) {
      const categorized = categorizeError(e);
      logger.error('Failed to disable quick login', categorized);
      setError(categorized.message);
    }
  }, [sessionToken]);

  // ===========================================================================
  // BIOMETRICS
  // ===========================================================================

  const handleEnableBiometrics = useCallback(async () => {
    if (!userId || !email) return;

    try {
      logger.info('Enabling biometrics');
      await invoke('enable_biometric_unlock', { userId });
      await settingsStore.set('last_email', email);
      await settingsStore.save();
      setSuccess('Biometric unlock enabled! Next login will be instant.');
      logger.info('Biometrics enabled successfully');
    } catch (e: any) {
      const categorized = categorizeError(e);
      logger.error('Failed to enable biometrics', categorized);
      setError(categorized.message);
    }
  }, [userId, email]);

  // ===========================================================================
  // RENDER
  // ===========================================================================

  if (!user) {
    return null;
  }

  return (
    <div className="space-y-6 fade-in">
      <div className="panel bg-[#111b21] rounded-2xl p-6">
        <h2 className="text-xl font-bold text-[#e9edef]">Settings</h2>
        <p className="text-sm text-[#8696a0] mt-1">
          Account security, SMS balance, preferences, and system information.
        </p>

        {error && <ErrorDisplay error={error} onDismiss={() => setError(null)} />}
        {success && <SuccessDisplay message={success} onDismiss={() => setSuccess(null)} />}
      </div>

      {/* Account */}
      <section className="panel-2 bg-[#202c33] rounded-2xl p-5">
        <div className="flex items-start justify-between gap-4">
          <div className="min-w-0">
            <h3 className="text-sm font-bold uppercase tracking-wider text-[#8696a0] mb-2">
              Account
            </h3>
            <p className="text-[#e9edef] font-medium truncate">{email}</p>
            
            {userId && (
              <div className="flex items-center justify-between mt-3 pt-3 border-t border-[#2a3942]">
                <div>
                  <p className="text-xs text-[#8696a0]">User ID: {userId}</p>
                  <p className="text-xs text-[#8696a0] mt-1">Enable Touch ID / Windows Hello for instant login.</p>
                </div>
                <button
                  onClick={handleEnableBiometrics}
                  className="btn-secondary bg-[#2a3942] hover:bg-[#00a884] text-[#e9edef] text-xs font-bold px-3 py-1.5 rounded-lg transition-colors shrink-0 ml-4"
                  aria-label="Enable biometric unlock"
                >
                  🔓 Enable Biometrics
                </button>
              </div>
            )}
          </div>

          <span
            className={`px-3 py-1.5 rounded-lg text-xs font-bold shrink-0 ${
              totpEnabled
                ? 'bg-[#00a884]/15 text-[#06cf9c]'
                : 'bg-[#111b21] text-[#8696a0]'
            }`}
            aria-label={totpEnabled ? '2FA enabled' : '2FA disabled'}
          >
            {totpEnabled ? '2FA Enabled' : '2FA Disabled'}
          </span>
        </div>
      </section>

      {/* Quick Login */}
      <section className="panel-2 bg-[#202c33] rounded-2xl p-5 border border-[#00a884]/20">
        <h3 className="text-sm font-bold uppercase tracking-wider text-[#00a884] mb-3">
          🔓 Quick Login (Trusted Device)
        </h3>
        <p className="text-sm text-[#e9edef] mb-4">
          Unlock this app instantly with a favorite word instead of your password. 
          This is tied specifically to this computer and cannot be used on other devices.
        </p>
        
        {!isSettingUpQuick ? (
          <div className="flex gap-2">
            <button 
              onClick={() => setIsSettingUpQuick(true)} 
              className="btn-secondary bg-[#2a3942] hover:bg-[#00a884] text-[#e9edef] font-medium px-4 py-2 rounded-xl transition-colors text-sm"
              aria-label="Enable or change quick login word"
            >
              Enable / Change Word
            </button>
            <button 
              onClick={handleDisableQuickLogin} 
              className="btn-ghost bg-[#111b21] text-red-400 hover:text-red-300 font-medium px-4 py-2 rounded-xl transition-colors text-sm"
              aria-label="Disable quick login"
            >
              Disable
            </button>
          </div>
        ) : (
          <div className="mt-4 p-4 bg-[#111b21] rounded-xl border border-[#2a3942] space-y-3">
            <div>
              <label htmlFor="quick-word" className="block text-xs font-bold text-[#8696a0] mb-2">
                Set Favorite Word ({VALIDATION_RULES.MIN_QUICK_WORD_LENGTH}-{VALIDATION_RULES.MAX_QUICK_WORD_LENGTH} characters, no spaces)
              </label>
              <input 
                id="quick-word"
                type="password" 
                value={newQuickWord} 
                onChange={(e) => setNewQuickWord(e.target.value)} 
                className="input w-full bg-[#202c33] text-[#e9edef] p-3 rounded-xl outline-none focus:ring-2 focus:ring-[#00a884] transition-all"
                placeholder="e.g., sunrise" 
                autoFocus
                maxLength={VALIDATION_RULES.MAX_QUICK_WORD_LENGTH}
                aria-label="Favorite word for quick login"
              />
            </div>
            {quickSetupError && (
              <p className="text-red-400 text-xs" role="alert">{quickSetupError}</p>
            )}
            <div className="flex gap-2">
              <button 
                onClick={handleEnableQuickLogin} 
                disabled={quickSetupLoading}
                className="btn-primary bg-[#00a884] hover:bg-[#06cf9c] text-white font-bold px-4 py-2 rounded-xl transition-colors disabled:opacity-50 text-sm"
                aria-label="Save quick login word"
              >
                {quickSetupLoading ? 'Saving...' : 'Save'}
              </button>
              <button 
                onClick={() => {
                  setIsSettingUpQuick(false);
                  setNewQuickWord('');
                  setQuickSetupError('');
                }} 
                className="btn-ghost bg-[#202c33] text-[#8696a0] hover:text-[#e9edef] px-4 py-2 rounded-xl transition-colors text-sm"
                aria-label="Cancel quick login setup"
              >
                Cancel
              </button>
            </div>
          </div>
        )}
      </section>

      {/* Two-Factor Authentication */}
      <section className="panel-2 bg-[#202c33] rounded-2xl p-5">
        <h3 className="text-sm font-bold uppercase tracking-wider text-[#8696a0] mb-3">
          Two-Factor Authentication
        </h3>

        {!totpEnabled ? (
          !setupQrUrl ? (
            <div className="space-y-4">
              <p className="text-sm text-[#e9edef]">
                Protect your account with TOTP two-factor authentication using an
                authenticator app.
              </p>
              <button
                onClick={handleStartEnable2FA}
                disabled={enabling}
                className="btn-primary bg-[#00a884] hover:bg-[#06cf9c] text-white font-bold px-4 py-2.5 rounded-xl transition-colors disabled:opacity-50"
                aria-label="Enable 2FA"
              >
                {enabling ? 'Preparing...' : 'Enable 2FA'}
              </button>
            </div>
          ) : (
            <div className="space-y-4">
              <p className="text-sm text-[#e9edef]">
                Scan this QR code with your authenticator app, then enter the
                {VALIDATION_RULES.TOTP_CODE_LENGTH}-digit code to confirm.
              </p>

              <div className="flex flex-col md:flex-row gap-6">
                <div className="shrink-0">
                  <img
                    src={setupQrUrl}
                    alt="2FA QR code"
                    className="w-48 h-48 rounded-xl bg-[#e9edef] p-2"
                  />
                </div>

                <div className="flex-1 space-y-4">
                  <div>
                    <p className="label text-sm text-[#8696a0] mb-2">
                      Backup secret
                    </p>
                    <div className="bg-[#111b21] rounded-xl p-3">
                      <p className="font-mono text-sm text-[#e9edef] break-all">
                        {setupSecret}
                      </p>
                    </div>
                    <button
                      onClick={handleCopySecret}
                      className="btn-ghost text-xs text-[#00a884] hover:text-[#06cf9c] mt-2 font-medium"
                      aria-label="Copy 2FA secret"
                    >
                      Copy secret
                    </button>
                  </div>

                  <div>
                    <label htmlFor="totp-code" className="label block text-sm text-[#8696a0] mb-2">
                      Authenticator code
                    </label>
                    <input
                      id="totp-code"
                      type="text"
                      inputMode="numeric"
                      maxLength={VALIDATION_RULES.TOTP_CODE_LENGTH}
                      value={setupCode}
                      onChange={(e) =>
                        setSetupCode(e.target.value.replace(/\D/g, ''))
                      }
                      className="input w-full md:w-48 bg-[#111b21] text-[#e9edef] p-3 text-center text-xl tracking-widest rounded-xl outline-none focus:ring-2 focus:ring-[#00a884] transition-all"
                      placeholder="000000"
                      aria-label="6-digit authenticator code"
                    />
                  </div>

                  <div className="flex flex-wrap gap-3">
                    <button
                      onClick={handleConfirmEnable2FA}
                      disabled={confirming || setupCode.length !== VALIDATION_RULES.TOTP_CODE_LENGTH}
                      className="btn-primary bg-[#00a884] hover:bg-[#06cf9c] text-white font-bold px-4 py-2.5 rounded-xl transition-colors disabled:opacity-50"
                      aria-label="Confirm and enable 2FA"
                    >
                      {confirming ? 'Confirming...' : 'Confirm & Enable'}
                    </button>
                    <button
                      onClick={handleCancelEnable2FA}
                      className="btn-ghost bg-[#111b21] text-[#8696a0] hover:text-[#e9edef] px-4 py-2.5 rounded-xl transition-colors"
                      aria-label="Cancel 2FA setup"
                    >
                      Cancel
                    </button>
                  </div>
                </div>
              </div>
            </div>
          )
        ) : (
          <div className="space-y-4">
            <p className="text-sm text-[#e9edef]">
              Two-factor authentication is currently enabled. Disabling it reduces
              account security.
            </p>

            {!showDisableForm ? (
              <button
                onClick={() => {
                  setShowDisableForm(true);
                  setError(null);
                  setSuccess(null);
                }}
                className="btn-secondary bg-[#2a3942] hover:bg-[#00a884] text-[#e9edef] font-medium px-4 py-2.5 rounded-xl transition-colors"
                aria-label="Disable 2FA"
              >
                Disable 2FA
              </button>
            ) : (
              <div className="space-y-4">
                <div>
                  <label htmlFor="disable-password" className="label block text-sm text-[#8696a0] mb-2">
                    Account password
                  </label>
                  <input
                    id="disable-password"
                    type="password"
                    value={disablePassword}
                    onChange={(e) => setDisablePassword(e.target.value)}
                    className="input w-full bg-[#111b21] text-[#e9edef] p-3 rounded-xl outline-none focus:ring-2 focus:ring-[#00a884] transition-all"
                    placeholder="Enter account password"
                    autoComplete="current-password"
                    aria-label="Account password"
                  />
                </div>

                <div>
                  <label htmlFor="disable-code" className="label block text-sm text-[#8696a0] mb-2">
                    Current 2FA code
                  </label>
                  <input
                    id="disable-code"
                    type="text"
                    inputMode="numeric"
                    maxLength={VALIDATION_RULES.TOTP_CODE_LENGTH}
                    value={disableCode}
                    onChange={(e) =>
                      setDisableCode(e.target.value.replace(/\D/g, ''))
                    }
                    className="input w-full md:w-48 bg-[#111b21] text-[#e9edef] p-3 text-center text-xl tracking-widest rounded-xl outline-none focus:ring-2 focus:ring-[#00a884] transition-all"
                    placeholder="000000"
                    aria-label="Current 2FA code"
                  />
                </div>

                <div className="flex flex-wrap gap-3">
                  <button
                    onClick={handleDisable2FA}
                    disabled={disabling}
                    className="btn-primary bg-red-500/80 hover:bg-red-500 text-white font-bold px-4 py-2.5 rounded-xl transition-colors disabled:opacity-50"
                    aria-label="Confirm disable 2FA"
                  >
                    {disabling ? 'Disabling...' : 'Confirm Disable'}
                  </button>
                  <button
                    onClick={() => {
                      setShowDisableForm(false);
                      setDisablePassword('');
                      setDisableCode('');
                      setError(null);
                    }}
                    className="btn-ghost bg-[#111b21] text-[#8696a0] hover:text-[#e9edef] px-4 py-2.5 rounded-xl transition-colors"
                    aria-label="Cancel disable 2FA"
                  >
                    Cancel
                  </button>
                </div>
              </div>
            )}
          </div>
        )}
      </section>

      {/* Audit Logs */}
      <section className="panel-2 bg-[#202c33] rounded-2xl p-5">
        <div className="flex items-center justify-between mb-3">
          <h3 className="text-sm font-bold uppercase tracking-wider text-[#8696a0]">
            Audit Logs
          </h3>
          <button
            onClick={() => {
              if (showAuditLogs) {
                setShowAuditLogs(false);
              } else {
                void handleFetchAuditLogs();
              }
            }}
            className="btn-ghost text-xs text-[#00a884] hover:text-[#06cf9c] font-medium"
            aria-label={showAuditLogs ? 'Hide audit logs' : 'View audit logs'}
          >
            {showAuditLogs ? 'Hide Logs' : 'View Logs'}
          </button>
        </div>
        <p className="text-sm text-[#e9edef] mb-4">
          Tamper-evident, hash-chained history of your account's security events.
        </p>
        {showAuditLogs && (
          <div className="bg-[#111b21] rounded-xl p-4 max-h-80 overflow-y-auto space-y-2" role="log">
            {loadingLogs ? (
              <p className="text-sm text-[#8696a0] animate-pulse">Loading logs...</p>
            ) : auditLogs.length === 0 ? (
              <p className="text-sm text-[#8696a0]">No audit logs found.</p>
            ) : (
              auditLogs.map((log) => (
                <div key={log.id} className="text-xs border-b border-[#202c33] pb-2 last:border-0">
                  <div className="flex justify-between">
                    <span className="text-[#e9edef] font-bold capitalize">{log.action.replace(/_/g, ' ')}</span>
                    <span className="text-[#8696a0]">{new Date(log.created_at).toLocaleString()}</span>
                  </div>
                  {log.details && <p className="text-[#8696a0] mt-0.5">{log.details}</p>}
                  <p className="text-[#53bdeb] font-mono text-[10px] mt-1 truncate" title={log.current_hash}>
                    Hash: {log.current_hash}
                  </p>
                </div>
              ))
            )}
          </div>
        )}
      </section>

      {/* SMS Status */}
      <section className="panel-2 bg-[#202c33] rounded-2xl p-5">
        <h3 className="text-sm font-bold uppercase tracking-wider text-[#8696a0] mb-3">
          SMS Status
        </h3>

        {loadingSms ? (
          <p className="text-sm text-[#8696a0] animate-pulse">
            Loading SMS status...
          </p>
        ) : smsStatus ? (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="bg-[#111b21] rounded-xl p-4">
              <p className="text-xs text-[#8696a0] mb-1">Free SMS remaining</p>
              <p className="text-2xl font-bold text-[#00a884]">
                {smsStatus.freeRemaining}
              </p>
            </div>

            <div className="bg-[#111b21] rounded-xl p-4">
              <p className="text-xs text-[#8696a0] mb-1">Paid SMS credits</p>
              <p className="text-2xl font-bold text-[#53bdeb]">
                {smsStatus.credits}
              </p>
            </div>

            <p className="text-xs text-[#8696a0] md:col-span-2">
              The first 5 SMS deliveries are free. After that, SMS is deducted from
              purchased credits. SMS delivery is Kenya-only.
            </p>
          </div>
        ) : (
          <p className="text-sm text-[#8696a0]">
            Unable to load SMS status.
          </p>
        )}
      </section>

      {/* Preferences */}
      <section className="panel-2 bg-[#202c33] rounded-2xl p-5">
        <h3 className="text-sm font-bold uppercase tracking-wider text-[#8696a0] mb-3">
          Preferences
        </h3>

        <div>
          <label htmlFor="default-preset" className="label block text-sm text-[#8696a0] mb-2">
            Default delivery time preset
          </label>
          <select
            id="default-preset"
            value={defaultPreset}
            onChange={(e) => void handlePresetChange(e.target.value as Preset)}
            className="input w-full bg-[#111b21] text-[#e9edef] p-3 rounded-xl outline-none focus:ring-2 focus:ring-[#00a884] transition-all border-none"
            aria-label="Default delivery time preset"
          >
            {PRESET_OPTIONS.map((option) => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </select>
          <p className="text-xs text-[#8696a0] mt-2">
            This preset is selected by default when creating a new delivery.
          </p>
        </div>
      </section>

      {/* System Info */}
      <section className="panel-2 bg-[#202c33] rounded-2xl p-5">
        <h3 className="text-sm font-bold uppercase tracking-wider text-[#8696a0] mb-3">
          System Information
        </h3>

        {loadingSystem ? (
          <p className="text-sm text-[#8696a0] animate-pulse">
            Loading system information...
          </p>
        ) : systemInfo ? (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {Object.entries(systemInfo).map(([key, value]) => (
              <div key={key} className="bg-[#111b21] rounded-xl p-3">
                <p className="text-xs text-[#8696a0] mb-1">{formatKey(key)}</p>
                <p className="text-sm text-[#e9edef] break-all">
                  {formatValue(value)}
                </p>
              </div>
            ))}
          </div>
        ) : (
          <p className="text-sm text-[#8696a0]">
            Unable to load system information.
          </p>
        )}
      </section>

      {/* Security */}
      <section className="panel-2 bg-[#202c33] rounded-2xl p-5">
        <h3 className="text-sm font-bold uppercase tracking-wider text-[#8696a0] mb-3">
          Security
        </h3>

        <ul className="space-y-2" role="list">
          {SECURITY_ITEMS.map((item, index) => (
            <li key={index} className="flex items-start gap-3 text-sm text-[#e9edef]" role="listitem">
              <span className="mt-0.5 text-[#00a884]" aria-hidden="true">✓</span>
              <span>{item}</span>
            </li>
          ))}
        </ul>
      </section>

      {/* Dead Man's Switch */}
      <section className="panel-2 bg-[#202c33] rounded-2xl p-5 border border-[#00a884]/30">
        <h3 className="text-sm font-bold uppercase tracking-wider text-[#00a884] mb-3">
          Dead Man's Switch (Heartbeat)
        </h3>
        <p className="text-sm text-[#e9edef] mb-4">
          If you don't check in within the specified interval (plus a 24-hour grace period), your <strong>Emergency Deliveries</strong> will be automatically dispatched.
        </p>

        <div className="space-y-4">
          <div>
            <label htmlFor="heartbeat-interval" className="label block text-sm text-[#8696a0] mb-2">
              Check-in Interval
            </label>
            <select
              id="heartbeat-interval"
              value={heartbeatInterval}
              onChange={(e) => setHeartbeatInterval(Number(e.target.value))}
              className="input w-full bg-[#111b21] text-[#e9edef] p-3 rounded-xl outline-none focus:ring-2 focus:ring-[#00a884] transition-all border-none"
              aria-label="Heartbeat check-in interval"
            >
              {HEARTBEAT_OPTIONS.map((option) => (
                <option key={option.value} value={option.value}>
                  {option.label}
                </option>
              ))}
            </select>
          </div>

          {lastHeartbeatAt && heartbeatInterval > 0 && (
            <p className="text-xs text-[#8696a0]">
              Last check-in: <span className="text-[#e9edef] font-medium">{new Date(lastHeartbeatAt).toLocaleString()}</span>
            </p>
          )}

          <div className="flex flex-wrap gap-3">
            <button
              onClick={handleSaveHeartbeat}
              disabled={savingHeartbeat}
              className="btn-primary bg-[#00a884] hover:bg-[#06cf9c] text-white font-bold px-4 py-2.5 rounded-xl transition-colors disabled:opacity-50"
              aria-label="Save heartbeat interval"
            >
              {savingHeartbeat ? 'Saving...' : 'Save Interval'}
            </button>

            {heartbeatInterval > 0 && (
              <button
                onClick={handleManualCheckIn}
                disabled={checkingIn}
                className="btn-secondary bg-[#2a3942] hover:bg-[#00a884] text-[#e9edef] font-medium px-4 py-2.5 rounded-xl transition-colors disabled:opacity-50"
                aria-label="Manual check-in"
              >
                {checkingIn ? 'Checking in...' : "👋 I'm Safe (Check-in Now)"}
              </button>
            )}
          </div>
        </div>
      </section>

      {/* Vault Backup */}
      <section className="panel-2 bg-[#202c33] rounded-2xl p-5 border border-[#53bdeb]/30">
        <h3 className="text-sm font-bold uppercase tracking-wider text-[#53bdeb] mb-3">
          Vault Backup & Restore
        </h3>
        <p className="text-sm text-[#e9edef] mb-4">
          Securely export your local database and encrypted files to a <code className="bg-[#111b21] px-1 rounded">.edbak</code> file, or restore them on a new device.
        </p>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div className="space-y-3">
            <h4 className="text-xs font-bold text-[#8696a0] uppercase">Export Vault</h4>
            <label htmlFor="export-password" className="sr-only">Export password</label>
            <input
              id="export-password"
              type="password"
              value={exportPw}
              onChange={(e) => setExportPw(e.target.value)}
              className="input w-full bg-[#111b21] text-[#e9edef] p-2.5 rounded-lg outline-none focus:ring-2 focus:ring-[#00a884] transition-all text-sm"
              placeholder="Set export password"
              aria-label="Export password"
            />
            <button
              onClick={handleExportVault}
              disabled={backupLoading || exportPw.length < VALIDATION_RULES.MIN_EXPORT_PASSWORD_LENGTH}
              className="btn-primary w-full bg-[#00a884] hover:bg-[#06cf9c] text-white font-bold py-2 rounded-lg transition-colors disabled:opacity-50 text-sm"
              aria-label="Export vault to file"
            >
              {backupLoading ? 'Exporting...' : '📦 Export to File'}
            </button>
          </div>

          <div className="space-y-3">
            <h4 className="text-xs font-bold text-[#8696a0] uppercase">Restore Vault</h4>
            <label htmlFor="import-password" className="sr-only">Import password</label>
            <input
              id="import-password"
              type="password"
              value={importPw}
              onChange={(e) => setImportPw(e.target.value)}
              className="input w-full bg-[#111b21] text-[#e9edef] p-2.5 rounded-lg outline-none focus:ring-2 focus:ring-[#53bdeb] transition-all text-sm"
              placeholder="Enter backup password"
              aria-label="Import password"
            />
            <button
              onClick={handleImportVault}
              disabled={backupLoading || importPw.length < VALIDATION_RULES.MIN_IMPORT_PASSWORD_LENGTH}
              className="btn-secondary w-full bg-[#2a3942] hover:bg-[#53bdeb] text-[#e9edef] font-bold py-2 rounded-lg transition-colors disabled:opacity-50 text-sm"
              aria-label="Import vault from file"
            >
              {backupLoading ? 'Importing...' : '📥 Import from File'}
            </button>
          </div>
        </div>
      </section>

      {/* Danger Zone */}
      <section className="panel-2 bg-[#202c33] rounded-2xl p-5 border border-red-900/30">
        <h3 className="text-sm font-bold uppercase tracking-wider text-red-400 mb-3">
          Danger Zone
        </h3>
        <p className="text-sm text-[#e9edef] mb-4">
          Permanently delete your account, wipe all local data, and crypto-shred your cloud files. This action cannot be undone.
        </p>
        
        {!showDeleteModal ? (
          <button
            onClick={() => setShowDeleteModal(true)}
            className="btn-secondary bg-red-900/20 hover:bg-red-900/40 text-red-400 font-bold px-4 py-2.5 rounded-xl transition-colors"
            aria-label="Delete account"
          >
            Delete My Account
          </button>
        ) : (
          <div className="space-y-4 bg-red-900/10 p-4 rounded-xl border border-red-900/50">
            <p className="text-sm text-red-300 font-semibold">
              To confirm, type the word <span className="font-mono bg-red-900/30 px-2 py-0.5 rounded">{VALIDATION_RULES.DELETE_CONFIRMATION}</span> below:
            </p>
            <label htmlFor="delete-confirmation" className="sr-only">Type DELETE to confirm</label>
            <input
              id="delete-confirmation"
              type="text"
              value={deleteConfirmation}
              onChange={(e) => setDeleteConfirmation(e.target.value)}
              className="input w-full bg-[#111b21] text-[#e9edef] p-3 rounded-xl outline-none focus:ring-2 focus:ring-red-500 transition-all"
              placeholder={`Type ${VALIDATION_RULES.DELETE_CONFIRMATION}`}
              autoComplete="off"
              aria-label="Type DELETE to confirm account deletion"
            />
            <div className="flex flex-wrap gap-3">
              <button
                onClick={handleDeleteAccount}
                disabled={deletingAccount || deleteConfirmation !== VALIDATION_RULES.DELETE_CONFIRMATION}
                className="btn-primary bg-red-600 hover:bg-red-700 text-white font-bold px-4 py-2.5 rounded-xl transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                aria-label="Permanently delete account"
              >
                {deletingAccount ? 'Wiping Account...' : 'Permanently Delete Account'}
              </button>
              <button
                onClick={() => {
                  setShowDeleteModal(false);
                  setDeleteConfirmation('');
                }}
                className="btn-ghost bg-[#111b21] text-[#8696a0] hover:text-[#e9edef] px-4 py-2.5 rounded-xl transition-colors"
                aria-label="Cancel account deletion"
              >
                Cancel
              </button>
            </div>
          </div>
        )}
      </section>
    </div>
  );
};

export default memo(Settings);