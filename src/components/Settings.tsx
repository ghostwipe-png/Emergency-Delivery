import React, { useEffect, useState } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { LazyStore } from '@tauri-apps/plugin-store';
import QRCode from 'qrcode';
import { useAppContext } from '../context/AppContext';

type Preset = 'now' | '1h' | '24h' | '1w' | '1m' | 'custom';

interface SmsStatus {
  freeRemaining: number;
  credits: number;
}

const settingsStore = new LazyStore('settings.json');

const PRESET_OPTIONS: { value: Preset; label: string }[] = [
  { value: 'now', label: 'Immediate / Now' },
  { value: '1h', label: '1 hour' },
  { value: '24h', label: '24 hours' },
  { value: '1w', label: '1 week' },
  { value: '1m', label: '1 month' },
  { value: 'custom', label: 'Custom' },
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

const formatKey = (key: string): string =>
  key
    .replace(/_/g, ' ')
    .replace(/\b\w/g, (char) => char.toUpperCase());

const formatValue = (value: any): string => {
  if (value === null || value === undefined) return '—';
  if (typeof value === 'object') return JSON.stringify(value);
  return String(value);
};

const Settings: React.FC = () => {
  // Added `logout` to context destructuring for the Danger Zone wipe
  const { user, sessionToken, refreshUser, logout } = useAppContext();

  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  const [smsStatus, setSmsStatus] = useState<SmsStatus | null>(null);
  const [loadingSms, setLoadingSms] = useState(false);

  const [systemInfo, setSystemInfo] = useState<Record<string, any> | null>(null);
  const [loadingSystem, setLoadingSystem] = useState(false);

  const [defaultPreset, setDefaultPreset] = useState<Preset>('now');

  const [enabling, setEnabling] = useState(false);
  const [confirming, setConfirming] = useState(false);
  const [setupQrUrl, setSetupQrUrl] = useState<string | null>(null);
  const [setupSecret, setSetupSecret] = useState<string | null>(null);
  const [setupCode, setSetupCode] = useState('');

  const [showDisableForm, setShowDisableForm] = useState(false);
  const [disabling, setDisabling] = useState(false);
  const [disablePassword, setDisablePassword] = useState('');
  const [disableCode, setDisableCode] = useState('');

  // Phase 1: Audit Logs State
  const [showAuditLogs, setShowAuditLogs] = useState(false);
  const [auditLogs, setAuditLogs] = useState<any[]>([]);
  const [loadingLogs, setLoadingLogs] = useState(false);

  // Phase 1: Danger Zone (GDPR) State
  const [showDeleteModal, setShowDeleteModal] = useState(false);
  const [deleteConfirmation, setDeleteConfirmation] = useState('');
  const [deletingAccount, setDeletingAccount] = useState(false);

  // Phase 4: Dead Man's Switch State (Additive)
  const [heartbeatInterval, setHeartbeatInterval] = useState<number>(0);
  const [lastHeartbeatAt, setLastHeartbeatAt] = useState<string | null>(null);
  const [savingHeartbeat, setSavingHeartbeat] = useState(false);
  const [checkingIn, setCheckingIn] = useState(false);
    // Phase 7: Vault Backup State
  const [exportPw, setExportPw] = useState('');
  const [importPw, setImportPw] = useState('');
  const [backupLoading, setBackupLoading] = useState(false);

  const loadPreferences = async () => {
    try {
      const saved = await settingsStore.get<string>('defaultPreset');
      if (saved && ['now', '1h', '24h', '1w', '1m', 'custom'].includes(saved)) {
        setDefaultPreset(saved as Preset);
      }
    } catch {
      // Ignore preference load errors.
    }
  };

  const loadSmsStatus = async () => {
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
    } catch {
      setSmsStatus(null);
    } finally {
      setLoadingSms(false);
    }
  };

  const loadSystemInfo = async () => {
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
    } catch {
      setSystemInfo(null);
    } finally {
      setLoadingSystem(false);
    }
  };

  useEffect(() => {
    void loadPreferences();
    void loadSmsStatus();
    void loadSystemInfo();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Phase 4: Sync Heartbeat state from User context (Additive)
  useEffect(() => {
    if (user) {
      const u = user as any;
      setHeartbeatInterval(u?.heartbeat_interval_days ?? u?.heartbeatIntervalDays ?? 0);
      setLastHeartbeatAt(u?.last_heartbeat_at ?? u?.lastHeartbeatAt ?? null);
    }
  }, [user]);

  const handlePresetChange = async (value: Preset) => {
    setDefaultPreset(value);

    try {
      await settingsStore.set('defaultPreset', value);
      await settingsStore.save();
      setSuccess('Preference saved.');
      setError(null);
    } catch {
      setError('Could not save preference.');
      setSuccess(null);
    }
  };

  const handleStartEnable2FA = async () => {
    setError(null);
    setSuccess(null);
    setEnabling(true);

    try {
      const raw: any = await invoke('two_factor_setup', { sessionToken });

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
        const account = (user as any)?.email || 'account';
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
    } catch (err: any) {
      setError(String(err?.message || err || 'Failed to start 2FA setup.'));
    } finally {
      setEnabling(false);
    }
  };

  const handleCancelEnable2FA = () => {
    setSetupQrUrl(null);
    setSetupSecret(null);
    setSetupCode('');
    setError(null);
    setSuccess(null);
  };

  const handleCopySecret = async () => {
    if (!setupSecret) return;

    try {
      await navigator.clipboard.writeText(setupSecret);
      setSuccess('2FA secret copied to clipboard.');
      setError(null);
    } catch {
      setError('Could not copy the 2FA secret.');
      setSuccess(null);
    }
  };

  const handleConfirmEnable2FA = async () => {
    setError(null);
    setSuccess(null);

    if (!/^\d{6}$/.test(setupCode)) {
      setError('Enter the 6-digit code from your authenticator app.');
      return;
    }

    setConfirming(true);

    try {
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
    } catch (err: any) {
      setError(String(err?.message || err || 'Failed to confirm 2FA code.'));
    } finally {
      setConfirming(false);
    }
  };

  const handleDisable2FA = async () => {
    setError(null);
    setSuccess(null);

    if (!disablePassword.trim() && !disableCode.trim()) {
      setError('Enter your account password or current 2FA code to disable 2FA.');
      return;
    }

    setDisabling(true);

    try {
      const args: Record<string, string> = {};
      if (sessionToken) args.sessionToken = sessionToken;

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
    } catch (err: any) {
      setError(String(err?.message || err || 'Failed to disable 2FA.'));
    } finally {
      setDisabling(false);
    }
  };

  // Phase 1: Fetch Audit Logs
  const handleFetchAuditLogs = async () => {
    setShowAuditLogs(true);
    setLoadingLogs(true);
    setError(null);
    try {
      const logs = await invoke<any[]>('get_audit_logs', { sessionToken });
      setAuditLogs(Array.isArray(logs) ? logs : []);
    } catch (err: any) {
      setError(String(err?.message || err || 'Failed to load audit logs.'));
      setAuditLogs([]);
    } finally {
      setLoadingLogs(false);
    }
  };

  // Phase 1: GDPR Account Deletion
  const handleDeleteAccount = async () => {
    if (deleteConfirmation !== 'DELETE') return;
    setDeletingAccount(true);
    setError(null);
    try {
      // Triggers the Rust crypto-shredding and DB wipe
      await invoke('delete_account', { sessionToken, confirmation: 'DELETE' });
      
      // The backend session is already destroyed, so api.logout will throw,
      // but the context's logout safely catches errors and wipes the local Store anyway.
      await logout();
      
      // Force reload to completely reset the React app state and redirect to AuthScreen
      window.location.reload();
    } catch (err: any) {
      setError(String(err?.message || err || 'Failed to delete account.'));
      setDeletingAccount(false);
    }
  };

  // Phase 4: Dead Man's Switch Handlers (Additive)
  const handleSaveHeartbeat = async () => {
    setSavingHeartbeat(true);
    setError(null);
    setSuccess(null);
    try {
      await invoke('update_heartbeat', { sessionToken, intervalDays: heartbeatInterval });
      setSuccess(heartbeatInterval > 0 ? `Heartbeat updated to ${heartbeatInterval} days.` : 'Heartbeat disabled.');
      await refreshUser();
      // Update local state to reflect the new 'last_heartbeat_at' which is 'now'
      setLastHeartbeatAt(new Date().toISOString());
    } catch (err: any) {
      setError(String(err?.message || err || 'Failed to update heartbeat.'));
    } finally {
      setSavingHeartbeat(false);
    }
  };

  const handleManualCheckIn = async () => {
    setCheckingIn(true);
    setError(null);
    setSuccess(null);
    try {
      await invoke('manual_heartbeat', { sessionToken });
      setSuccess('Check-in recorded! You are safe.');
      await refreshUser();
      setLastHeartbeatAt(new Date().toISOString());
    } catch (err: any) {
      setError(String(err?.message || err || 'Failed to check in.'));
    } finally {
      setCheckingIn(false);
    }
  };

  if (!user) {
    return null;
  }

    // Phase 7: Vault Backup Handlers
  const handleExportVault = async () => {
    if (exportPw.length < 4) {
      setError('Export password must be at least 4 characters.');
      return;
    }
    setBackupLoading(true);
    setError(null);
    setSuccess(null);
    try {
      await invoke('export_vault', { sessionToken, password: exportPw });
      setSuccess('Vault exported successfully! Keep your .edbak file and password safe.');
      setExportPw('');
    } catch (err: any) {
      setError(err.message || 'Failed to export vault.');
    } finally {
      setBackupLoading(false);
    }
  };

  const handleImportVault = async () => {
    if (importPw.length < 4) {
      setError('Import password must be at least 4 characters.');
      return;
    }
    setBackupLoading(true);
    setError(null);
    setSuccess(null);
    try {
      await invoke('import_vault', { sessionToken, password: importPw });
      setSuccess('Vault imported successfully! Please restart the app to load the restored data.');
      setImportPw('');
    } catch (err: any) {
      setError(err.message || 'Failed to import vault.');
    } finally {
      setBackupLoading(false);
    }
  };

  const totpEnabled = Boolean(
    (user as any)?.totp_enabled ?? (user as any)?.totpEnabled ?? false
  );

  const email = String((user as any)?.email || '');
  const userId = String((user as any)?.id || '');

  return (
    <div className="space-y-6 fade-in">
      <div className="panel bg-[#111b21] rounded-2xl p-6">
        <h2 className="text-xl font-bold text-[#e9edef]">Settings</h2>
        <p className="text-sm text-[#8696a0] mt-1">
          Account security, SMS balance, preferences, and system information.
        </p>

        {error && (
          <div className="bg-red-900/20 text-red-400 p-3 rounded-xl text-sm mt-4">
            {error}
          </div>
        )}

        {success && (
          <div className="bg-[#00a884]/10 text-[#06cf9c] p-3 rounded-xl text-sm mt-4">
            {success}
          </div>
        )}
      </div>

      {/* Account */}
      <section className="panel-2 bg-[#202c33] rounded-2xl p-5">
        <div className="flex items-start justify-between gap-4">
          <div className="min-w-0">
            <h3 className="text-sm font-bold uppercase tracking-wider text-[#8696a0] mb-2">
              Account
            </h3>
            <p className="text-[#e9edef] font-medium truncate">{email}</p>
            
            {/* Phase 7: Enable Biometrics Button (Strictly Additive) */}
            {userId && (
              <div className="flex items-center justify-between mt-3 pt-3 border-t border-[#2a3942]">
                <div>
                  <p className="text-xs text-[#8696a0]">User ID: {userId}</p>
                  <p className="text-xs text-[#8696a0] mt-1">Enable Touch ID / Windows Hello for instant login.</p>
                </div>
                <button
                  onClick={async () => {
                    try {
                      await invoke('enable_biometric_unlock', { userId });
                      await settingsStore.set('last_email', email);
                      await settingsStore.save();
                      setSuccess('Biometric unlock enabled! Next login will be instant.');
                    } catch (e: any) {
                      setError(e.message || 'Failed to enable biometrics.');
                    }
                  }}
                  className="btn-secondary bg-[#2a3942] hover:bg-[#00a884] text-[#e9edef] text-xs font-bold px-3 py-1.5 rounded-lg transition-colors shrink-0 ml-4"
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
          >
            {totpEnabled ? '2FA Enabled' : '2FA Disabled'}
          </span>
        </div>
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
                onClick={() => void handleStartEnable2FA()}
                disabled={enabling}
                className="btn-primary bg-[#00a884] hover:bg-[#06cf9c] text-white font-bold px-4 py-2.5 rounded-xl transition-colors disabled:opacity-50"
              >
                {enabling ? 'Preparing...' : 'Enable 2FA'}
              </button>
            </div>
          ) : (
            <div className="space-y-4">
              <p className="text-sm text-[#e9edef]">
                Scan this QR code with your authenticator app, then enter the
                6-digit code to confirm.
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
                      onClick={() => void handleCopySecret()}
                      className="btn-ghost text-xs text-[#00a884] hover:text-[#06cf9c] mt-2 font-medium"
                    >
                      Copy secret
                    </button>
                  </div>

                  <div>
                    <label className="label block text-sm text-[#8696a0] mb-2">
                      Authenticator code
                    </label>
                    <input
                      type="text"
                      inputMode="numeric"
                      maxLength={6}
                      value={setupCode}
                      onChange={(e) =>
                        setSetupCode(e.target.value.replace(/\D/g, ''))
                      }
                      className="input w-full md:w-48 bg-[#111b21] text-[#e9edef] p-3 text-center text-xl tracking-widest rounded-xl outline-none focus:ring-2 focus:ring-[#00a884] transition-all"
                      placeholder="000000"
                    />
                  </div>

                  <div className="flex flex-wrap gap-3">
                    <button
                      onClick={() => void handleConfirmEnable2FA()}
                      disabled={confirming || setupCode.length !== 6}
                      className="btn-primary bg-[#00a884] hover:bg-[#06cf9c] text-white font-bold px-4 py-2.5 rounded-xl transition-colors disabled:opacity-50"
                    >
                      {confirming ? 'Confirming...' : 'Confirm & Enable'}
                    </button>
                    <button
                      onClick={handleCancelEnable2FA}
                      className="btn-ghost bg-[#111b21] text-[#8696a0] hover:text-[#e9edef] px-4 py-2.5 rounded-xl transition-colors"
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
              >
                Disable 2FA
              </button>
            ) : (
              <div className="space-y-4">
                <div>
                  <label className="label block text-sm text-[#8696a0] mb-2">
                    Account password
                  </label>
                  <input
                    type="password"
                    value={disablePassword}
                    onChange={(e) => setDisablePassword(e.target.value)}
                    className="input w-full bg-[#111b21] text-[#e9edef] p-3 rounded-xl outline-none focus:ring-2 focus:ring-[#00a884] transition-all"
                    placeholder="Enter account password"
                    autoComplete="current-password"
                  />
                </div>

                <div>
                  <label className="label block text-sm text-[#8696a0] mb-2">
                    Current 2FA code
                  </label>
                  <input
                    type="text"
                    inputMode="numeric"
                    maxLength={6}
                    value={disableCode}
                    onChange={(e) =>
                      setDisableCode(e.target.value.replace(/\D/g, ''))
                    }
                    className="input w-full md:w-48 bg-[#111b21] text-[#e9edef] p-3 text-center text-xl tracking-widest rounded-xl outline-none focus:ring-2 focus:ring-[#00a884] transition-all"
                    placeholder="000000"
                  />
                </div>

                <div className="flex flex-wrap gap-3">
                  <button
                    onClick={() => void handleDisable2FA()}
                    disabled={disabling}
                    className="btn-primary bg-red-500/80 hover:bg-red-500 text-white font-bold px-4 py-2.5 rounded-xl transition-colors disabled:opacity-50"
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
                  >
                    Cancel
                  </button>
                </div>
              </div>
            )}
          </div>
        )}
      </section>

      {/* Phase 1: Audit Logs */}
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
          >
            {showAuditLogs ? 'Hide Logs' : 'View Logs'}
          </button>
        </div>
        <p className="text-sm text-[#e9edef] mb-4">
          Tamper-evident, hash-chained history of your account's security events.
        </p>
        {showAuditLogs && (
          <div className="bg-[#111b21] rounded-xl p-4 max-h-80 overflow-y-auto space-y-2">
            {loadingLogs ? (
              <p className="text-sm text-[#8696a0] animate-pulse">Loading logs...</p>
            ) : auditLogs.length === 0 ? (
              <p className="text-sm text-[#8696a0]">No audit logs found.</p>
            ) : (
              auditLogs.map((log, idx) => (
                <div key={idx} className="text-xs border-b border-[#202c33] pb-2 last:border-0">
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
          <label className="label block text-sm text-[#8696a0] mb-2">
            Default delivery time preset
          </label>
          <select
            value={defaultPreset}
            onChange={(e) => void handlePresetChange(e.target.value as Preset)}
            className="input w-full bg-[#111b21] text-[#e9edef] p-3 rounded-xl outline-none focus:ring-2 focus:ring-[#00a884] transition-all border-none"
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

        <ul className="space-y-2">
          {SECURITY_ITEMS.map((item, index) => (
            <li key={index} className="flex items-start gap-3 text-sm text-[#e9edef]">
              <span className="mt-0.5 text-[#00a884]">✓</span>
              <span>{item}</span>
            </li>
          ))}
        </ul>
      </section>

      {/* Phase 4: Dead Man's Switch (Heartbeat) - Additive */}
      <section className="panel-2 bg-[#202c33] rounded-2xl p-5 border border-[#00a884]/30">
        <h3 className="text-sm font-bold uppercase tracking-wider text-[#00a884] mb-3">
          Dead Man's Switch (Heartbeat)
        </h3>
        <p className="text-sm text-[#e9edef] mb-4">
          If you don't check in within the specified interval (plus a 24-hour grace period), your <strong>Emergency Deliveries</strong> will be automatically dispatched.
        </p>

        <div className="space-y-4">
          <div>
            <label className="label block text-sm text-[#8696a0] mb-2">
              Check-in Interval
            </label>
            <select
              value={heartbeatInterval}
              onChange={(e) => setHeartbeatInterval(Number(e.target.value))}
              className="input w-full bg-[#111b21] text-[#e9edef] p-3 rounded-xl outline-none focus:ring-2 focus:ring-[#00a884] transition-all border-none"
            >
              <option value={0}>Disabled</option>
              <option value={3}>Every 3 days</option>
              <option value={7}>Every 7 days (1 week)</option>
              <option value={14}>Every 14 days (2 weeks)</option>
              <option value={30}>Every 30 days (1 month)</option>
              <option value={90}>Every 90 days (3 months)</option>
            </select>
          </div>

          {lastHeartbeatAt && heartbeatInterval > 0 && (
            <p className="text-xs text-[#8696a0]">
              Last check-in: <span className="text-[#e9edef] font-medium">{new Date(lastHeartbeatAt).toLocaleString()}</span>
            </p>
          )}

          <div className="flex flex-wrap gap-3">
            <button
              onClick={() => void handleSaveHeartbeat()}
              disabled={savingHeartbeat}
              className="btn-primary bg-[#00a884] hover:bg-[#06cf9c] text-white font-bold px-4 py-2.5 rounded-xl transition-colors disabled:opacity-50"
            >
              {savingHeartbeat ? 'Saving...' : 'Save Interval'}
            </button>

            {heartbeatInterval > 0 && (
              <button
                onClick={() => void handleManualCheckIn()}
                disabled={checkingIn}
                className="btn-secondary bg-[#2a3942] hover:bg-[#00a884] text-[#e9edef] font-medium px-4 py-2.5 rounded-xl transition-colors disabled:opacity-50"
              >
                {checkingIn ? 'Checking in...' : '👋 I\'m Safe (Check-in Now)'}
              </button>
            )}
          </div>
        </div>
      </section>

            {/* Phase 7: Vault Backup & Restore */}
      <section className="panel-2 bg-[#202c33] rounded-2xl p-5 border border-[#53bdeb]/30">
        <h3 className="text-sm font-bold uppercase tracking-wider text-[#53bdeb] mb-3">
          Vault Backup & Restore
        </h3>
        <p className="text-sm text-[#e9edef] mb-4">
          Securely export your local database and encrypted files to a <code className="bg-[#111b21] px-1 rounded">.edbak</code> file, or restore them on a new device.
        </p>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {/* Export */}
          <div className="space-y-3">
            <h4 className="text-xs font-bold text-[#8696a0] uppercase">Export Vault</h4>
            <input
              type="password"
              value={exportPw}
              onChange={(e) => setExportPw(e.target.value)}
              className="input w-full bg-[#111b21] text-[#e9edef] p-2.5 rounded-lg outline-none focus:ring-2 focus:ring-[#00a884] transition-all text-sm"
              placeholder="Set export password"
            />
            <button
              onClick={() => void handleExportVault()}
              disabled={backupLoading || exportPw.length < 4}
              className="btn-primary w-full bg-[#00a884] hover:bg-[#06cf9c] text-white font-bold py-2 rounded-lg transition-colors disabled:opacity-50 text-sm"
            >
              {backupLoading ? 'Exporting...' : '📦 Export to File'}
            </button>
          </div>

          {/* Import */}
          <div className="space-y-3">
            <h4 className="text-xs font-bold text-[#8696a0] uppercase">Restore Vault</h4>
            <input
              type="password"
              value={importPw}
              onChange={(e) => setImportPw(e.target.value)}
              className="input w-full bg-[#111b21] text-[#e9edef] p-2.5 rounded-lg outline-none focus:ring-2 focus:ring-[#53bdeb] transition-all text-sm"
              placeholder="Enter backup password"
            />
            <button
              onClick={() => void handleImportVault()}
              disabled={backupLoading || importPw.length < 4}
              className="btn-secondary w-full bg-[#2a3942] hover:bg-[#53bdeb] text-[#e9edef] font-bold py-2 rounded-lg transition-colors disabled:opacity-50 text-sm"
            >
              {backupLoading ? 'Importing...' : '📥 Import from File'}
            </button>
          </div>
        </div>
      </section>

      {/* Phase 1: Danger Zone (GDPR Right to be Forgotten) */}
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
          >
            Delete My Account
          </button>
        ) : (
          <div className="space-y-4 bg-red-900/10 p-4 rounded-xl border border-red-900/50">
            <p className="text-sm text-red-300 font-semibold">
              To confirm, type the word <span className="font-mono bg-red-900/30 px-2 py-0.5 rounded">DELETE</span> below:
            </p>
            <input
              type="text"
              value={deleteConfirmation}
              onChange={(e) => setDeleteConfirmation(e.target.value)}
              className="input w-full bg-[#111b21] text-[#e9edef] p-3 rounded-xl outline-none focus:ring-2 focus:ring-red-500 transition-all"
              placeholder="Type DELETE"
              autoComplete="off"
            />
            <div className="flex flex-wrap gap-3">
              <button
                onClick={() => void handleDeleteAccount()}
                disabled={deletingAccount || deleteConfirmation !== 'DELETE'}
                className="btn-primary bg-red-600 hover:bg-red-700 text-white font-bold px-4 py-2.5 rounded-xl transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {deletingAccount ? 'Wiping Account...' : 'Permanently Delete Account'}
              </button>
              <button
                onClick={() => {
                  setShowDeleteModal(false);
                  setDeleteConfirmation('');
                }}
                className="btn-ghost bg-[#111b21] text-[#8696a0] hover:text-[#e9edef] px-4 py-2.5 rounded-xl transition-colors"
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

export default Settings;