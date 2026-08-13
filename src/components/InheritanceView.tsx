import React, { useState, useEffect, useCallback, memo } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { useAppContext } from '../context/AppContext';
import { api } from '../services/api';

// =============================================================================
// TYPES & INTERFACES
// =============================================================================

interface VaultShard {
  id: string;
  beneficiary_name: string;
  beneficiary_contact: string;
  idx: number;
  status: 'pending' | 'claimed';
}

interface Vault {
  id: string;
  name: string;
  secret_type: 'seed' | 'password' | 'will' | 'text';
  m: number;
  n: number;
  trigger_type: 'date' | 'heartbeat' | 'manual';
  trigger_time?: string;
  status: 'locked' | 'open' | 'cancelled';
  created_at: string;
  shards: VaultShard[];
}

interface CreatedShardInfo {
  beneficiary_name: string;
  beneficiary_contact: string;
  access_code: string;
}

interface UploadInfo {
  file_key: string;
  file_name: string;
  file_size: number;
  file_type?: string | null;
}

interface Beneficiary {
  name: string;
  contact: string;
}

type SecretType = 'seed' | 'password' | 'will' | 'text';
type TriggerType = 'date' | 'heartbeat' | 'manual';

// =============================================================================
// CONSTANTS
// =============================================================================

const SECRET_TYPES: Array<{ value: SecretType; label: string; icon: string }> = [
  { value: 'seed', label: 'Seed Phrase', icon: '🔑' },
  { value: 'password', label: 'Master Password', icon: '🔒' },
  { value: 'will', label: 'Will / Legal Document', icon: '📜' },
  { value: 'text', label: 'Private Message', icon: '💬' },
];

const TRIGGER_TYPES: Array<{ value: TriggerType; label: string; icon: string }> = [
  { value: 'date', label: 'On a specific date', icon: '📅' },
  { value: 'heartbeat', label: "If I don't check in (Dead Man's Switch)", icon: '💓' },
  { value: 'manual', label: 'Manual release', icon: '🖐️' },
];

const VALIDATION_RULES = {
  MAX_VAULT_NAME_LENGTH: 100,
  MAX_BENEFICIARY_NAME_LENGTH: 100,
  MAX_CONTACT_LENGTH: 254,
  MIN_THRESHOLD: 2,
  MAX_SHARDS: 7,
  EMAIL_REGEX: /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
  PHONE_REGEX: /^\+?[\d\s-()]+$/,
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

// =============================================================================
// UTILITY FUNCTIONS
// =============================================================================

/**
 * Structured logger for debugging
 */
const logger = {
  info: (msg: string, data?: any) => {
    console.log(`[InheritanceView] ${msg}`, data || '');
  },
  error: (msg: string, error?: any) => {
    console.error(`[InheritanceView] ${msg}`, error || '');
  },
  warn: (msg: string, data?: any) => {
    console.warn(`[InheritanceView] ${msg}`, data || '');
  },
};

/**
 * Validate email format
 */
function isValidEmail(email: string): boolean {
  return VALIDATION_RULES.EMAIL_REGEX.test(email);
}

/**
 * Validate phone format
 */
function isValidPhone(phone: string): boolean {
  return VALIDATION_RULES.PHONE_REGEX.test(phone);
}

/**
 * Validate contact (email or phone)
 */
function isValidContact(contact: string): boolean {
  const trimmed = contact.trim();
  return isValidEmail(trimmed) || isValidPhone(trimmed);
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
  if (msg.includes('database') || msg.includes('storage')) {
    return { type: 'storage', message: 'Storage error. Please try again.' };
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
    storage: '💾',
    unknown: '❌',
  };
  
  const colorMap: Record<string, string> = {
    validation: 'border-yellow-900/50 bg-yellow-900/20 text-yellow-200',
    network: 'border-blue-900/50 bg-blue-900/20 text-blue-200',
    auth: 'border-red-900/50 bg-red-900/20 text-red-200',
    storage: 'border-purple-900/50 bg-purple-900/20 text-purple-200',
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
 * Vault card component
 */
const VaultCard = memo(({
  vault,
  recoveringVaultId,
  recoveredSecret,
  onRecover,
  onTrigger,
  onCancel,
}: {
  vault: Vault;
  recoveringVaultId: string | null;
  recoveredSecret: string | null;
  onRecover: (vaultId: string) => void;
  onTrigger: (vaultId: string) => void;
  onCancel: (vaultId: string) => void;
}) => {
  const isLocked = vault.status === 'locked';
  const isManual = vault.trigger_type === 'manual';
  const isRecovering = recoveringVaultId === vault.id;
  const hasRecoveredSecret = isRecovering && recoveredSecret;

  return (
    <div
      className="panel-2 bg-[#202c33] rounded-xl p-4 transition-all hover:bg-[#2a3942]"
      role="article"
      aria-label={`Vault: ${vault.name}`}
    >
      <div className="flex items-start justify-between gap-4">
        <div className="min-w-0 flex-1">
          <h4 className="text-sm font-bold text-[#e9edef] truncate">{vault.name}</h4>
          <p className="text-xs text-[#8696a0] mt-1">
            {vault.m}/{vault.n} threshold · {vault.status} · {vault.trigger_type}
          </p>
          
          <div className="mt-2 space-y-1">
            {vault.shards.map((s) => (
              <p key={s.id} className="text-xs text-[#8696a0]">
                • {s.beneficiary_name} ({s.beneficiary_contact})
              </p>
            ))}
          </div>
          
          {hasRecoveredSecret && (
            <div
              className="bg-[#111b21] p-3 rounded-lg mt-3 border border-[#00a884]/30"
              role="alert"
              aria-live="polite"
            >
              <p className="text-xs text-[#8696a0] mb-1">Recovered Secret:</p>
              <p className="text-xs text-[#00a884] font-mono break-all">{recoveredSecret}</p>
            </div>
          )}
        </div>
        
        <div className="flex flex-col gap-2 shrink-0">
          {isLocked && isManual && (
            <button
              onClick={() => onTrigger(vault.id)}
              className="btn-primary px-3 py-1.5 rounded-lg bg-[#00a884] text-white text-xs hover:bg-[#06cf9c] transition-colors"
              aria-label={`Release vault ${vault.name} now`}
            >
              🔓 Release Now
            </button>
          )}
          
          {isLocked && (
            <>
              <button
                onClick={() => onRecover(vault.id)}
                disabled={isRecovering}
                className="btn-secondary px-3 py-1.5 rounded-lg bg-[#2a3942] text-[#e9edef] text-xs hover:bg-[#3a4952] transition-colors disabled:opacity-50"
                aria-label={`Recover secret for vault ${vault.name}`}
              >
                {isRecovering ? 'Recovering...' : 'Recover Secret'}
              </button>
              <button
                onClick={() => onCancel(vault.id)}
                className="btn-ghost px-3 py-1.5 rounded-lg bg-[#111b21] text-red-400 text-xs hover:bg-red-900/20 transition-colors"
                aria-label={`Cancel vault ${vault.name}`}
              >
                Cancel
              </button>
            </>
          )}
        </div>
      </div>
    </div>
  );
});

/**
 * Post-creation screen showing access codes
 */
const CreatedShardsScreen = memo(({
  shards,
  onClose,
}: {
  shards: CreatedShardInfo[];
  onClose: () => void;
}) => (
  <div className="mx-auto max-w-3xl p-6 space-y-6 fade-in">
    <div className="panel bg-[#111b21] rounded-2xl p-8 border border-[#00a884]/40">
      <h2 className="text-2xl font-bold text-[#e9edef] mb-4">
        🔐 Vault Created — Write Down These Codes NOW
      </h2>
      
      <div
        className="bg-yellow-900/20 border border-yellow-900/50 rounded-xl p-4 mb-6"
        role="alert"
      >
        <p className="text-sm text-yellow-200 font-bold">
          ⚠️ These 8-digit codes are shown ONLY ONCE.
        </p>
        <p className="text-xs text-yellow-200/80 mt-1">
          Give each code to the named beneficiary in real life (handwritten letter, in person).
          If you lose these codes, you cannot recover them. The vault itself remains secure.
        </p>
      </div>

      <div className="space-y-3">
        {shards.map((s, i) => (
          <div
            key={i}
            className="panel-2 bg-[#202c33] rounded-xl p-4 flex items-center justify-between"
          >
            <div>
              <p className="text-sm text-[#e9edef] font-bold">{s.beneficiary_name}</p>
              <p className="text-xs text-[#8696a0]">{s.beneficiary_contact}</p>
            </div>
            <div className="text-right">
              <p className="text-xs text-[#8696a0] mb-1">Access Code:</p>
              <p className="text-2xl font-mono font-bold text-[#00a884] tracking-widest">
                {s.access_code}
              </p>
            </div>
          </div>
        ))}
      </div>

      <button
        onClick={onClose}
        className="btn-primary w-full mt-6 py-3 rounded-xl bg-[#00a884] hover:bg-[#06cf9c] text-white font-bold transition-colors"
        aria-label="Close and acknowledge codes"
      >
        I've Written Them Down — Close
      </button>
    </div>
  </div>
));

// =============================================================================
// MAIN COMPONENT
// =============================================================================

const InheritanceView: React.FC = () => {
  const { sessionToken } = useAppContext();
  
  // Core state
  const [vaults, setVaults] = useState<Vault[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  
  // Form state
  const [creating, setCreating] = useState(false);
  const [name, setName] = useState('');
  const [secretType, setSecretType] = useState<SecretType>('seed');
  const [secret, setSecret] = useState('');
  const [fileInfo, setFileInfo] = useState<UploadInfo | null>(null);
  const [uploading, setUploading] = useState(false);
  const [m, setM] = useState(3);
  const [n, setN] = useState(5);
  const [triggerType, setTriggerType] = useState<TriggerType>('manual');
  const [triggerTime, setTriggerTime] = useState('');
  const [beneficiaries, setBeneficiaries] = useState<Beneficiary[]>([
    { name: '', contact: '' },
    { name: '', contact: '' },
    { name: '', contact: '' },
    { name: '', contact: '' },
    { name: '', contact: '' },
  ]);
  
  // Post-creation state
  const [createdShards, setCreatedShards] = useState<CreatedShardInfo[] | null>(null);
  
  // Recovery state
  const [recoveringVaultId, setRecoveringVaultId] = useState<string | null>(null);
  const [recoveredSecret, setRecoveredSecret] = useState<string | null>(null);

  // ===========================================================================
  // DATA LOADING
  // ===========================================================================

  const loadVaults = useCallback(async () => {
    if (!sessionToken) {
      logger.warn('Cannot load vaults: no session token');
      return;
    }

    try {
      logger.info('Loading vaults...');
      const rawData = await api.listInheritanceVaults(sessionToken);
      
      logger.info('Raw vault data received', { count: rawData.length });
      
      const flattenedData = rawData.map((item: any) => ({
        ...item.vault,
        shards: item.shards,
      }));
      
      logger.info('Vaults loaded successfully', { count: flattenedData.length });
      setVaults(flattenedData);
      setError(null);
    } catch (e: any) {
      const categorized = categorizeError(e);
      logger.error('Failed to load vaults', categorized);
      setError(categorized.message);
    }
  }, [sessionToken]);

  useEffect(() => {
    if (sessionToken) {
      void loadVaults();
    }
    
    // Cleanup function
    return () => {
      logger.info('InheritanceView unmounting');
    };
  }, [sessionToken, loadVaults]);

  // ===========================================================================
  // BENEFICIARY MANAGEMENT
  // ===========================================================================

  const addBeneficiary = useCallback(() => {
    if (n < VALIDATION_RULES.MAX_SHARDS) {
      setN(n + 1);
      setBeneficiaries((prev) => [...prev, { name: '', contact: '' }]);
      logger.info('Added beneficiary', { newCount: n + 1 });
    }
  }, [n]);

  const removeBeneficiary = useCallback((i: number) => {
    if (n <= VALIDATION_RULES.MIN_THRESHOLD) {
      logger.warn('Cannot remove beneficiary: minimum threshold reached');
      return;
    }
    
    setN(n - 1);
    setBeneficiaries((prev) => prev.filter((_, idx) => idx !== i));
    logger.info('Removed beneficiary', { index: i, newCount: n - 1 });
  }, [n]);

  const updateBeneficiary = useCallback(
    (i: number, field: keyof Beneficiary, value: string) => {
      setBeneficiaries((prev) => {
        const updated = [...prev];
        updated[i] = { ...updated[i], [field]: value };
        return updated;
      });
    },
    []
  );

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
      const categorized = categorizeError(e);
      logger.error('File upload failed', categorized);
      setError(categorized.message);
    } finally {
      setUploading(false);
    }
  }, [sessionToken]);

  // ===========================================================================
  // VAULT CREATION
  // ===========================================================================

  const validateForm = useCallback((): string | null => {
    if (!name.trim()) return 'Enter a vault name';
    if (name.length > VALIDATION_RULES.MAX_VAULT_NAME_LENGTH) {
      return `Vault name must be less than ${VALIDATION_RULES.MAX_VAULT_NAME_LENGTH} characters`;
    }
    
    if (!secret.trim() && !fileInfo) return 'Enter a secret OR upload a file';
    if (secret.trim() && fileInfo) return 'Choose either a text secret OR a file, not both';
    
    if (m < VALIDATION_RULES.MIN_THRESHOLD || m > n) {
      return `Invalid threshold: require ${VALIDATION_RULES.MIN_THRESHOLD} ≤ M ≤ N`;
    }
    
    const validBeneficiaries = beneficiaries.slice(0, n);
    for (let i = 0; i < validBeneficiaries.length; i++) {
      const b = validBeneficiaries[i];
      if (!b.name.trim()) return `Beneficiary ${i + 1} needs a name`;
      if (b.name.length > VALIDATION_RULES.MAX_BENEFICIARY_NAME_LENGTH) {
        return `Beneficiary ${i + 1} name is too long`;
      }
      if (!b.contact.trim()) return `Beneficiary ${i + 1} needs a contact`;
      if (!isValidContact(b.contact)) {
        return `Beneficiary ${i + 1} has invalid contact (must be email or phone)`;
      }
      if (b.contact.length > VALIDATION_RULES.MAX_CONTACT_LENGTH) {
        return `Beneficiary ${i + 1} contact is too long`;
      }
    }
    
    if (triggerType === 'date' && !triggerTime) return 'Pick a trigger date';
    
    return null;
  }, [name, secret, fileInfo, m, n, beneficiaries, triggerType, triggerTime]);

  const handleCreate = useCallback(async () => {
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

    setCreating(true);
    
    try {
      logger.info('Creating inheritance vault', {
        name,
        secretType,
        m,
        n,
        triggerType,
        beneficiaries: beneficiaries.slice(0, n).length,
      });
      
      const response = await api.createInheritanceVault(sessionToken, {
        name: name.trim(),
        secret_type: secretType,
        secret: secret.trim() || null,
        file_key: fileInfo?.file_key || null,
        m,
        n,
        trigger_type: triggerType,
        trigger_time: triggerType === 'date' ? new Date(triggerTime).toISOString() : null,
        beneficiaries: beneficiaries.slice(0, n).map((b) => ({
          name: b.name.trim(),
          contact: b.contact.trim(),
        })),
      });
      
      setCreatedShards(response.shards);
      setSecret('');
      setFileInfo(null);
      setSuccess('Vault created successfully!');
      logger.info('Vault created successfully', { vaultId: response.vault_id });
      
      void loadVaults();
    } catch (e: any) {
      const categorized = categorizeError(e);
      logger.error('Vault creation failed', categorized);
      setError(categorized.message);
    } finally {
      setCreating(false);
    }
  }, [sessionToken, name, secretType, secret, fileInfo, m, n, triggerType, triggerTime, beneficiaries, validateForm, loadVaults]);

  // ===========================================================================
  // VAULT OPERATIONS
  // ===========================================================================

  const handleRecover = useCallback(async (vaultId: string) => {
    if (!sessionToken) {
      setError('Session required');
      return;
    }

    setError(null);
    setRecoveringVaultId(vaultId);
    setRecoveredSecret(null);
    
    try {
      logger.info('Recovering vault secret', { vaultId });
      const secret = await api.recoverVaultSecret(sessionToken, vaultId);
      setRecoveredSecret(secret);
      logger.info('Vault secret recovered successfully', { vaultId });
    } catch (e: any) {
      const categorized = categorizeError(e);
      logger.error('Vault recovery failed', categorized);
      setError(categorized.message);
      setRecoveringVaultId(null);
    }
  }, [sessionToken]);

  const handleTrigger = useCallback(async (vaultId: string) => {
    if (!sessionToken) {
      setError('Session required');
      return;
    }

    const confirmed = window.confirm(
      'Release this vault now? All beneficiaries will be notified.'
    );
    
    if (!confirmed) {
      logger.info('Vault trigger cancelled by user', { vaultId });
      return;
    }

    setError(null);
    
    try {
      logger.info('Triggering vault', { vaultId });
      await api.triggerInheritanceVault(sessionToken, vaultId);
      setSuccess('Vault released successfully! Beneficiaries have been notified.');
      logger.info('Vault triggered successfully', { vaultId });
      void loadVaults();
    } catch (e: any) {
      const categorized = categorizeError(e);
      logger.error('Vault trigger failed', categorized);
      setError(categorized.message);
    }
  }, [sessionToken, loadVaults]);

  const handleCancel = useCallback(async (vaultId: string) => {
    if (!sessionToken) {
      setError('Session required');
      return;
    }

    const confirmed = window.confirm(
      'Cancel this vault? Only possible while locked.'
    );
    
    if (!confirmed) {
      logger.info('Vault cancellation cancelled by user', { vaultId });
      return;
    }

    setError(null);
    
    try {
      logger.info('Cancelling vault', { vaultId });
      await api.cancelInheritanceVault(sessionToken, vaultId);
      setSuccess('Vault cancelled successfully.');
      logger.info('Vault cancelled successfully', { vaultId });
      void loadVaults();
    } catch (e: any) {
      const categorized = categorizeError(e);
      logger.error('Vault cancellation failed', categorized);
      setError(categorized.message);
    }
  }, [sessionToken, loadVaults]);

  // ===========================================================================
  // RENDER: POST-CREATION SCREEN
  // ===========================================================================

  if (createdShards) {
    return (
      <CreatedShardsScreen
        shards={createdShards}
        onClose={() => {
          setCreatedShards(null);
          setSuccess(null);
        }}
      />
    );
  }

  // ===========================================================================
  // RENDER: MAIN VIEW
  // ===========================================================================

  return (
    <div className="mx-auto max-w-3xl p-6 space-y-6 fade-in">
      <div className="panel bg-[#111b21] rounded-2xl p-6">
        <h2 className="text-2xl font-bold text-[#e9edef] mb-2">🧬 Digital Inheritance Vault</h2>
        <p className="text-sm text-[#8696a0] mb-6">
          Split a secret into N shards. Any M of your trusted beneficiaries can reconstruct it.
          Even if your device is destroyed, the vault survives in the cloud.
        </p>

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

        {/* Creation Form */}
        <div className="space-y-5">
          <div>
            <label htmlFor="vault-name" className="label text-sm text-[#8696a0] block mb-2">
              Vault name
            </label>
            <input
              id="vault-name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              className="input w-full bg-[#202c33] text-[#e9edef] p-3 rounded-xl focus:ring-2 focus:ring-[#00a884] transition-all"
              placeholder="Family Seed Phrase Vault"
              maxLength={VALIDATION_RULES.MAX_VAULT_NAME_LENGTH}
              aria-label="Vault name"
            />
          </div>

          <div>
            <label htmlFor="secret-type" className="label text-sm text-[#8696a0] block mb-2">
              Secret type
            </label>
            <select
              id="secret-type"
              value={secretType}
              onChange={(e) => setSecretType(e.target.value as SecretType)}
              className="input w-full bg-[#202c33] text-[#e9edef] p-3 rounded-xl border-none focus:ring-2 focus:ring-[#00a884] transition-all"
              aria-label="Secret type"
            >
              {SECRET_TYPES.map((t) => (
                <option key={t.value} value={t.value}>
                  {t.icon} {t.label}
                </option>
              ))}
            </select>
          </div>

          <div>
            <label htmlFor="secret-text" className="label text-sm text-[#8696a0] block mb-2">
              Text secret (seed phrase, password, message)
            </label>
            <textarea
              id="secret-text"
              rows={4}
              value={secret}
              onChange={(e) => setSecret(e.target.value)}
              className="input w-full bg-[#202c33] text-[#e9edef] p-3 rounded-xl resize-none focus:ring-2 focus:ring-[#00a884] transition-all"
              placeholder="Enter the secret to protect (optional if uploading a file)..."
              aria-label="Secret text"
            />
          </div>

          <div>
            <label className="label text-sm text-[#8696a0] block mb-2">
              OR upload a file (will, document, photo)
            </label>
            <div className="panel-2 bg-[#202c33] rounded-xl p-4 flex items-center justify-between">
              <div className="min-w-0 flex-1">
                {fileInfo ? (
                  <div>
                    <p className="text-sm text-[#e9edef] truncate">{fileInfo.file_name}</p>
                    <p className="text-xs text-[#8696a0]">{formatFileSize(fileInfo.file_size)}</p>
                  </div>
                ) : (
                  <p className="text-sm text-[#8696a0]">No file selected</p>
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
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div>
              <label htmlFor="total-shards" className="label text-sm text-[#8696a0] block mb-2">
                N (total shards)
              </label>
              <input
                id="total-shards"
                type="number"
                min={VALIDATION_RULES.MIN_THRESHOLD}
                max={VALIDATION_RULES.MAX_SHARDS}
                value={n}
                onChange={(e) => {
                  const v = parseInt(e.target.value);
                  if (v >= VALIDATION_RULES.MIN_THRESHOLD && v <= VALIDATION_RULES.MAX_SHARDS) {
                    setN(v);
                    if (m > v) setM(v);
                  }
                }}
                className="input w-full bg-[#202c33] text-[#e9edef] p-3 rounded-xl focus:ring-2 focus:ring-[#00a884] transition-all"
                aria-label="Total shards"
              />
            </div>
            <div>
              <label htmlFor="threshold" className="label text-sm text-[#8696a0] block mb-2">
                M (threshold to reconstruct)
              </label>
              <input
                id="threshold"
                type="number"
                min={VALIDATION_RULES.MIN_THRESHOLD}
                max={n}
                value={m}
                onChange={(e) => {
                  const v = parseInt(e.target.value);
                  if (v >= VALIDATION_RULES.MIN_THRESHOLD && v <= n) setM(v);
                }}
                className="input w-full bg-[#202c33] text-[#e9edef] p-3 rounded-xl focus:ring-2 focus:ring-[#00a884] transition-all"
                aria-label="Threshold"
              />
              <p className="text-xs text-[#8696a0] mt-1">Any {m} of {n} can reconstruct.</p>
            </div>
          </div>

          <div>
            <label htmlFor="trigger-type" className="label text-sm text-[#8696a0] block mb-2">
              Trigger
            </label>
            <select
              id="trigger-type"
              value={triggerType}
              onChange={(e) => setTriggerType(e.target.value as TriggerType)}
              className="input w-full bg-[#202c33] text-[#e9edef] p-3 rounded-xl border-none focus:ring-2 focus:ring-[#00a884] transition-all"
              aria-label="Trigger type"
            >
              {TRIGGER_TYPES.map((t) => (
                <option key={t.value} value={t.value}>
                  {t.icon} {t.label}
                </option>
              ))}
            </select>
            {triggerType === 'date' && (
              <input
                type="datetime-local"
                value={triggerTime}
                onChange={(e) => setTriggerTime(e.target.value)}
                className="input w-full bg-[#202c33] text-[#e9edef] p-3 rounded-xl mt-3 focus:ring-2 focus:ring-[#00a884] transition-all"
                aria-label="Trigger date and time"
              />
            )}
          </div>

          {/* Beneficiaries */}
          <div>
            <div className="flex items-center justify-between mb-3">
              <label className="label text-sm text-[#8696a0]">Beneficiaries ({n})</label>
              {n < VALIDATION_RULES.MAX_SHARDS && (
                <button
                  onClick={addBeneficiary}
                  className="btn-ghost text-xs text-[#00a884] hover:text-[#06cf9c] transition-colors"
                  aria-label="Add beneficiary"
                >
                  + Add
                </button>
              )}
            </div>
            <div className="space-y-2">
              {beneficiaries.slice(0, n).map((b, i) => (
                <div key={i} className="flex gap-2">
                  <input
                    value={b.name}
                    onChange={(e) => updateBeneficiary(i, 'name', e.target.value)}
                    className="input flex-1 bg-[#202c33] text-[#e9edef] p-2 rounded-lg text-sm focus:ring-2 focus:ring-[#00a884] transition-all"
                    placeholder="Name"
                    maxLength={VALIDATION_RULES.MAX_BENEFICIARY_NAME_LENGTH}
                    aria-label={`Beneficiary ${i + 1} name`}
                  />
                  <input
                    value={b.contact}
                    onChange={(e) => updateBeneficiary(i, 'contact', e.target.value)}
                    className="input flex-1 bg-[#202c33] text-[#e9edef] p-2 rounded-lg text-sm focus:ring-2 focus:ring-[#00a884] transition-all"
                    placeholder="Email or phone"
                    maxLength={VALIDATION_RULES.MAX_CONTACT_LENGTH}
                    aria-label={`Beneficiary ${i + 1} contact`}
                  />
                  {n > VALIDATION_RULES.MIN_THRESHOLD && (
                    <button
                      onClick={() => removeBeneficiary(i)}
                      className="btn-ghost px-3 py-2 rounded-lg bg-[#111b21] text-red-400 text-xs hover:bg-red-900/20 transition-colors"
                      aria-label={`Remove beneficiary ${i + 1}`}
                    >
                      ✕
                    </button>
                  )}
                </div>
              ))}
            </div>
          </div>

          <button
            onClick={handleCreate}
            disabled={creating || uploading}
            className="btn-primary w-full py-3 rounded-xl bg-[#00a884] hover:bg-[#06cf9c] text-white font-bold transition-colors disabled:opacity-50"
            aria-label="Create inheritance vault"
          >
            {creating ? 'Creating...' : '🔐 Create Vault'}
          </button>
        </div>
      </div>

      {/* Existing Vaults */}
      {vaults.length > 0 && (
        <div className="panel bg-[#111b21] rounded-2xl p-6">
          <h3 className="text-lg font-bold text-[#e9edef] mb-4">Your Vaults</h3>
          <div className="space-y-3">
            {vaults.map((v) => (
              <VaultCard
                key={v.id}
                vault={v}
                recoveringVaultId={recoveringVaultId}
                recoveredSecret={recoveredSecret}
                onRecover={handleRecover}
                onTrigger={handleTrigger}
                onCancel={handleCancel}
              />
            ))}
          </div>
        </div>
      )}
    </div>
  );
};

export default memo(InheritanceView);