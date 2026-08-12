import React, { useState, useEffect } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { useAppContext } from '../context/AppContext';
import { api } from '../services/api';

interface VaultShard {
  id: string;
  beneficiary_name: string;
  beneficiary_contact: string;
  idx: number;
}

interface Vault {
  id: string;
  name: string;
  secret_type: string;
  m: number;
  n: number;
  trigger_type: string;
  trigger_time?: string;
  status: string;
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

const SECRET_TYPES = [
  { value: 'seed', label: '🔑 Seed Phrase' },
  { value: 'password', label: '🔒 Master Password' },
  { value: 'will', label: '📜 Will / Legal Document' },
  { value: 'text', label: '💬 Private Message' },
];

const TRIGGER_TYPES = [
  { value: 'date', label: '📅 On a specific date' },
  { value: 'heartbeat', label: '💓 If I don\'t check in (Dead Man\'s Switch)' },
  { value: 'manual', label: '🖐️ Manual release' },
];

const InheritanceView: React.FC = () => {
  const { sessionToken } = useAppContext();
  const [vaults, setVaults] = useState<Vault[]>([]);
  const [error, setError] = useState<string | null>(null);

  // Creation form state
  const [creating, setCreating] = useState(false);
  const [name, setName] = useState('');
  const [secretType, setSecretType] = useState('seed');
  const [secret, setSecret] = useState('');
  const [fileInfo, setFileInfo] = useState<UploadInfo | null>(null);
  const [uploading, setUploading] = useState(false);
  const [m, setM] = useState(3);
  const [n, setN] = useState(5);
  const [triggerType, setTriggerType] = useState('manual');
  const [triggerTime, setTriggerTime] = useState('');
  const [beneficiaries, setBeneficiaries] = useState<{ name: string; contact: string }[]>([
    { name: '', contact: '' },
    { name: '', contact: '' },
    { name: '', contact: '' },
  ]);

  // Post-creation state
  const [createdShards, setCreatedShards] = useState<CreatedShardInfo[] | null>(null);

  // Recovery state
  const [recoveringVaultId, setRecoveringVaultId] = useState<string | null>(null);
  const [recoveredSecret, setRecoveredSecret] = useState<string | null>(null);

      const loadVaults = async () => {
    try {
      const rawData = await api.listInheritanceVaults(sessionToken!);
      
      // DEBUG: Log the raw data to see what we're getting
      console.log('Raw vault data:', JSON.stringify(rawData, null, 2));
      
      // Flatten the { vault: {...}, shards: [...] } structure 
      const flattenedData = rawData.map((item: any) => ({
        ...item.vault,
        shards: item.shards,
      }));
      
      // DEBUG: Log the flattened data
      console.log('Flattened vault data:', JSON.stringify(flattenedData, null, 2));
      
      setVaults(flattenedData);
    } catch (e: any) {
      setError(String(e?.message || e));
    }
  };

  useEffect(() => {
    if (sessionToken) void loadVaults();
  }, [sessionToken]);

  const addBeneficiary = () => {
    if (n < 7) {
      setN(n + 1);
      setBeneficiaries([...beneficiaries, { name: '', contact: '' }]);
    }
  };

  const removeBeneficiary = (i: number) => {
    if (n <= 2) return;
    setN(n - 1);
    setBeneficiaries(beneficiaries.filter((_, idx) => idx !== i));
  };

  const updateBeneficiary = (i: number, field: 'name' | 'contact', value: string) => {
    const updated = [...beneficiaries];
    updated[i][field] = value;
    setBeneficiaries(updated);
  };

  const handlePickFile = async () => {
    setError(null);
    setUploading(true);
    try {
      const raw = await invoke('pick_and_upload_file', { sessionToken });
      const src = Array.isArray(raw) ? raw[0] : raw;
      if (!src?.file_key) throw new Error('Upload failed.');
      setFileInfo({
        file_key: src.file_key,
        file_name: src.file_name,
        file_size: src.file_size,
        file_type: src.file_type,
      });
    } catch (e: any) {
      setError(String(e?.message || e));
    } finally {
      setUploading(false);
    }
  };

  const handleCreate = async () => {
    if (!sessionToken) return;
    setError(null);

    // Validation
    if (!name.trim()) return setError('Enter a vault name.');
    if (!secret.trim() && !fileInfo) return setError('Enter a secret OR upload a file.');
    if (secret.trim() && fileInfo) return setError('Choose either a text secret OR a file, not both.');
    if (m < 2 || m > n) return setError('Invalid threshold: require 2 ≤ M ≤ N.');
    const valid = beneficiaries.slice(0, n).every(b => b.name.trim() && b.contact.trim());
    if (!valid) return setError('All beneficiaries need name + contact.');
    if (triggerType === 'date' && !triggerTime) return setError('Pick a trigger date.');

    setCreating(true);
    try {
      const response = await api.createInheritanceVault(sessionToken, {
        name: name.trim(),
        secret_type: secretType,
        secret: secret.trim() || null,
        file_key: fileInfo?.file_key || null,
        m,
        n,
        trigger_type: triggerType,
        trigger_time: triggerType === 'date' ? new Date(triggerTime).toISOString() : null,
        beneficiaries: beneficiaries.slice(0, n).map(b => ({ name: b.name, contact: b.contact })),
      });
      setCreatedShards(response.shards);
      setSecret('');
      setFileInfo(null);
      setCreating(false);
      void loadVaults();
    } catch (e: any) {
      setError(String(e?.message || e));
      setCreating(false);
    }
  };

  const handleRecover = async (vaultId: string) => {
    if (!sessionToken) return;
    setError(null);
    setRecoveringVaultId(vaultId);
    setRecoveredSecret(null);
    try {
      const secret = await api.recoverVaultSecret(sessionToken, vaultId);
      setRecoveredSecret(secret);
    } catch (e: any) {
      setError(String(e?.message || e));
    }
  };

  const handleTrigger = async (vaultId: string) => {
    if (!sessionToken) return;
    if (!window.confirm('Release this vault now? All beneficiaries will be notified.')) return;
    try {
      await api.triggerInheritanceVault(sessionToken, vaultId);
      void loadVaults();
    } catch (e: any) {
      setError(String(e?.message || e));
    }
  };

  const handleCancel = async (vaultId: string) => {
    if (!sessionToken) return;
    if (!window.confirm('Cancel this vault? Only possible while locked.')) return;
    try {
      await api.cancelInheritanceVault(sessionToken, vaultId);
      void loadVaults();
    } catch (e: any) {
      setError(String(e?.message || e));
    }
  };

  // Post-creation screen
  if (createdShards) {
    return (
      <div className="mx-auto max-w-3xl p-6 space-y-6 fade-in">
        <div className="panel bg-[#111b21] rounded-2xl p-8 border border-[#00a884]/40">
          <h2 className="text-2xl font-bold text-[#e9edef] mb-4">🔐 Vault Created — Write Down These Codes NOW</h2>
          <div className="bg-yellow-900/20 border border-yellow-900/50 rounded-xl p-4 mb-6">
            <p className="text-sm text-yellow-200 font-bold">⚠️ These 8-digit codes are shown ONLY ONCE.</p>
            <p className="text-xs text-yellow-200/80 mt-1">
              Give each code to the named beneficiary in real life (handwritten letter, in person).
              If you lose these codes, you cannot recover them. The vault itself remains secure.
            </p>
          </div>

          <div className="space-y-3">
            {createdShards.map((s, i) => (
              <div key={i} className="panel-2 bg-[#202c33] rounded-xl p-4 flex items-center justify-between">
                <div>
                  <p className="text-sm text-[#e9edef] font-bold">{s.beneficiary_name}</p>
                  <p className="text-xs text-[#8696a0]">{s.beneficiary_contact}</p>
                </div>
                <div className="text-right">
                  <p className="text-xs text-[#8696a0] mb-1">Access Code:</p>
                  <p className="text-2xl font-mono font-bold text-[#00a884] tracking-widest">{s.access_code}</p>
                </div>
              </div>
            ))}
          </div>

          <button
            onClick={() => { setCreatedShards(null); }}
            className="btn-primary w-full mt-6 py-3 rounded-xl bg-[#00a884] hover:bg-[#06cf9c] text-white font-bold"
          >
            I've Written Them Down — Close
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="mx-auto max-w-3xl p-6 space-y-6 fade-in">
      <div className="panel bg-[#111b21] rounded-2xl p-6">
        <h2 className="text-2xl font-bold text-[#e9edef] mb-2">🧬 Digital Inheritance Vault</h2>
        <p className="text-sm text-[#8696a0] mb-6">
          Split a secret into N shards. Any M of your trusted beneficiaries can reconstruct it.
          Even if your device is destroyed, the vault survives in the cloud.
        </p>

        {error && <div className="bg-red-900/20 text-red-400 p-3 rounded-xl text-sm mb-4">{error}</div>}

        {/* Creation Form */}
        <div className="space-y-5">
          <div>
            <label className="label text-sm text-[#8696a0] block mb-2">Vault name</label>
            <input
              value={name}
              onChange={(e) => setName(e.target.value)}
              className="input w-full bg-[#202c33] text-[#e9edef] p-3 rounded-xl"
              placeholder="Family Seed Phrase Vault"
            />
          </div>

          <div>
            <label className="label text-sm text-[#8696a0] block mb-2">Secret type</label>
            <select
              value={secretType}
              onChange={(e) => setSecretType(e.target.value)}
              className="input w-full bg-[#202c33] text-[#e9edef] p-3 rounded-xl border-none"
            >
              {SECRET_TYPES.map(t => <option key={t.value} value={t.value}>{t.label}</option>)}
            </select>
          </div>

          <div>
            <label className="label text-sm text-[#8696a0] block mb-2">
              Text secret (seed phrase, password, message)
            </label>
            <textarea
              rows={4}
              value={secret}
              onChange={(e) => setSecret(e.target.value)}
              className="input w-full bg-[#202c33] text-[#e9edef] p-3 rounded-xl resize-none"
              placeholder="Enter the secret to protect (optional if uploading a file)..."
            />
          </div>

          <div>
            <label className="label text-sm text-[#8696a0] block mb-2">
              OR upload a file (will, document, photo)
            </label>
            <div className="panel-2 bg-[#202c33] rounded-xl p-4 flex items-center justify-between">
              <div className="min-w-0">
                {fileInfo ? (
                  <p className="text-sm text-[#e9edef] truncate">{fileInfo.file_name}</p>
                ) : (
                  <p className="text-sm text-[#8696a0]">No file selected</p>
                )}
              </div>
              <button
                onClick={handlePickFile}
                disabled={uploading}
                className="btn-secondary px-3 py-2 rounded-lg bg-[#2a3942] text-[#e9edef] text-sm disabled:opacity-50"
              >
                {uploading ? 'Uploading...' : fileInfo ? 'Replace' : 'Choose File'}
              </button>
            </div>
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="label text-sm text-[#8696a0] block mb-2">N (total shards)</label>
              <input
                type="number"
                min={2}
                max={7}
                value={n}
                onChange={(e) => {
                  const v = parseInt(e.target.value);
                  if (v >= 2 && v <= 7) {
                    setN(v);
                    if (m > v) setM(v);
                  }
                }}
                className="input w-full bg-[#202c33] text-[#e9edef] p-3 rounded-xl"
              />
            </div>
            <div>
              <label className="label text-sm text-[#8696a0] block mb-2">M (threshold to reconstruct)</label>
              <input
                type="number"
                min={2}
                max={n}
                value={m}
                onChange={(e) => {
                  const v = parseInt(e.target.value);
                  if (v >= 2 && v <= n) setM(v);
                }}
                className="input w-full bg-[#202c33] text-[#e9edef] p-3 rounded-xl"
              />
              <p className="text-xs text-[#8696a0] mt-1">Any {m} of {n} can reconstruct.</p>
            </div>
          </div>

          <div>
            <label className="label text-sm text-[#8696a0] block mb-2">Trigger</label>
            <select
              value={triggerType}
              onChange={(e) => setTriggerType(e.target.value)}
              className="input w-full bg-[#202c33] text-[#e9edef] p-3 rounded-xl border-none"
            >
              {TRIGGER_TYPES.map(t => <option key={t.value} value={t.value}>{t.label}</option>)}
            </select>
            {triggerType === 'date' && (
              <input
                type="datetime-local"
                value={triggerTime}
                onChange={(e) => setTriggerTime(e.target.value)}
                className="input w-full bg-[#202c33] text-[#e9edef] p-3 rounded-xl mt-3"
              />
            )}
          </div>

          {/* Beneficiaries */}
          <div>
            <div className="flex items-center justify-between mb-3">
              <label className="label text-sm text-[#8696a0]">Beneficiaries ({n})</label>
              {n < 7 && (
                <button onClick={addBeneficiary} className="btn-ghost text-xs text-[#00a884]">+ Add</button>
              )}
            </div>
            <div className="space-y-2">
              {beneficiaries.slice(0, n).map((b, i) => (
                <div key={i} className="flex gap-2">
                  <input
                    value={b.name}
                    onChange={(e) => updateBeneficiary(i, 'name', e.target.value)}
                    className="input flex-1 bg-[#202c33] text-[#e9edef] p-2 rounded-lg text-sm"
                    placeholder="Name"
                  />
                  <input
                    value={b.contact}
                    onChange={(e) => updateBeneficiary(i, 'contact', e.target.value)}
                    className="input flex-1 bg-[#202c33] text-[#e9edef] p-2 rounded-lg text-sm"
                    placeholder="Email or phone"
                  />
                  {n > 2 && (
                    <button
                      onClick={() => removeBeneficiary(i)}
                      className="btn-ghost px-3 py-2 rounded-lg bg-[#111b21] text-red-400 text-xs"
                    >
                      ✕
                    </button>
                  )}
                </div>
              ))}
            </div>
          </div>

          <button
            onClick={() => void handleCreate()}
            disabled={creating || uploading}
            className="btn-primary w-full py-3 rounded-xl bg-[#00a884] hover:bg-[#06cf9c] text-white font-bold disabled:opacity-50"
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
            {vaults.map(v => (
              <div key={v.id} className="panel-2 bg-[#202c33] rounded-xl p-4">
                <div className="flex items-start justify-between gap-4">
                  <div className="min-w-0 flex-1">
                    <p className="text-sm font-bold text-[#e9edef] truncate">{v.name}</p>
                    <p className="text-xs text-[#8696a0] mt-1">
                      {v.m}/{v.n} threshold · {v.status} · {v.trigger_type}
                    </p>
                    <div className="mt-2 space-y-1">
                      {v.shards.map(s => (
                        <p key={s.id} className="text-xs text-[#8696a0]">
                          • {s.beneficiary_name} ({s.beneficiary_contact})
                        </p>
                      ))}
                    </div>
                    {recoveringVaultId === v.id && recoveredSecret && (
                      <div className="bg-[#111b21] p-2 rounded-lg mt-2">
                        <p className="text-xs text-[#00a884] font-mono break-all">{recoveredSecret}</p>
                      </div>
                    )}
                  </div>
                  <div className="flex flex-col gap-2 shrink-0">
                    {v.status === 'locked' && v.trigger_type === 'manual' && (
                      <button
                        onClick={() => void handleTrigger(v.id)}
                        className="btn-primary px-3 py-1.5 rounded-lg bg-[#00a884] text-white text-xs"
                      >
                        🔓 Release Now
                      </button>
                    )}
                    {v.status === 'locked' && (
                      <>
                        <button
                          onClick={() => void handleRecover(v.id)}
                          className="btn-secondary px-3 py-1.5 rounded-lg bg-[#2a3942] text-[#e9edef] text-xs"
                        >
                          Recover Secret
                        </button>
                        <button
                          onClick={() => void handleCancel(v.id)}
                          className="btn-ghost px-3 py-1.5 rounded-lg bg-[#111b21] text-red-400 text-xs"
                        >
                          Cancel
                        </button>
                      </>
                    )}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};

export default InheritanceView;