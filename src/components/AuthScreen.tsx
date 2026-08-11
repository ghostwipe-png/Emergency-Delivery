import React, { useState, FormEvent, useEffect } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { LazyStore } from '@tauri-apps/plugin-store';
import { useAppContext } from '../context/AppContext';

const settingsStore = new LazyStore('settings.json');
type AuthMode = 'login' | 'register';

const AuthScreen: React.FC = () => {
  const { login, register, completeTwoFactor, cancelTwoFactor, pending, loginWithToken } = useAppContext() as any;

  const [mode, setMode] = useState<AuthMode>('login');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [remember, setRemember] = useState(true);
  
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [twoFactorCode, setTwoFactorCode] = useState('');
  
  // Phase 7: Biometric State
  const [lastEmail, setLastEmail] = useState<string | null>(null);

  useEffect(() => {
    settingsStore.get<string>('last_email').then((savedEmail) => {
      if (savedEmail) {
        setLastEmail(savedEmail);
        setEmail(savedEmail);
      }
    });
  }, []);

  const handleAuthSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);

    try {
      if (mode === 'register') {
        if (password !== confirmPassword) throw new Error('Passwords do not match.');
        if (password.length < 8) throw new Error('Password must be at least 8 characters.');
        await register(email, password);
      } else {
        await login(email, password, remember);
        if (remember) {
          await settingsStore.set('last_email', email);
          await settingsStore.save();
        }
      }
    } catch (err: any) {
      setError(err.message || 'Authentication failed. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const handleBiometricLogin = async () => {
    if (!lastEmail) return;
    setError(null);
    setLoading(true);
    try {
      // Triggers OS prompt and returns AuthResponse
      const res = await invoke<any>('login_with_biometrics', { email: lastEmail });
      if (loginWithToken) {
        loginWithToken(res.token, res.user);
      } else {
        window.location.reload(); // Fallback if context method is missing
      }
    } catch (err: any) {
      setError(err.message || 'Biometric unlock failed or was cancelled.');
    } finally {
      setLoading(false);
    }
  };

  const handle2FASubmit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    if (twoFactorCode.length !== 6) {
      setError('Please enter the 6-digit code.');
      return;
    }
    setLoading(true);
    try {
      await completeTwoFactor(twoFactorCode);
    } catch (err: any) {
      setError(err.message || 'Invalid 2FA code.');
    } finally {
      setLoading(false);
    }
  };

  // 2FA SCREEN
  if (pending) {
    return (
      <div className="flex items-center justify-center h-screen bg-[#0b141a] text-[#e9edef] p-4">
        <div className="w-full max-w-md bg-[#111b21] p-8 rounded-2xl fade-in">
          <h2 className="text-2xl font-bold mb-2 text-center">Two-Factor Authentication</h2>
          <p className="text-[#8696a0] text-center mb-6">Enter the 6-digit code from your authenticator app.</p>
          <form onSubmit={handle2FASubmit} className="space-y-4">
            <div>
              <label className="label block text-sm text-[#8696a0] mb-2">Authentication Code</label>
              <input type="text" inputMode="numeric" maxLength={6} value={twoFactorCode} onChange={(e) => setTwoFactorCode(e.target.value.replace(/\D/g, ''))} className="input w-full bg-[#202c33] text-[#e9edef] p-4 text-center text-2xl tracking-widest rounded-xl outline-none focus:ring-2 focus:ring-[#00a884] transition-all" placeholder="000000" autoFocus />
            </div>
            {error && <p className="text-red-400 text-sm text-center">{error}</p>}
            <button type="submit" disabled={loading} className="btn-primary w-full bg-[#00a884] hover:bg-[#06cf9c] text-white font-bold py-3 rounded-xl transition-colors disabled:opacity-50">
              {loading ? 'Verifying...' : 'Verify Code'}
            </button>
            <button type="button" onClick={() => { cancelTwoFactor(); setTwoFactorCode(''); setError(null); }} className="btn-ghost w-full py-2 text-[#8696a0] hover:text-[#e9edef] transition-colors text-sm">
              Back to Login
            </button>
          </form>
        </div>
      </div>
    );
  }

  // AUTH SCREEN (Login / Register)
  return (
    <div className="flex items-center justify-center h-screen bg-[#0b141a] text-[#e9edef] p-4">
      <div className="w-full max-w-md bg-[#111b21] p-8 rounded-2xl fade-in">
        <div className="text-center mb-8">
          <h1 className="text-3xl font-bold text-[#00a884] mb-2">Emergency Delivery</h1>
          <p className="text-[#8696a0]">Secure messaging and file delivery</p>
        </div>

        {/* Phase 7: Biometric Quick Unlock */}
        {mode === 'login' && lastEmail && (
          <div className="mb-6 p-4 bg-[#202c33] rounded-xl border border-[#2a3942]">
            <p className="text-xs text-[#8696a0] mb-2 text-center">Welcome back, <span className="text-[#e9edef] font-semibold">{lastEmail}</span></p>
            <button
              type="button"
              onClick={handleBiometricLogin}
              disabled={loading}
              className="btn-primary w-full bg-[#00a884] hover:bg-[#06cf9c] text-white font-bold py-3 rounded-xl transition-colors disabled:opacity-50 flex items-center justify-center gap-2"
            >
              🔓 {loading ? 'Waiting for OS Prompt...' : 'Unlock with Biometrics'}
            </button>
            <button
              type="button"
              onClick={() => { setLastEmail(null); setEmail(''); setPassword(''); }}
              className="w-full mt-2 text-xs text-[#8696a0] hover:text-[#e9edef] transition-colors"
            >
              Use a different account
            </button>
          </div>
        )}

        {/* Tabs (Only show if not using biometric quick unlock) */}
        {(!lastEmail || mode === 'register') && (
          <>
            <div className="flex bg-[#202c33] p-1 rounded-xl mb-6">
              <button onClick={() => { setMode('login'); setError(null); }} className={`flex-1 py-2 rounded-lg font-medium transition-colors ${mode === 'login' ? 'bg-[#2a3942] text-[#e9edef]' : 'text-[#8696a0] hover:text-[#e9edef]'}`}>Login</button>
              <button onClick={() => { setMode('register'); setError(null); }} className={`flex-1 py-2 rounded-lg font-medium transition-colors ${mode === 'register' ? 'bg-[#2a3942] text-[#e9edef]' : 'text-[#8696a0] hover:text-[#e9edef]'}`}>Register</button>
            </div>

            <form onSubmit={handleAuthSubmit} className="space-y-4">
              <div>
                <label className="label block text-sm text-[#8696a0] mb-2">Email Address</label>
                <input type="email" required value={email} onChange={(e) => setEmail(e.target.value)} className="input w-full bg-[#202c33] text-[#e9edef] p-3 rounded-xl outline-none focus:ring-2 focus:ring-[#00a884] transition-all" placeholder="you@example.com" autoComplete="email" />
              </div>

              <div>
                <label className="label block text-sm text-[#8696a0] mb-2">Password</label>
                <input type="password" required value={password} onChange={(e) => setPassword(e.target.value)} className="input w-full bg-[#202c33] text-[#e9edef] p-3 rounded-xl outline-none focus:ring-2 focus:ring-[#00a884] transition-all" placeholder="••••••••" autoComplete={mode === 'login' ? 'current-password' : 'new-password'} />
              </div>

              {mode === 'register' && (
                <div>
                  <label className="label block text-sm text-[#8696a0] mb-2">Confirm Password</label>
                  <input type="password" required value={confirmPassword} onChange={(e) => setConfirmPassword(e.target.value)} className="input w-full bg-[#202c33] text-[#e9edef] p-3 rounded-xl outline-none focus:ring-2 focus:ring-[#00a884] transition-all" placeholder="••••••••" autoComplete="new-password" />
                </div>
              )}

              {mode === 'login' && (
                <div className="flex items-center">
                  <input id="remember" type="checkbox" checked={remember} onChange={(e) => setRemember(e.target.checked)} className="w-4 h-4 rounded bg-[#202c33] border-none text-[#00a884] focus:ring-[#00a884] focus:ring-offset-0 focus:ring-offset-[#111b21]" />
                  <label htmlFor="remember" className="ml-2 text-sm text-[#8696a0] cursor-pointer select-none">Remember me on this device</label>
                </div>
              )}

              {error && <div className="bg-red-900/20 text-red-400 p-3 rounded-xl text-sm text-center">{error}</div>}

              <button type="submit" disabled={loading} className="btn-primary w-full bg-[#00a884] hover:bg-[#06cf9c] text-white font-bold py-3 rounded-xl transition-colors disabled:opacity-50 mt-2">
                {loading ? 'Please wait...' : (mode === 'login' ? 'Sign In' : 'Create Account')}
              </button>
            </form>
          </>
        )}
      </div>
    </div>
  );
};

export default AuthScreen;