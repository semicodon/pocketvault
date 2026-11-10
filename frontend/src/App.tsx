import React, { useState, useEffect } from 'react';
import {
  ShieldCheck,
  KeyRound,
  PlusCircle,
  LogOut,
  Lock,
  AlertCircle,
  CheckCircle2,
} from 'lucide-react';
import {
  AuthUser,
  attemptSilentRefresh,
  secureFetch,
  setMemoryToken,
  clearMemoryToken,} from "./api/secureClient";
import { SecretCard, type MaskedSecretItem } from './components/SecretCard';

export function App() {
  const [user, setUser] = useState<AuthUser | null>(null);
  const [isBootstrapping, setIsBootstrapping] = useState(true);

  // Auth Form State
  const [authMode, setAuthMode] = useState<'login' | 'register'>('login');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [authError, setAuthError] = useState<string | null>(null);
  const [authSuccess, setAuthSuccess] = useState<string | null>(null);
  const [isSubmittingAuth, setIsSubmittingAuth] = useState(false);

  // Vault Secrets State
  const [secrets, setSecrets] = useState<MaskedSecretItem[]>([]);
  const [title, setTitle] = useState('');
  const [secretValue, setSecretValue] = useState('');
  const [vaultError, setVaultError] = useState<string | null>(null);
  const [isCreating, setIsCreating] = useState(false);

  // 1. On Initial Page Load / F5: Restore session via HttpOnly cookie silent refresh
  useEffect(() => {
    let isMounted = true;
    (async () => {
      const restoredUser = await attemptSilentRefresh();
      if (isMounted && restoredUser) {
        setUser(restoredUser);
      }
      if (isMounted) {
        setIsBootstrapping(false);
      }
    })();
    return () => {
      isMounted = false;
    };
  }, []);

  // 2. Load Masked Secrets List when authenticated
  useEffect(() => {
    if (!user) {
      setSecrets([]);
      return;
    }

    (async () => {
      const res = await secureFetch('/api/secrets');
      if (res.ok) {
        const data = await res.json();
        setSecrets(data.secrets);
      }
    })();
  }, [user]);

  const handleAuthSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setAuthError(null);
    setAuthSuccess(null);
    setIsSubmittingAuth(true);

    try {
      const endpoint = authMode === 'login' ? '/api/auth/login' : '/api/auth/register';
      const res = await secureFetch(endpoint, {
        method: 'POST',
        body: JSON.stringify({ email, password }),
      });

      const data = await res.json();
      if (!res.ok) {
        const fieldErrors = data.details
          ? Object.values(data.details).flat().join(' • ')
          : null;
        setAuthError(fieldErrors || data.error || 'Authentication failed');
        return;
      }

      if (authMode === 'register') {
        setAuthSuccess('Account created with Argon2id! Please sign in.');
        setAuthMode('login');
        setPassword('');
        return;
      }

      // Login success: Store 15m JWT in private module closure RAM
      setMemoryToken(data.accessToken);
      setUser(data.user);
      setPassword('');
    } catch {
      setAuthError('Unable to reach PocketVault API server.');
    } finally {
      setIsSubmittingAuth(false);
    }
  };

  const handleCreateSecret = async (e: React.FormEvent) => {
    e.preventDefault();
    setVaultError(null);
    setIsCreating(true);

    try {
      const res = await secureFetch('/api/secrets', {
        method: 'POST',
        body: JSON.stringify({ title, secretValue }),
      });

      const data = await res.json();
      if (!res.ok) {
        setVaultError(data.error || 'Failed to encrypt and store secret');
        return;
      }

      // Immediately scrub plaintext inputs from React memory
      setTitle('');
      setSecretValue('');
      setSecrets((prev) => [data.secret, ...prev]);
    } catch {
      setVaultError('Network error while saving secret');
    } finally {
      setIsCreating(false);
    }
  };

  const handleLogout = async () => {
    await secureFetch('/api/auth/logout', { method: 'POST' });
    clearMemoryToken();
    setUser(null);
    setSecrets([]);
  };

  if (isBootstrapping) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-slate-950 text-slate-400">
        <div className="flex items-center gap-3 text-sm">
          <ShieldCheck className="h-5 w-5 animate-pulse text-indigo-400" />
          <span>Verifying Zero-Trust Session...</span>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100">
      {/* Top Security Telemetry Banner */}
      <header className="border-b border-slate-800/80 bg-slate-900/60 backdrop-blur">
        <div className="mx-auto flex max-w-4xl items-center justify-between px-6 py-4">
          <div className="flex items-center gap-2.5">
            <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-indigo-600/20 border border-indigo-500/30">
              <ShieldCheck className="h-5 w-5 text-indigo-400" />
            </div>
            <div>
              <h1 className="text-lg font-bold tracking-tight text-white">PocketVault</h1>
              <p className="text-xs text-slate-400">
                AES-256-GCM • Argon2id • Closure RAM JWT • Step-Up Reveal
              </p>
            </div>
          </div>

          {user && (
            <div className="flex items-center gap-4">
              <span className="hidden text-xs text-slate-400 sm:inline">
                Signed in as <strong className="text-slate-200">{user.email}</strong>
              </span>
              <button
                onClick={handleLogout}
                className="inline-flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800/80 px-3 py-1.5 text-xs font-medium text-slate-200 transition hover:bg-slate-700"
              >
                <LogOut className="h-3.5 w-3.5" />
                Sign Out
              </button>
            </div>
          )}
        </div>
      </header>

      <main className="mx-auto max-w-4xl px-6 py-10">
        {!user ? (
          /* ================= AUTHENTICATION CARD ================= */
          <div className="mx-auto max-w-md rounded-2xl border border-slate-800 bg-slate-900/80 p-8 shadow-2xl">
            <div className="mb-6 flex items-center gap-2 text-indigo-400">
              <Lock className="h-5 w-5" />
              <h2 className="text-xl font-bold text-white">
                {authMode === 'login' ? 'Unlock Your Vault' : 'Create Zero-Trust Vault'}
              </h2>
            </div>

            {authError && (
              <div className="mb-4 flex items-start gap-2 rounded-lg border border-rose-500/30 bg-rose-950/30 p-3 text-xs text-rose-300">
                <AlertCircle className="h-4 w-4 shrink-0 text-rose-400" />
                <span>{authError}</span>
              </div>
            )}

            {authSuccess && (
              <div className="mb-4 flex items-start gap-2 rounded-lg border border-emerald-500/30 bg-emerald-950/30 p-3 text-xs text-emerald-300">
                <CheckCircle2 className="h-4 w-4 shrink-0 text-emerald-400" />
                <span>{authSuccess}</span>
              </div>
            )}

            <form onSubmit={handleAuthSubmit} className="space-y-4">
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">
                  Email Address
                </label>
                <input
                  type="email"
                  required
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="alice@pocketvault.dev"
                  className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3.5 py-2 text-sm text-white placeholder-slate-500 focus:border-indigo-500 focus:outline-none"
                />
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">
                  Master Password
                </label>
                <input
                  type="password"
                  required
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="Min 10 chars, 1 uppercase, 1 number"
                  className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3.5 py-2 text-sm text-white placeholder-slate-500 focus:border-indigo-500 focus:outline-none"
                />
              </div>

              <button
                type="submit"
                disabled={isSubmittingAuth}
                className="w-full rounded-lg bg-indigo-600 py-2.5 text-sm font-semibold text-white transition hover:bg-indigo-500 disabled:opacity-50"
              >
                {isSubmittingAuth
                  ? 'Processing...'
                  : authMode === 'login'
                    ? 'Sign In (Mint RAM Token)'
                    : 'Register (Argon2id Hash)'}
              </button>
            </form>

            <div className="mt-6 border-t border-slate-800 pt-4 text-center text-xs text-slate-400">
              {authMode === 'login' ? (
                <>
                  Need a vault account?{' '}
                  <button
                    onClick={() => {
                      setAuthMode('register');
                      setAuthError(null);
                    }}
                    className="font-semibold text-indigo-400 hover:underline"
                  >
                    Register here
                  </button>
                </>
              ) : (
                <>
                  Already registered?{' '}
                  <button
                    onClick={() => {
                      setAuthMode('login');
                      setAuthError(null);
                    }}
                    className="font-semibold text-indigo-400 hover:underline"
                  >
                    Sign in
                  </button>
                </>
              )}
            </div>
          </div>
        ) : (
          /* ================= AUTHENTICATED VAULT DASHBOARD ================= */
          <div className="space-y-8">
            {/* Store New Secret Form */}
            <section className="rounded-2xl border border-slate-800 bg-slate-900/70 p-6 shadow-xl">
              <div className="mb-4 flex items-center gap-2 text-indigo-400">
                <PlusCircle className="h-5 w-5" />
                <h2 className="text-base font-semibold text-white">
                  Encrypt & Store New API Key / Secret
                </h2>
              </div>

              <form onSubmit={handleCreateSecret} className="grid gap-4 sm:grid-cols-12">
                <div className="sm:col-span-4">
                  <input
                    type="text"
                    required
                    value={title}
                    onChange={(e) => setTitle(e.target.value)}
                    placeholder="Label (e.g., Stripe Live Key)"
                    className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3.5 py-2 text-sm text-white placeholder-slate-500 focus:border-indigo-500 focus:outline-none"
                  />
                </div>
                <div className="sm:col-span-6">
                  <input
                    type="password"
                    required
                    value={secretValue}
                    onChange={(e) => setSecretValue(e.target.value)}
                    placeholder="Secret value (e.g., sk_live_9988776655)"
                    className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3.5 py-2 font-mono text-sm text-white placeholder-slate-500 focus:border-indigo-500 focus:outline-none"
                  />
                </div>
                <div className="sm:col-span-2">
                  <button
                    type="submit"
                    disabled={isCreating}
                    className="w-full rounded-lg bg-indigo-600 px-4 py-2 text-sm font-semibold text-white transition hover:bg-indigo-500 disabled:opacity-50"
                  >
                    {isCreating ? 'Locking...' : 'Encrypt'}
                  </button>
                </div>
              </form>

              {vaultError && (
                <p className="mt-3 text-xs text-rose-400">{vaultError}</p>
              )}
            </section>

            {/* Masked Secrets List */}
            <section className="space-y-4">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <KeyRound className="h-4 w-4 text-indigo-400" />
                  <h2 className="text-sm font-semibold uppercase tracking-wider text-slate-300">
                    Stored Vault Secrets ({secrets.length})
                  </h2>
                </div>
                <span className="text-xs text-slate-500">
                  Auto-wipes after 10s or on browser tab switch
                </span>
              </div>

              {secrets.length === 0 ? (
                <div className="rounded-xl border border-dashed border-slate-800 p-10 text-center text-sm text-slate-500">
                  Your vault is empty. Add an API key or secret above to encrypt it with AES-256-GCM.
                </div>
              ) : (
                <div className="space-y-3">
                  {secrets.map((secret) => (
                    <SecretCard
                      key={secret.id}
                      secret={secret}
                      onDeleted={(id) =>
                        setSecrets((prev) => prev.filter((item) => item.id !== id))
                      }
                    />
                  ))}
                </div>
              )}
            </section>
          </div>
        )}
      </main>
    </div>
  );
}

export default App;