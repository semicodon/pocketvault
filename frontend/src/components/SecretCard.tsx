import React, { useState, useEffect, useCallback } from 'react';
import { Eye, EyeOff, Lock, Trash2, Copy, Check, ShieldAlert, Clock } from 'lucide-react';
import { secureFetch } from '../api/secureClient.ts';

export interface MaskedSecretItem {
  id: string;
  title: string;
  maskedPreview: string;
  createdAt: string;
}

interface SecretCardProps {
  secret: MaskedSecretItem;
  onDeleted: (id: string) => void;
}

const REVEAL_DURATION_SECONDS = 10;

export const SecretCard: React.FC<SecretCardProps> = ({ secret, onDeleted }) => {
  // Ephemeral plaintext state — strictly null unless actively revealed
  const [plaintext, setPlaintext] = useState<string | null>(null);
  const [secondsLeft, setSecondsLeft] = useState<number>(0);

  // Step-Up Password Prompt state
  const [isPromptOpen, setIsPromptOpen] = useState(false);
  const [stepUpPassword, setStepUpPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [copied, setCopied] = useState(false);

  // Immediately scrubs decrypted secret from React component memory
  const wipeSecretFromMemory = useCallback(() => {
    setPlaintext(null);
    setSecondsLeft(0);
    setCopied(false);
  }, []);

  // 🛡️ DEFENSE 1: 10-Second Auto-Destruct Timer
  useEffect(() => {
    if (!plaintext) return;

    const interval = setInterval(() => {
      setSecondsLeft((prev) => {
        if (prev <= 1) {
          wipeSecretFromMemory();
          return 0;
        }
        return prev - 1;
      });
    }, 1000);

    return () => clearInterval(interval);
  }, [plaintext, wipeSecretFromMemory]);

  // 🛡️ DEFENSE 2: Instant Memory Wipe on Tab Switch (`visibilitychange`)
  useEffect(() => {
    if (!plaintext) return;

    const handleVisibilityChange = () => {
      if (document.visibilityState === 'hidden') {
        wipeSecretFromMemory();
      }
    };

    document.addEventListener('visibilitychange', handleVisibilityChange);
    return () => {
      document.removeEventListener('visibilitychange', handleVisibilityChange);
    };
  }, [plaintext, wipeSecretFromMemory]);

  const handleStepUpReveal = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!stepUpPassword) return;

    setIsLoading(true);
    setError(null);

    try {
      const res = await secureFetch(`/api/secrets/${secret.id}/reveal`, {
        method: 'POST',
        body: JSON.stringify({ password: stepUpPassword }),
      });

      // Immediately wipe the password input from state regardless of outcome
      setStepUpPassword('');

      const data = await res.json();
      if (!res.ok) {
        setError(data.error || 'Step-up verification failed');
        return;
      }

      setPlaintext(data.plaintextValue);
      setSecondsLeft(REVEAL_DURATION_SECONDS);
      setIsPromptOpen(false);
    } catch {
      setStepUpPassword('');
      setError('Network error during step-up verification');
    } finally {
      setIsLoading(false);
    }
  };

  const handleCopy = async () => {
    if (!plaintext) return;
    await navigator.clipboard.writeText(plaintext);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDelete = async () => {
    const res = await secureFetch(`/api/secrets/${secret.id}`, {
      method: 'DELETE',
    });
    if (res.ok) {
      wipeSecretFromMemory();
      onDeleted(secret.id);
    }
  };

  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900/90 p-5 shadow-lg transition hover:border-slate-700">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h3 className="text-base font-semibold text-slate-100">{secret.title}</h3>
          <p className="mt-0.5 text-xs text-slate-400">
            Encrypted with AES-256-GCM • Added {new Date(secret.createdAt).toLocaleDateString()}
          </p>
        </div>

        <button
          onClick={handleDelete}
          title="Delete secret"
          className="rounded-lg p-2 text-slate-400 transition hover:bg-rose-500/10 hover:text-rose-400"
        >
          <Trash2 className="h-4 w-4" />
        </button>
      </div>

      {/* Secret Value Display Box */}
      <div className="mt-4 flex items-center justify-between rounded-lg border border-slate-800 bg-slate-950 px-4 py-3 font-mono text-sm">
        {plaintext ? (
          <div className="flex flex-1 items-center justify-between gap-3 overflow-x-auto">
            <span className="text-emerald-400 select-all">{plaintext}</span>
            <div className="flex items-center gap-2 shrink-0">
              <span className="inline-flex items-center gap-1 rounded-full bg-amber-500/10 px-2.5 py-0.5 text-xs font-medium text-amber-400 border border-amber-500/20">
                <Clock className="h-3 w-3" />
                {secondsLeft}s
              </span>
              <button
                onClick={handleCopy}
                className="rounded-md bg-slate-800 px-2.5 py-1 text-xs font-sans text-slate-200 hover:bg-slate-700 flex items-center gap-1"
              >
                {copied ? <Check className="h-3.5 w-3.5 text-emerald-400" /> : <Copy className="h-3.5 w-3.5" />}
                {copied ? 'Copied' : 'Copy'}
              </button>
              <button
                onClick={wipeSecretFromMemory}
                className="rounded-md bg-slate-800 px-2.5 py-1 text-xs font-sans text-slate-300 hover:bg-slate-700 flex items-center gap-1"
              >
                <EyeOff className="h-3.5 w-3.5" />
                Hide
              </button>
            </div>
          </div>
        ) : (
          <div className="flex flex-1 items-center justify-between">
            <span className="tracking-wider text-slate-400">{secret.maskedPreview}</span>
            <button
              onClick={() => {
                setIsPromptOpen((prev) => !prev);
                setError(null);
              }}
              className="inline-flex items-center gap-1.5 rounded-lg bg-indigo-600/20 border border-indigo-500/30 px-3 py-1.5 font-sans text-xs font-medium text-indigo-300 transition hover:bg-indigo-600/30"
            >
              <Eye className="h-3.5 w-3.5" />
              {isPromptOpen ? 'Cancel' : 'Step-Up Reveal'}
            </button>
          </div>
        )}
      </div>

      {/* Step-Up Password Verification Drawer */}
      {isPromptOpen && !plaintext && (
        <form
          onSubmit={handleStepUpReveal}
          className="mt-3 rounded-lg border border-indigo-500/30 bg-indigo-950/20 p-3"
        >
          <div className="flex items-center gap-2 text-xs font-medium text-indigo-300 mb-2">
            <Lock className="h-3.5 w-3.5" />
            <span>Step-Up Authentication Required: Enter master password to decrypt</span>
          </div>

          <div className="flex gap-2">
            <input
              type="password"
              value={stepUpPassword}
              onChange={(e) => setStepUpPassword(e.target.value)}
              placeholder="Confirm your password..."
              autoComplete="current-password"
              required
              className="flex-1 rounded-lg border border-slate-700 bg-slate-950 px-3 py-1.5 text-sm text-slate-100 placeholder-slate-500 focus:border-indigo-500 focus:outline-none"
            />
            <button
              type="submit"
              disabled={isLoading}
              className="rounded-lg bg-indigo-600 px-4 py-1.5 text-xs font-semibold text-white transition hover:bg-indigo-500 disabled:opacity-50"
            >
              {isLoading ? 'Verifying...' : 'Unlock (10s)'}
            </button>
          </div>

          {error && (
            <div className="mt-2 flex items-center gap-1.5 text-xs text-rose-400">
              <ShieldAlert className="h-3.5 w-3.5 shrink-0" />
              <span>{error}</span>
            </div>
          )}
        </form>
      )}
    </div>
  );
};