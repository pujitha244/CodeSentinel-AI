import React, { FormEvent, useState } from 'react';
import { KeyRound, Shield } from 'lucide-react';

interface SignInPageProps {
  configured: boolean | null;
  initialError?: string | null;
  onSignIn: (token: string) => Promise<void>;
}

export const SignInPage: React.FC<SignInPageProps> = ({ configured, initialError, onSignIn }) => {
  const [token, setToken] = useState('');
  const [error, setError] = useState<string | null>(initialError ?? null);
  const [submitting, setSubmitting] = useState(false);

  const handleSubmit = async (event: FormEvent) => {
    event.preventDefault();
    if (configured === false || !token.trim()) return;

    setSubmitting(true);
    setError(null);
    try {
      await onSignIn(token);
      setToken('');
    } catch (signInError: unknown) {
      setError(signInError instanceof Error ? signInError.message : 'Sign-in failed.');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <main className="min-h-screen flex items-center justify-center px-4 py-10">
      <section className="w-full max-w-md rounded-xl border border-slate-800 bg-sentinel-900/80 p-7 shadow-xl">
        <div className="mb-6 flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-lg border border-cyan-900 bg-cyan-950/60 text-cyan-300">
            <Shield className="h-5 w-5" aria-hidden="true" />
          </div>
          <div>
            <div className="text-sm font-semibold text-slate-100">CodeSentinel AI</div>
            <div className="text-xs text-slate-500">Private single-user workspace</div>
          </div>
        </div>

        <h1 className="text-2xl font-semibold tracking-tight text-white">Sign in to your workspace</h1>
        <p className="mt-2 text-sm leading-relaxed text-slate-400">
          Enter the access token configured on this server. It is exchanged for an HTTP-only session cookie and is not stored in the browser.
        </p>

        {configured === false && (
          <p className="mt-5 border border-amber-900/60 bg-amber-950/20 px-3 py-2 text-xs leading-relaxed text-amber-200" role="alert">
            Server authentication is not configured. Set API_ACCESS_TOKEN to a random secret with at least 32 characters, then restart the backend.
          </p>
        )}
        {error && <p className="mt-4 border border-rose-900/70 bg-rose-950/30 px-3 py-2 text-xs text-rose-200" role="alert">{error}</p>}

        <form onSubmit={handleSubmit} className="mt-6 space-y-4">
          <div>
            <label htmlFor="access-token" className="mb-1.5 block text-xs font-medium text-slate-300">
              Server access token
            </label>
            <input
              id="access-token"
              type="password"
              autoComplete="current-password"
              value={token}
              onChange={(event) => setToken(event.target.value)}
              className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2.5 text-sm text-slate-100 placeholder-slate-500"
              placeholder="Paste the configured token"
              disabled={configured === false || submitting}
              required
            />
          </div>
          <button
            type="submit"
            disabled={configured === false || !token.trim() || submitting}
            className="flex w-full items-center justify-center gap-2 rounded-lg border border-cyan-700 bg-cyan-800 px-4 py-2.5 text-sm font-semibold text-white transition hover:bg-cyan-700 disabled:cursor-not-allowed disabled:opacity-50"
          >
            <KeyRound className="h-4 w-4" aria-hidden="true" />
            {submitting ? 'Signing in…' : 'Sign in'}
          </button>
        </form>

        <p className="mt-5 border-t border-slate-800 pt-4 text-[11px] leading-relaxed text-slate-500">
          This single-user token does not provide separate user accounts or per-user tenant isolation. Use HTTPS outside local development and restrict the service to trusted users.
        </p>
      </section>
    </main>
  );
};
