import React, { useEffect, useState } from 'react';
import { api } from '../services/api';
import { AlertCircle, CheckCircle2, Shield, Cpu, Lock } from 'lucide-react';

export const SettingsPage: React.FC = () => {
  const [healthData, setHealthData] = useState<Awaited<ReturnType<typeof api.getHealth>> | null>(null);
  const [healthError, setHealthError] = useState<string | null>(null);
  const [healthLoading, setHealthLoading] = useState(true);

  useEffect(() => {
    let active = true;
    api.getHealth()
      .then((health) => {
        if (active) setHealthData(health);
      })
      .catch((error: unknown) => {
        if (active) {
          setHealthError(error instanceof Error ? error.message : 'Backend health check failed.');
        }
      })
      .finally(() => {
        if (active) setHealthLoading(false);
      });
    return () => {
      active = false;
    };
  }, []);

  const scanners = [
    { name: 'Python AST + limited JS/TS parsing', status: 'Built-in', desc: 'Python-focused interprocedural taint flow; JS/TS cross-file flow is not implemented' },
    { name: 'Cross-File Taint Analysis', status: 'Python-focused', desc: 'Static source-to-sink propagation through supported calls and assignments' },
    { name: 'Secret Sentinel (Gitleaks Patterns)', status: 'Active', desc: 'Detects AWS keys, JWT tokens, private keys, passwords' },
    { name: 'Dependency Advisory Catalog', status: 'Limited catalog', desc: 'Matches a small built-in advisory list; not a live OSV feed or complete dependency audit' },
    { name: 'Code Slop Intelligence Engine', status: 'Active', desc: 'Identifies dead code, duplicate blocks, and cyclomatic complexity' },
    { name: 'Coding Gap & Edge-Case Hunter', status: 'Active', desc: 'Identifies missing null guards, boundary errors, unhandled I/O' }
  ];

  return (
    <div className="page-frame flex flex-col gap-8 py-6 px-6 max-w-5xl mx-auto">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-white tracking-tight">Platform Settings & Scanner Status</h1>
        <p className="text-xs text-slate-400 mt-1">
          Review scanner engines, AI provider modes, and isolated workspace security controls.
        </p>
      </div>

      {/* System Health Status */}
      <div className="rounded-2xl border border-slate-800 bg-sentinel-900/60 p-6 flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className={`p-3 rounded-xl border ${healthError ? 'bg-rose-950 border-rose-800 text-rose-400' : 'bg-emerald-950 border-emerald-800 text-emerald-400'}`}>
            {healthError ? <AlertCircle className="w-6 h-6" /> : <CheckCircle2 className="w-6 h-6" />}
          </div>
          <div>
            <h3 className="font-bold text-sm text-slate-100">
              {healthLoading ? 'Checking analysis backend…' : healthError ? 'Backend health check failed' : `Backend status: ${healthData?.status}`}
            </h3>
            <p className="text-xs text-slate-400 mt-0.5 font-mono">
              {healthData ? `Service: ${healthData.service} • Version: ${healthData.version}` : healthError || 'Waiting for health response'}
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2 text-xs font-mono px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-cyan-400">
          <Cpu className="w-4 h-4 text-cyan-400" />
          <span>Analysis mode: {healthData?.ai_provider || 'Unknown'}</span>
        </div>
      </div>

      {/* Active Scanner Engines */}
      <div className="rounded-2xl border border-slate-800 bg-sentinel-900/60 p-6 space-y-4">
        <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
          <Shield className="w-4 h-4 text-cyan-400" />
          Security & Engineering Analysis Engines
        </h3>

        <div className="divide-y divide-slate-800/80">
          {scanners.map((s, i) => (
            <div key={i} className="py-3 flex items-center justify-between">
              <div>
                <div className="font-semibold text-xs text-slate-200">{s.name}</div>
                <div className="text-[11px] text-slate-400 mt-0.5">{s.desc}</div>
              </div>
              <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-800">
                {s.status}
              </span>
            </div>
          ))}
        </div>
      </div>

      {/* Security Boundaries */}
      <div className="rounded-2xl border border-slate-800 bg-sentinel-900/60 p-6 space-y-3">
        <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
          <Lock className="w-4 h-4 text-indigo-400" />
          Security Policy & Execution Isolation
        </h3>
        <ul className="space-y-2 text-xs text-slate-300">
          <li className="flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
            <span>Untrusted code is never executed on the host system during static analysis.</span>
          </li>
          <li className="flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
            <span>ZIP extraction verifies path traversal boundaries (Zip-Slip defense) and file size quotas.</span>
          </li>
          <li className="flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
            <span>Exposed secrets and keys are automatically redacted in snippet previews for safe auditing.</span>
          </li>
          <li className="flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
            <span>Remediation patches create automatic backups (.codesentinel_backup) for safe rollback.</span>
          </li>
        </ul>
        <p className="border border-amber-900/60 bg-amber-950/20 px-3 py-2 text-xs leading-relaxed text-amber-200">
          API authentication is disabled by default for local development. Set API_AUTH_ENABLED=true and configure a strong API_ACCESS_TOKEN before exposing the API beyond a trusted local machine. This is a single shared identity, not per-user tenant isolation.
        </p>
      </div>
    </div>
  );
};
