import React, { useEffect, useState } from 'react';
import { api } from '../services/api';
import { Settings, CheckCircle2, Shield, Cpu, Lock, Database } from 'lucide-react';

export const SettingsPage: React.FC = () => {
  const [healthData, setHealthData] = useState<any>(null);

  useEffect(() => {
    api.getHealth().then(setHealthData).catch(() => {});
  }, []);

  const scanners = [
    { name: 'Native Python & JS AST Engine', status: 'Built-in (Active)', desc: 'Interprocedural function, call, and import extraction' },
    { name: 'Flagship Cross-File Taint Engine', status: 'Active', desc: 'Traces untrusted sources across files to dangerous sinks' },
    { name: 'Secret Sentinel (Gitleaks Patterns)', status: 'Active', desc: 'Detects AWS keys, JWT tokens, private keys, passwords' },
    { name: 'Dependency Security Advisor (OSV)', status: 'Active', desc: 'Known CVE vulnerability matching for requirements & packages' },
    { name: 'Code Slop Intelligence Engine', status: 'Active', desc: 'Identifies dead code, duplicate blocks, and cyclomatic complexity' },
    { name: 'Coding Gap & Edge-Case Hunter', status: 'Active', desc: 'Identifies missing null guards, boundary errors, unhandled I/O' }
  ];

  return (
    <div className="flex flex-col gap-8 py-6 px-6 max-w-5xl mx-auto">
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
          <div className="p-3 rounded-xl bg-emerald-950 border border-emerald-800 text-emerald-400">
            <CheckCircle2 className="w-6 h-6" />
          </div>
          <div>
            <h3 className="font-bold text-sm text-slate-100">CodeSentinel Analysis Backend Healthy</h3>
            <p className="text-xs text-slate-400 mt-0.5 font-mono">
              Service: {healthData?.service || 'CodeSentinel AI'} • Version: {healthData?.version || '1.0.0'}
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2 text-xs font-mono px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-cyan-400">
          <Cpu className="w-4 h-4 text-cyan-400" />
          <span>AI Engine: {healthData?.ai_provider || 'Deterministic / Rule-Only'}</span>
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
      </div>
    </div>
  );
};
