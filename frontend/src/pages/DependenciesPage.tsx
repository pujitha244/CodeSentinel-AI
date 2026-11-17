import React from 'react';
import { Finding } from '../types';
import { PackageSearch, ShieldAlert, ArrowUpCircle, ExternalLink } from 'lucide-react';
import { SeverityBadge } from '../components/common/SeverityBadge';

interface DependenciesPageProps {
  findings: Finding[];
}

export const DependenciesPage: React.FC<DependenciesPageProps> = ({ findings }) => {
  const depFindings = findings.filter(f => f.category === 'dependency');

  return (
    <div className="flex flex-col gap-6 py-6 px-6 max-w-7xl mx-auto">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-white tracking-tight">Dependency Security & CVE Advisories</h1>
        <p className="text-xs text-slate-400 mt-1">
          Analyzes third-party manifest files (requirements.txt, package.json) against publicly disclosed CVE advisories.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {depFindings.map(d => (
          <div
            key={d.id}
            className="rounded-2xl border border-slate-800 bg-sentinel-900/60 p-5 space-y-3 backdrop-blur"
          >
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <SeverityBadge severity={d.severity} size="sm" />
                <span className="font-mono text-xs font-bold text-slate-300">{d.id}</span>
              </div>
              <span className="font-mono text-xs text-slate-400">{d.file_path}</span>
            </div>

            <h3 className="font-bold text-sm text-slate-100">{d.title}</h3>
            <p className="text-xs text-slate-300 leading-relaxed">{d.description}</p>

            {d.snippet && (
              <div className="bg-slate-950 p-2 rounded font-mono text-xs text-rose-300 border border-slate-800">
                {d.snippet}
              </div>
            )}

            <div className="bg-emerald-950/30 border border-emerald-900/50 p-2.5 rounded-lg text-xs flex items-center gap-2 text-emerald-300">
              <ArrowUpCircle className="w-4 h-4 shrink-0 text-emerald-400" />
              <span>{d.recommendation}</span>
            </div>
          </div>
        ))}

        {depFindings.length === 0 && (
          <div className="col-span-2 py-12 text-center text-xs text-slate-500 rounded-2xl border border-slate-800 bg-sentinel-900/20">
            No known CVE vulnerabilities detected in dependencies.
          </div>
        )}
      </div>
    </div>
  );
};
