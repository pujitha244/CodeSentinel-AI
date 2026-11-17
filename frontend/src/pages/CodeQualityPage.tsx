import React from 'react';
import { Audit, Finding } from '../types';
import { ScoreCard } from '../components/common/ScoreCard';
import { Code2, Copy, FileX, Scissors, AlertTriangle, Layers } from 'lucide-react';

interface CodeQualityPageProps {
  latestAudit: Audit | null;
  findings: Finding[];
}

export const CodeQualityPage: React.FC<CodeQualityPageProps> = ({ latestAudit, findings }) => {
  const qualityFindings = findings.filter(f => f.category === 'quality');
  const slopScore = latestAudit?.slop_score || 0;

  return (
    <div className="flex flex-col gap-8 py-6 px-6 max-w-7xl mx-auto">
      {/* Header */}
      <div>
        <div className="flex items-center gap-2">
          <span className="px-2 py-0.5 rounded bg-amber-950 text-amber-300 border border-amber-800 text-[10px] font-mono font-bold uppercase">
            Signature Intelligence
          </span>
          <h1 className="text-2xl font-bold text-white tracking-tight">Code Slop & Quality Intelligence</h1>
        </div>
        <p className="text-xs text-slate-400 mt-1">
          Identifies unnecessary, low-quality, and copy-pasted code with a transparent 0–100 Code Slop Score.
        </p>
      </div>

      {/* Slop Score Banner */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <ScoreCard
          title="Code Slop Score"
          score={slopScore}
          subtitle="Quantifies duplicate logic, dead code, and nesting"
          invertColors={true}
          icon={<Scissors className="w-5 h-5 text-amber-400" />}
        />

        <div className="md:col-span-2 rounded-xl border border-slate-800 bg-sentinel-900/60 p-5 flex flex-col justify-between">
          <div>
            <h4 className="text-xs font-bold uppercase tracking-wider text-slate-400 mb-2">
              Scoring Methodology & Transparency
            </h4>
            <p className="text-xs text-slate-300 leading-relaxed">
              CodeSentinel calculates Code Slop from 0 to 100 based on concrete AST observations rather than arbitrary AI ratings.
              Deductions are applied for duplicate block occurrences, unreferenced import declarations, dead functions with zero call-graph reachability, and deep nesting.
            </p>
          </div>
          <div className="mt-4 flex flex-wrap gap-4 text-xs font-mono text-slate-400">
            <span className="flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full bg-amber-500" /> Duplicate blocks: -12.5 pts
            </span>
            <span className="flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full bg-rose-500" /> Dead functions: -10 pts
            </span>
            <span className="flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full bg-cyan-500" /> Unused imports: -5 pts
            </span>
          </div>
        </div>
      </div>

      {/* Discovered Slop Findings */}
      <div className="rounded-2xl border border-slate-800 bg-sentinel-900/60 p-6 space-y-4">
        <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
          <Code2 className="w-4 h-4 text-cyan-400" />
          Detected Code Quality & Slop Observations ({qualityFindings.length})
        </h3>

        <div className="divide-y divide-slate-800">
          {qualityFindings.map((q) => (
            <div key={q.id} className="py-4 space-y-2">
              <div className="flex items-center justify-between">
                <span className="font-semibold text-xs text-slate-200">{q.title}</span>
                <span className="font-mono text-xs text-slate-400">{q.file_path}:{q.start_line}</span>
              </div>
              <p className="text-xs text-slate-400">{q.description}</p>
              {q.snippet && (
                <div className="bg-slate-950 p-2.5 rounded font-mono text-xs text-amber-300 border border-slate-800/80">
                  {q.snippet}
                </div>
              )}
              <div className="text-xs text-emerald-400">
                <strong>Remediation:</strong> {q.recommendation}
              </div>
            </div>
          ))}

          {qualityFindings.length === 0 && (
            <div className="py-8 text-center text-xs text-slate-500">
              No severe code slop or quality regressions found.
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
