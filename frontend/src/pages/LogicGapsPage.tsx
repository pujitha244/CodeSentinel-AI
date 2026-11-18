import React from 'react';
import { Finding } from '../types';
import { HelpCircle, AlertTriangle, ShieldCheck, ArrowRight } from 'lucide-react';
import { SeverityBadge } from '../components/common/SeverityBadge';

interface LogicGapsPageProps {
  findings: Finding[];
}

export const LogicGapsPage: React.FC<LogicGapsPageProps> = ({ findings }) => {
  const gaps = findings.filter(f => f.category === 'logic_gap');

  return (
    <div className="page-frame flex flex-col gap-6 py-6 px-6 max-w-7xl mx-auto">
      {/* Header */}
      <div>
        <div className="flex items-center gap-2">
          <span className="px-2 py-0.5 rounded bg-sky-950 text-sky-300 border border-sky-800 text-[10px] font-mono font-bold uppercase">
            Signature Intelligence
          </span>
          <h1 className="text-2xl font-bold text-white tracking-tight">
            Coding Gap & Edge-Case Hunter
          </h1>
        </div>
        <p className="text-xs text-slate-400 mt-1">
          Investigates missing defensive validations, unhandled null states, negative bounds, and missing exception guards.
        </p>
      </div>

      {/* Gaps List */}
      <div className="space-y-4">
        {gaps.map((g) => (
          <div
            key={g.id}
            className="rounded-2xl border border-slate-800 bg-sentinel-900/60 p-6 space-y-4 backdrop-blur hover:border-slate-700 transition"
          >
            <div className="flex items-start justify-between gap-4">
              <div className="space-y-1">
                <div className="flex items-center gap-2.5">
                  <SeverityBadge severity={g.severity} size="sm" />
                  <span className="font-mono text-xs font-bold text-cyan-400">{g.id}</span>
                  <h3 className="font-bold text-sm text-slate-100">{g.title}</h3>
                </div>
                <div className="text-xs text-slate-400 font-mono">
                  Location: <span className="text-slate-300">{g.file_path}:{g.start_line}</span>
                </div>
              </div>

              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700 uppercase">
                {Math.round(g.confidence * 100)}% Confidence
              </span>
            </div>

            <p className="text-xs text-slate-300 leading-relaxed">
              {g.description}
            </p>

            {/* Triggering scenario card */}
            <div className="rounded-xl border border-sky-900/50 bg-sky-950/20 p-3.5 text-xs">
              <span className="font-semibold text-sky-300 uppercase tracking-wider text-[10px] block mb-1">
                ⚡ Triggering Edge-Case Scenario
              </span>
              <p className="text-slate-300 leading-relaxed">
                Client transmits unvalidated boundary input (null parameter, empty string, negative page number, or missing authorization token), bypassing intended application constraints.
              </p>
            </div>

            <div className="rounded-xl border border-emerald-900/40 bg-emerald-950/20 p-3 text-xs">
              <span className="font-semibold text-emerald-400 uppercase tracking-wider text-[10px] block mb-0.5">
                Defensive Remediation
              </span>
              <p className="text-slate-300">{g.recommendation}</p>
            </div>
          </div>
        ))}

        {gaps.length === 0 && (
          <div className="py-12 text-center text-xs text-slate-500 rounded-2xl border border-slate-800 bg-sentinel-900/20">
            No logic gaps or edge-case boundaries identified.
          </div>
        )}
      </div>
    </div>
  );
};
