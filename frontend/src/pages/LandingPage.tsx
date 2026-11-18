import React from 'react';
import { useNavigate } from 'react-router-dom';
import { 
  Shield, 
  GitMerge, 
  Sparkles, 
  Layers, 
  Wrench, 
  ArrowRight, 
  CheckCircle2, 
  Flame, 
  FileCode2, 
  Activity,
  Play
} from 'lucide-react';

interface LandingPageProps {
  onLoadDemo: () => void;
  isLoadingDemo?: boolean;
}

export const LandingPage: React.FC<LandingPageProps> = ({ onLoadDemo, isLoadingDemo }) => {
  const navigate = useNavigate();

  const differentiators = [
    {
      title: 'Cross-File Vulnerability Chains',
      desc: 'Python-focused interprocedural taint analysis traces supported untrusted inputs across function calls to dynamic SQL and command expressions.',
      icon: GitMerge,
      badge: 'Flagship Intelligence',
      badgeColor: 'border-rose-800 bg-rose-950/70 text-rose-300'
    },
    {
      title: 'Code Slop Intelligence',
      desc: 'Transparent 0–100 scoring quantifying duplicate logic, dead functions, unused imports, and excessive cyclomatic nesting with documented deductions.',
      icon: FileCode2,
      badge: 'Engineering Quality',
      badgeColor: 'border-amber-800 bg-amber-950/70 text-amber-300'
    },
    {
      title: 'Coding Gap & Edge-Case Hunter',
      desc: 'Proactively identifies missing null guards, boundary conditions, unhandled I/O exceptions, and missing authentication with triggering scenarios.',
      icon: Activity,
      badge: 'Defensive Assurance',
      badgeColor: 'border-sky-800 bg-sky-950/70 text-sky-300'
    },
    {
      title: 'Safe Auto-Fix Remediation Lab',
      desc: 'Preview evidence-backed unified diff patches with explicit user approval, isolated file application, automated static verification, and instant rollback.',
      icon: Wrench,
      badge: 'Review-Gated Remediation',
      badgeColor: 'border-emerald-800 bg-emerald-950/70 text-emerald-300'
    }
  ];

  const workflowSteps = [
    { step: '01', title: 'UNDERSTAND', desc: 'Index repository AST, classes, functions, imports, and cross-module relationships.' },
    { step: '02', stepName: 'DETECT', desc: 'Execute multi-engine static rules, Gitleaks pattern secrets, and CVE dependency advisor.' },
    { step: '03', title: 'CORRELATE', desc: 'Connect sources to sinks across files into unified parent vulnerability chains.' },
    { step: '04', title: 'REMEDIATE', desc: 'Synthesize reviewable unified diffs and verify fix via scanner re-execution.' }
  ];

  return (
    <div className="page-frame flex flex-col gap-12 py-8 px-4 max-w-6xl mx-auto">
      {/* Hero Section */}
      <section className="text-center relative py-12">
        <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded border border-slate-700 bg-slate-900 text-slate-300 text-xs font-mono font-semibold mb-6">
          <Shield className="w-3.5 h-3.5 text-cyan-400" />
          <span>Repository security review</span>
        </div>

        <h1 className="text-4xl sm:text-6xl font-extrabold tracking-tight text-white max-w-4xl mx-auto leading-tight">
          Understand Your Code. <br className="hidden sm:inline" />
          <span className="text-cyan-300">
            Discover Hidden Risks.
          </span> <br className="hidden sm:inline" />
          Fix With Confidence.
        </h1>

        <p className="mt-6 text-base sm:text-lg text-slate-400 max-w-2xl mx-auto leading-relaxed">
          Static security analysis and code intelligence for repository evidence.
          Trace supported Python source-to-sink paths, inspect findings, and review targeted remediation before applying changes.
        </p>

        {/* Action CTAs */}
        <div className="mt-8 flex flex-col sm:flex-row items-center justify-center gap-4">
          <button
            onClick={onLoadDemo}
            disabled={isLoadingDemo}
            className="w-full sm:w-auto flex items-center justify-center gap-2.5 px-6 py-3.5 rounded-lg border border-cyan-700 bg-cyan-800 hover:bg-cyan-700 text-white font-semibold text-sm transition disabled:opacity-50"
          >
            <Play className="w-4 h-4 fill-current" />
            <span>{isLoadingDemo ? 'Launching Demo...' : 'Try Flagship Demo Project'}</span>
            <ArrowRight className="w-4 h-4 ml-1" />
          </button>

          <button
            onClick={() => navigate('/audit/new')}
            className="w-full sm:w-auto flex items-center justify-center gap-2 px-6 py-3.5 rounded-xl border border-slate-700 bg-slate-900/80 hover:bg-slate-800 text-slate-200 font-semibold text-sm transition"
          >
            <span>Upload or Ingest Repository</span>
          </button>
        </div>

        {/* Trust Badges */}
        <div className="mt-10 flex flex-wrap items-center justify-center gap-6 text-xs text-slate-500">
          <span className="flex items-center gap-1.5">
            <CheckCircle2 className="w-4 h-4 text-emerald-400" /> Real Multi-Tier Python Demo
          </span>
          <span className="flex items-center gap-1.5">
            <CheckCircle2 className="w-4 h-4 text-emerald-400" /> Static source-to-sink evidence
          </span>
          <span className="flex items-center gap-1.5">
            <CheckCircle2 className="w-4 h-4 text-emerald-400" /> No execution of project code
          </span>
          <span className="flex items-center gap-1.5">
            <CheckCircle2 className="w-4 h-4 text-emerald-400" /> Rule-based analysis
          </span>
        </div>
      </section>

      {/* Differentiators Grid */}
      <section className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {differentiators.map((d, i) => {
          const Icon = d.icon;
          return (
            <div
              key={i}
              className="rounded-2xl border border-slate-800 bg-sentinel-900/60 p-6 backdrop-blur hover:border-slate-700 transition"
            >
              <div className="flex items-center justify-between mb-4">
                <div className="p-2.5 rounded-xl bg-slate-800 text-cyan-400">
                  <Icon className="w-5 h-5" />
                </div>
                <span className={`text-[10px] font-mono px-2 py-0.5 rounded-full border uppercase font-bold ${d.badgeColor}`}>
                  {d.badge}
                </span>
              </div>
              <h3 className="text-lg font-bold text-slate-100 mb-2">{d.title}</h3>
              <p className="text-xs text-slate-400 leading-relaxed">{d.desc}</p>
            </div>
          );
        })}
      </section>

      {/* Core Workflow Pipeline */}
      <section className="rounded-2xl border border-slate-800 bg-sentinel-900/30 p-8">
        <div className="text-center mb-8">
          <span className="text-xs font-mono font-bold uppercase tracking-wider text-cyan-400">
            Autonomous Engine Pipeline
          </span>
          <h2 className="text-2xl font-bold text-slate-100 mt-1">
            How CodeSentinel Investigates Your Codebase
          </h2>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6">
          {workflowSteps.map((s, idx) => (
            <div key={idx} className="flex flex-col border border-slate-800/80 bg-slate-950/60 p-5 rounded-xl">
              <span className="text-2xl font-extrabold font-mono text-cyan-500/70 mb-2">{s.step}</span>
              <h4 className="font-bold text-slate-200 text-sm mb-1">{s.title || s.stepName}</h4>
              <p className="text-xs text-slate-400 leading-relaxed">{s.desc}</p>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
};
