import React from 'react';
import { useNavigate } from 'react-router-dom';
import { Project, Audit, Finding, VulnerabilityChain } from '../types';
import { ScoreCard } from '../components/common/ScoreCard';
import { SeverityBadge } from '../components/common/SeverityBadge';
import { 
  ShieldAlert, 
  GitMerge, 
  Code2, 
  ListTodo, 
  Activity, 
  ArrowRight, 
  FileCheck2, 
  CheckCircle2, 
  ExternalLink,
  Flame,
  Layers,
  Wrench
} from 'lucide-react';

interface DashboardPageProps {
  currentProject: Project | null;
  latestAudit: Audit | null;
  chains: VulnerabilityChain[];
  findings: Finding[];
  onLoadDemo: () => void;
  isLoadingDemo?: boolean;
}

export const DashboardPage: React.FC<DashboardPageProps> = ({
  currentProject,
  latestAudit,
  chains,
  findings,
  onLoadDemo,
  isLoadingDemo
}) => {
  const navigate = useNavigate();

  if (!currentProject || !latestAudit) {
    return (
      <div className="flex flex-col items-center justify-center py-20 px-4 text-center">
        <div className="p-4 rounded-2xl bg-indigo-950/40 border border-indigo-800/60 mb-4">
          <Activity className="w-8 h-8 text-cyan-400 animate-bounce" />
        </div>
        <h2 className="text-xl font-bold text-slate-100">No Audits Performed Yet</h2>
        <p className="text-sm text-slate-400 max-w-md mt-2 mb-6">
          Load the pre-configured vulnerable multi-tier Python application to test the cross-file SQL injection investigation engine, or launch a new audit on your own repository.
        </p>
        <button
          onClick={onLoadDemo}
          disabled={isLoadingDemo}
          className="flex items-center gap-2 px-5 py-2.5 rounded-xl bg-gradient-to-r from-cyan-600 to-indigo-600 text-white font-semibold text-sm shadow-lg shadow-cyan-600/20"
        >
          <span>{isLoadingDemo ? 'Analyzing Sample...' : 'Run Flagship Demo Audit'}</span>
          <ArrowRight className="w-4 h-4" />
        </button>
      </div>
    );
  }

  const criticalFindings = findings.filter(f => f.severity === 'critical');
  const highFindings = findings.filter(f => f.severity === 'high');

  return (
    <div className="flex flex-col gap-8 py-6 px-6 max-w-7xl mx-auto">
      {/* Top Header */}
      <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-2xl font-bold text-white tracking-tight">Security & Engineering Dashboard</h1>
            <span className="text-xs font-mono px-2 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-800">
              AUDIT COMPLETED
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Project: <span className="font-semibold text-slate-300">{currentProject.name}</span> • Root: <span className="font-mono text-slate-400">{currentProject.root_path}</span>
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={() => navigate('/chains')}
            className="flex items-center gap-2 px-3.5 py-2 rounded-lg bg-rose-950/80 border border-rose-800 hover:bg-rose-900 text-rose-300 font-semibold text-xs transition"
          >
            <GitMerge className="w-3.5 h-3.5" />
            <span>Chain Explorer ({chains.length})</span>
          </button>
          <button
            onClick={() => navigate('/remediation')}
            className="flex items-center gap-2 px-3.5 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-semibold text-xs shadow-md shadow-cyan-600/20 transition"
          >
            <Wrench className="w-3.5 h-3.5" />
            <span>Safe Auto-Fix Lab</span>
          </button>
        </div>
      </div>

      {/* Scorecards Row */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <ScoreCard
          title="Engineering Health"
          score={latestAudit.engineering_health_score}
          subtitle="Weighted holistic architecture score"
          icon={<Activity className="w-4 h-4 text-emerald-400" />}
        />
        <ScoreCard
          title="Security Posture"
          score={latestAudit.security_score}
          subtitle={`${latestAudit.critical_count} critical, ${latestAudit.high_count} high findings`}
          icon={<ShieldAlert className="w-4 h-4 text-rose-400" />}
        />
        <ScoreCard
          title="Code Slop Score"
          score={latestAudit.slop_score}
          subtitle="Dead code, duplicate blocks, nesting"
          invertColors={true}
          icon={<Code2 className="w-4 h-4 text-amber-400" />}
        />
        <ScoreCard
          title="Implementation Completeness"
          score={latestAudit.completeness_score}
          subtitle="Evaluates TODOs, logic gaps & edge cases"
          icon={<CheckCircle2 className="w-4 h-4 text-sky-400" />}
        />
      </div>

      {/* Flagship Chain Spotlight */}
      {chains.length > 0 && (
        <div className="rounded-2xl border border-rose-900/60 bg-gradient-to-r from-rose-950/40 via-sentinel-900 to-sentinel-900 p-6 shadow-xl relative overflow-hidden">
          <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4 mb-4">
            <div className="flex items-center gap-3">
              <div className="p-2.5 rounded-xl bg-rose-950 border border-rose-800 text-rose-400">
                <Flame className="w-5 h-5 animate-pulse" />
              </div>
              <div>
                <span className="text-[10px] font-mono font-bold uppercase tracking-wider text-rose-400">
                  FLAGSHIP CROSS-FILE DISCOVERY
                </span>
                <h3 className="text-lg font-bold text-white">{chains[0].title}</h3>
              </div>
            </div>

            <button
              onClick={() => navigate('/chains')}
              className="flex items-center gap-1.5 px-4 py-2 rounded-lg bg-rose-600 hover:bg-rose-500 text-white font-semibold text-xs shadow-lg shadow-rose-600/30 transition"
            >
              <span>Inspect Full Propagation Graph</span>
              <ArrowRight className="w-4 h-4" />
            </button>
          </div>

          <p className="text-xs text-slate-300 max-w-3xl leading-relaxed mb-4">
            {chains[0].description}
          </p>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs font-mono">
            <div className="bg-slate-950/70 p-3 rounded-lg border border-slate-800">
              <span className="text-slate-500 text-[10px] uppercase block">Untrusted Source</span>
              <span className="text-rose-300 font-semibold">{chains[0].source_file}:{chains[0].source_line}</span>
            </div>
            <div className="bg-slate-950/70 p-3 rounded-lg border border-slate-800">
              <span className="text-slate-500 text-[10px] uppercase block">Interprocedural Flow</span>
              <span className="text-amber-300 font-semibold">{chains[0].nodes.length} connected layers</span>
            </div>
            <div className="bg-slate-950/70 p-3 rounded-lg border border-slate-800">
              <span className="text-slate-500 text-[10px] uppercase block">Dangerous Sink</span>
              <span className="text-rose-400 font-semibold">{chains[0].sink_file}:{chains[0].sink_line}</span>
            </div>
          </div>
        </div>
      )}

      {/* Two Column Layout: Urgent Findings & Architecture Summary */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Urgent Findings */}
        <div className="rounded-xl border border-slate-800 bg-sentinel-900/80 p-5 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
                <ShieldAlert className="w-4 h-4 text-rose-400" />
                Critical & High Remediation Priorities
              </h3>
              <button 
                onClick={() => navigate('/findings')}
                className="text-xs text-cyan-400 hover:text-cyan-300 font-medium"
              >
                View all ({findings.length}) →
              </button>
            </div>

            <div className="mt-3 divide-y divide-slate-800/60">
              {(criticalFindings.concat(highFindings)).slice(0, 4).map((f) => (
                <div key={f.id} className="py-3 flex items-start justify-between gap-3">
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <SeverityBadge severity={f.severity} size="sm" />
                      <span className="text-xs font-mono font-semibold text-slate-200">{f.id}</span>
                    </div>
                    <div className="text-xs font-semibold text-slate-200 line-clamp-1">{f.title}</div>
                    <div className="text-[11px] font-mono text-slate-400 truncate max-w-sm">
                      {f.file_path}:{f.start_line}
                    </div>
                  </div>

                  <button
                    onClick={() => navigate(`/remediation`)}
                    className="shrink-0 text-xs px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-cyan-400 font-medium transition"
                  >
                    Fix
                  </button>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Project Profile & Structure */}
        <div className="rounded-xl border border-slate-800 bg-sentinel-900/80 p-5 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
                <Layers className="w-4 h-4 text-indigo-400" />
                Repository Structural Profile
              </h3>
              <button 
                onClick={() => navigate('/architecture')}
                className="text-xs text-indigo-400 hover:text-indigo-300 font-medium"
              >
                Open Graph →
              </button>
            </div>

            <div className="mt-4 space-y-4 text-xs">
              <div className="flex items-center justify-between py-1.5 border-b border-slate-800/60">
                <span className="text-slate-400">Primary Languages</span>
                <span className="font-semibold text-slate-200 font-mono">
                  {currentProject.meta_info?.languages?.join(', ') || 'Python'}
                </span>
              </div>
              <div className="flex items-center justify-between py-1.5 border-b border-slate-800/60">
                <span className="text-slate-400">Detected Frameworks</span>
                <span className="font-semibold text-slate-200 font-mono">
                  {currentProject.meta_info?.frameworks?.join(', ') || 'FastAPI'}
                </span>
              </div>
              <div className="flex items-center justify-between py-1.5 border-b border-slate-800/60">
                <span className="text-slate-400">Indexed Source Files</span>
                <span className="font-semibold text-slate-200 font-mono">
                  {currentProject.meta_info?.file_count || 6} files
                </span>
              </div>
              <div className="flex items-center justify-between py-1.5">
                <span className="text-slate-400">Source Entry Points</span>
                <span className="font-semibold text-slate-200 font-mono truncate max-w-[200px]">
                  {currentProject.meta_info?.entry_points?.join(', ') || 'routes.py'}
                </span>
              </div>
            </div>
          </div>

          <div className="mt-6 pt-4 border-t border-slate-800 flex items-center justify-between">
            <span className="text-[11px] text-slate-500">Autonomous Security Auditor</span>
            <button
              onClick={() => navigate('/reports')}
              className="text-xs text-cyan-400 hover:text-cyan-300 font-semibold"
            >
              Export Comprehensive Report →
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
