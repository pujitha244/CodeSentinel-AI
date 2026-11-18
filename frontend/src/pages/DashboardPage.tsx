import React from 'react';
import { useNavigate } from 'react-router-dom';
import { Project, Audit, Finding, VulnerabilityChain } from '../types';
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
  const severityDistribution = [
    { severity: 'Critical', color: '#f87171', count: findings.filter(f => f.severity === 'critical').length },
    { severity: 'High', color: '#fb923c', count: findings.filter(f => f.severity === 'high').length },
    { severity: 'Medium', color: '#fbbf24', count: findings.filter(f => f.severity === 'medium').length },
    { severity: 'Low', color: '#38bdf8', count: findings.filter(f => f.severity === 'low').length },
    { severity: 'Info', color: '#94a3b8', count: findings.filter(f => f.severity === 'info').length }
  ];
  const findingTotal = severityDistribution.reduce((total, item) => total + item.count, 0);

  return (
    <div className="page-frame flex flex-col gap-8 py-6 px-6 max-w-7xl mx-auto">
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

      <section aria-label="Audit scores" className="grid grid-cols-2 lg:grid-cols-4 border-y border-slate-800 divide-x divide-slate-800">
        {[
          { label: 'Engineering health', score: latestAudit.engineering_health_score, note: 'Composite score' },
          { label: 'Security posture', score: latestAudit.security_score, note: `${latestAudit.critical_count} critical · ${latestAudit.high_count} high` },
          { label: 'Code slop', score: latestAudit.slop_score, note: 'Lower is cleaner' },
          { label: 'Completeness', score: latestAudit.completeness_score, note: 'Logic gaps and deferred work' }
        ].map((metric) => (
          <div key={metric.label} className="min-w-0 px-4 py-4 first:pl-0">
            <div className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">{metric.label}</div>
            <div className="mt-1 flex items-baseline gap-1">
              <span className="font-mono text-2xl font-semibold text-slate-100">{metric.score}</span>
              <span className="text-xs text-slate-500">/100</span>
            </div>
            <div className="mt-1 text-[10px] text-slate-500 truncate">{metric.note}</div>
          </div>
        ))}
      </section>

      {/* Flagship Chain Spotlight */}
      {chains.length > 0 && (
        <div className="rounded-xl border border-rose-900/60 bg-[#11171e] p-6 relative overflow-hidden">
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

      {/* Two Column Layout: Priorities & Evidence Distribution */}
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

        {/* Evidence Distribution */}
        <div className="rounded-xl border border-slate-800 bg-sentinel-900/80 p-5 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
                <ShieldAlert className="w-4 h-4 text-indigo-400" />
                Finding severity distribution
              </h3>
              <span className="font-mono text-xs text-slate-500">{findingTotal} findings</span>
            </div>

            {findingTotal > 0 ? (
              <>
                <div
                  className="mt-5 h-3 w-full overflow-hidden rounded-sm bg-slate-800 flex"
                  role="img"
                  aria-label={severityDistribution.map(item => `${item.severity}: ${item.count}`).join(', ')}
                >
                  {severityDistribution.filter(item => item.count > 0).map(item => (
                    <span
                      key={item.severity}
                      title={`${item.severity}: ${item.count}`}
                      style={{ width: `${(item.count / findingTotal) * 100}%`, backgroundColor: item.color }}
                    />
                  ))}
                </div>
                <ul className="mt-5 grid grid-cols-2 gap-x-6 gap-y-3">
                  {severityDistribution.map(item => (
                    <li key={item.severity} className="flex items-center justify-between gap-3 text-xs">
                      <span className="flex items-center gap-2 text-slate-400">
                        <span className="h-2 w-2 rounded-sm" style={{ backgroundColor: item.color }} />
                        {item.severity}
                      </span>
                      <span className="font-mono text-slate-200">{item.count}</span>
                    </li>
                  ))}
                </ul>
              </>
            ) : (
              <p className="mt-5 text-xs text-slate-400" role="status">No findings were returned for this audit.</p>
            )}
          </div>

          <div className="mt-6 pt-4 border-t border-slate-800 flex items-center justify-between">
            <span className="text-[11px] text-slate-500">
              {currentProject.meta_info?.file_count != null ? `${currentProject.meta_info.file_count} indexed files` : 'File count not reported'}
            </span>
            <button
              onClick={() => navigate('/architecture')}
              className="text-xs text-cyan-400 hover:text-cyan-300 font-semibold"
            >
              View architecture →
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
