import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { api } from '../services/api';
import { Project, Audit } from '../types';
import { 
  UploadCloud, 
  Github, 
  Play, 
  CheckCircle2, 
  AlertCircle, 
  ArrowRight, 
  Loader2,
  Terminal,
  ShieldCheck
} from 'lucide-react';

interface NewAuditPageProps {
  onAuditComplete: (project: Project, audit: Audit) => void;
}

export const NewAuditPage: React.FC<NewAuditPageProps> = ({ onAuditComplete }) => {
  const navigate = useNavigate();
  const [tab, setTab] = useState<'demo' | 'upload' | 'github'>('demo');
  const [isProcessing, setIsProcessing] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Form states
  const [zipFile, setZipFile] = useState<File | null>(null);
  const [githubUrl, setGithubUrl] = useState('https://github.com/fastapi/fastapi');
  const [githubToken, setGithubToken] = useState('');

  // Live progress
  const [progressPercent, setProgressPercent] = useState(0);
  const [currentStage, setCurrentStage] = useState('');
  const [auditLogs, setAuditLogs] = useState<string[]>([]);
  const [completedAudit, setCompletedAudit] = useState<Audit | null>(null);

  const startAuditFlow = async (project: Project) => {
    setIsProcessing(true);
    setError(null);
    setProgressPercent(10);
    setCurrentStage('Step 1/17: Initializing repository audit pipeline');
    setAuditLogs(['Validating repository workspace boundaries...']);

    try {
      // Launch Audit
      const audit = await api.createAudit(project.id);
      
      setProgressPercent(100);
      setCurrentStage('Step 17/17: Audit complete! Results synthesized.');
      setAuditLogs(audit.stages_log || ['Completed all 17 analysis stages.']);
      setCompletedAudit(audit);
      setIsProcessing(false);

      onAuditComplete(project, audit);
    } catch (err: any) {
      setIsProcessing(false);
      setError(err.message || 'Audit execution encountered a failure.');
    }
  };

  const handleLaunchDemo = async () => {
    setIsProcessing(true);
    setError(null);
    try {
      const proj = await api.loadDemo();
      await startAuditFlow(proj);
    } catch (err: any) {
      setIsProcessing(false);
      setError(err.message || 'Failed to load demo project.');
    }
  };

  const handleUploadZip = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!zipFile) {
      setError('Please select a valid .zip repository archive.');
      return;
    }
    setIsProcessing(true);
    setError(null);
    try {
      const proj = await api.uploadZip(zipFile);
      await startAuditFlow(proj);
    } catch (err: any) {
      setIsProcessing(false);
      setError(err.message || 'Upload failed.');
    }
  };

  const handleGithubIngest = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!githubUrl) {
      setError('Please enter a GitHub repository URL.');
      return;
    }
    setIsProcessing(true);
    setError(null);
    try {
      const proj = await api.ingestGithub(githubUrl, githubToken || undefined);
      await startAuditFlow(proj);
    } catch (err: any) {
      setIsProcessing(false);
      setError(err.message || 'GitHub repository ingestion failed.');
    }
  };

  return (
    <div className="max-w-4xl mx-auto py-8 px-6 flex flex-col gap-8">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-white tracking-tight">Launch Autonomous Audit</h1>
        <p className="text-xs text-slate-400 mt-1">
          Ingest a codebase to run the 17-stage static analysis pipeline, extract cross-file vulnerability chains, and assess code slop.
        </p>
      </div>

      {error && (
        <div className="p-4 rounded-xl border border-rose-800 bg-rose-950/60 text-rose-300 text-xs flex items-center gap-3">
          <AlertCircle className="w-5 h-5 shrink-0 text-rose-400" />
          <span>{error}</span>
        </div>
      )}

      {/* Tabs */}
      {!isProcessing && !completedAudit && (
        <div className="flex border-b border-slate-800 gap-6">
          <button
            onClick={() => setTab('demo')}
            className={`pb-3 text-xs font-semibold flex items-center gap-2 border-b-2 transition ${
              tab === 'demo'
                ? 'border-cyan-400 text-cyan-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Play className="w-4 h-4 fill-current" />
            <span>Try Sample Demo Project</span>
            <span className="text-[10px] px-1.5 py-0.2 rounded bg-cyan-950 text-cyan-300 border border-cyan-800">
              Recommended
            </span>
          </button>

          <button
            onClick={() => setTab('upload')}
            className={`pb-3 text-xs font-semibold flex items-center gap-2 border-b-2 transition ${
              tab === 'upload'
                ? 'border-cyan-400 text-cyan-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <UploadCloud className="w-4 h-4" />
            <span>Upload ZIP Archive</span>
          </button>

          <button
            onClick={() => setTab('github')}
            className={`pb-3 text-xs font-semibold flex items-center gap-2 border-b-2 transition ${
              tab === 'github'
                ? 'border-cyan-400 text-cyan-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Github className="w-4 h-4" />
            <span>GitHub Ingestion</span>
          </button>
        </div>
      )}

      {/* Tab Contents */}
      {!isProcessing && !completedAudit && (
        <div className="rounded-2xl border border-slate-800 bg-sentinel-900/60 p-6 backdrop-blur">
          {tab === 'demo' && (
            <div className="space-y-4">
              <div className="flex items-center gap-3">
                <span className="px-2.5 py-1 rounded bg-rose-950 text-rose-300 text-xs font-mono font-bold border border-rose-800">
                  FLAGSHIP DEMO
                </span>
                <h3 className="text-base font-bold text-slate-100">
                  Multi-Tier Vulnerable Python Application
                </h3>
              </div>
              <p className="text-xs text-slate-400 leading-relaxed">
                Contains an intentional cross-file SQL injection propagation flow spanning client input in{' '}
                <code className="text-cyan-300">frontend/login.js</code>, route controller{' '}
                <code className="text-cyan-300">backend/routes.py</code>, intermediate service{' '}
                <code className="text-cyan-300">backend/services.py</code>, and dangerous raw query execution in{' '}
                <code className="text-rose-400">backend/database.py</code>. Also includes exposed AWS secrets, code slop, and logic gaps.
              </p>
              <button
                onClick={handleLaunchDemo}
                className="mt-4 flex items-center gap-2 px-6 py-3 rounded-xl bg-gradient-to-r from-cyan-600 to-indigo-600 hover:from-cyan-500 hover:to-indigo-500 text-white font-bold text-sm shadow-xl shadow-cyan-600/20 transition"
              >
                <Play className="w-4 h-4 fill-current" />
                <span>Run Audit On Demo Repository</span>
              </button>
            </div>
          )}

          {tab === 'upload' && (
            <form onSubmit={handleUploadZip} className="space-y-4">
              <div className="border-2 border-dashed border-slate-800 hover:border-slate-700 rounded-xl p-8 text-center cursor-pointer bg-slate-950/40">
                <UploadCloud className="w-10 h-10 text-cyan-400 mx-auto mb-3" />
                <label className="cursor-pointer">
                  <span className="text-sm font-semibold text-slate-200">Choose a ZIP archive</span>
                  <input
                    type="file"
                    accept=".zip"
                    onChange={(e) => setZipFile(e.target.files?.[0] || null)}
                    className="hidden"
                  />
                </label>
                <p className="text-xs text-slate-500 mt-1">Maximum size: 50MB. Safe unzipping with path traversal defenses.</p>
                {zipFile && (
                  <div className="mt-3 text-xs font-mono text-cyan-300 font-semibold">
                    Selected: {zipFile.name} ({(zipFile.size / 1024 / 1024).toFixed(2)} MB)
                  </div>
                )}
              </div>
              <button
                type="submit"
                disabled={!zipFile}
                className="w-full flex items-center justify-center gap-2 py-3 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-white font-semibold text-sm transition disabled:opacity-50"
              >
                <span>Upload & Start Audit</span>
              </button>
            </form>
          )}

          {tab === 'github' && (
            <form onSubmit={handleGithubIngest} className="space-y-4">
              <div>
                <label className="text-xs font-semibold text-slate-300 block mb-1">
                  GitHub Repository URL
                </label>
                <input
                  type="text"
                  value={githubUrl}
                  onChange={(e) => setGithubUrl(e.target.value)}
                  placeholder="https://github.com/owner/repository"
                  className="w-full px-3.5 py-2.5 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono"
                />
              </div>

              <div>
                <label className="text-xs font-semibold text-slate-300 block mb-1">
                  Personal Access Token <span className="text-slate-500 font-normal">(Optional for private repos)</span>
                </label>
                <input
                  type="password"
                  value={githubToken}
                  onChange={(e) => setGithubToken(e.target.value)}
                  placeholder="ghp_..."
                  className="w-full px-3.5 py-2.5 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono"
                />
              </div>

              <button
                type="submit"
                className="w-full flex items-center justify-center gap-2 py-3 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-white font-semibold text-sm transition"
              >
                <span>Download & Start Audit</span>
              </button>
            </form>
          )}
        </div>
      )}

      {/* Real-Time Processing Stepper & Terminal Log */}
      {isProcessing && (
        <div className="rounded-2xl border border-slate-800 bg-sentinel-900/90 p-6 space-y-6 shadow-2xl">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <Loader2 className="w-5 h-5 text-cyan-400 animate-spin" />
              <h3 className="font-bold text-slate-100 text-sm">{currentStage}</h3>
            </div>
            <span className="font-mono text-xs font-bold text-cyan-400">{progressPercent}%</span>
          </div>

          {/* Progress bar */}
          <div className="h-2 w-full rounded-full bg-slate-800 overflow-hidden">
            <div 
              className="h-full bg-gradient-to-r from-cyan-500 via-blue-500 to-indigo-500 transition-all duration-300"
              style={{ width: `${progressPercent}%` }}
            />
          </div>

          {/* Terminal log output */}
          <div className="rounded-xl border border-slate-800 bg-[#0a0e17] p-4 font-mono text-xs text-slate-300 max-h-56 overflow-y-auto space-y-1">
            <div className="flex items-center gap-2 text-slate-500 text-[11px] pb-2 border-b border-slate-800/80 mb-2">
              <Terminal className="w-3.5 h-3.5" />
              <span>CodeSentinel Static Engine Output Log</span>
            </div>
            {auditLogs.map((log, i) => (
              <div key={i} className="text-cyan-400/90">
                › {log}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Completion Banner */}
      {completedAudit && (
        <div className="rounded-2xl border border-emerald-800 bg-emerald-950/20 p-6 text-center space-y-4 shadow-xl">
          <div className="w-12 h-12 rounded-full bg-emerald-900/60 border border-emerald-700/80 flex items-center justify-center mx-auto text-emerald-400">
            <ShieldCheck className="w-6 h-6" />
          </div>
          <div>
            <h3 className="text-lg font-bold text-white">Autonomous Audit Completed Successfully!</h3>
            <p className="text-xs text-slate-400 mt-1">
              Discovered <span className="font-bold text-rose-400">{completedAudit.total_findings} findings</span> across security, code quality, logic gaps, and loose ends.
            </p>
          </div>

          <div className="flex flex-wrap items-center justify-center gap-4 pt-2">
            <button
              onClick={() => navigate('/chains')}
              className="flex items-center gap-2 px-5 py-2.5 rounded-xl bg-rose-600 hover:bg-rose-500 text-white font-semibold text-xs shadow-lg shadow-rose-600/20"
            >
              <span>Explore Vulnerability Chains</span>
              <ArrowRight className="w-4 h-4" />
            </button>
            <button
              onClick={() => navigate('/dashboard')}
              className="flex items-center gap-2 px-5 py-2.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 font-semibold text-xs border border-slate-700"
            >
              <span>View Executive Dashboard</span>
            </button>
          </div>
        </div>
      )}
    </div>
  );
};
