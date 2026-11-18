import React, { useState } from 'react';
import { Finding, RemediationPatch } from '../types';
import { api } from '../services/api';
import { DiffViewer } from '../components/common/DiffViewer';
import { SeverityBadge } from '../components/common/SeverityBadge';
import { 
  Wrench, 
  CheckCircle2, 
  RotateCcw, 
  Play, 
  ShieldCheck, 
  AlertCircle, 
  Loader2,
  FileCheck2,
  ExternalLink
} from 'lucide-react';

interface RemediationLabPageProps {
  findings: Finding[];
}

export const RemediationLabPage: React.FC<RemediationLabPageProps> = ({ findings }) => {
  const [selectedFindingId, setSelectedFindingId] = useState<string>(findings[0]?.id || '');
  const [currentPatch, setCurrentPatch] = useState<RemediationPatch | null>(null);
  const [loadingPatch, setLoadingPatch] = useState(false);
  const [applying, setApplying] = useState(false);
  const [verifying, setVerifying] = useState(false);
  const [rollingBack, setRollingBack] = useState(false);
  const [verificationResult, setVerificationResult] = useState<any>(null);
  const [statusMessage, setStatusMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const selectedFinding = findings.find(f => f.id === selectedFindingId) || findings[0];

  const handleGeneratePreview = async () => {
    if (!selectedFinding) return;
    setLoadingPatch(true);
    setError(null);
    setStatusMessage(null);
    setVerificationResult(null);

    try {
      const patch = await api.previewRemediation(selectedFinding.id);
      setCurrentPatch(patch);
      setLoadingPatch(false);
    } catch (err: any) {
      setLoadingPatch(false);
      setError(err.message || 'Failed to generate patch.');
    }
  };

  const handleApplyPatch = async () => {
    if (!selectedFinding || !currentPatch) return;
    setApplying(true);
    setError(null);

    try {
      const res = await api.applyRemediation(
        selectedFinding.id, 
        currentPatch.patch_id, 
        currentPatch.patched_code || ''
      );
      setStatusMessage('Patch applied successfully to workspace file. A backup copy was retained.');
      setApplying(false);
      setCurrentPatch({ ...currentPatch, status: 'applied' });
    } catch (err: any) {
      setApplying(false);
      setError(err.message || 'Failed to apply patch.');
    }
  };

  const handleVerifyPatch = async () => {
    if (!selectedFinding) return;
    setVerifying(true);
    setError(null);

    try {
      const res = await api.verifyRemediation(selectedFinding.id);
      setVerificationResult(res);
      setVerifying(false);
    } catch (err: any) {
      setVerifying(false);
      setError(err.message || 'Verification failed.');
    }
  };

  const handleRollback = async () => {
    if (!selectedFinding) return;
    setRollingBack(true);
    setError(null);

    try {
      const res = await api.rollbackRemediation(selectedFinding.id);
      setStatusMessage('File rolled back to original pristine state.');
      setRollingBack(false);
      setVerificationResult(null);
      if (currentPatch) {
        setCurrentPatch({ ...currentPatch, status: 'rolled_back' });
      }
    } catch (err: any) {
      setRollingBack(false);
      setError(err.message || 'Rollback failed.');
    }
  };

  if (findings.length === 0) {
    return (
      <div className="py-20 text-center text-xs text-slate-500">
        No findings available for remediation. Run an audit first.
      </div>
    );
  }

  return (
    <div className="page-frame flex flex-col gap-6 py-6 px-6 max-w-7xl mx-auto">
      {/* Header */}
      <div>
        <div className="flex items-center gap-2">
          <span className="px-2 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-800 text-[10px] font-mono font-bold uppercase">
            Safe Auto-Fix
          </span>
          <h1 className="text-2xl font-bold text-white tracking-tight">Remediation Lab & Verification</h1>
        </div>
        <p className="text-xs text-slate-400 mt-1">
          Review evidence-backed targeted patches, preview unified diffs, apply with explicit approval, and verify with static analysis.
        </p>
      </div>

      {error && (
        <div className="p-4 rounded-xl border border-rose-800 bg-rose-950/60 text-rose-300 text-xs flex items-center gap-2">
          <AlertCircle className="w-4 h-4 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {statusMessage && (
        <div className="p-4 rounded-xl border border-emerald-800 bg-emerald-950/60 text-emerald-300 text-xs flex items-center gap-2">
          <CheckCircle2 className="w-4 h-4 shrink-0" />
          <span>{statusMessage}</span>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Finding Selector & Overview */}
        <div className="rounded-2xl border border-slate-800 bg-sentinel-900/60 p-5 space-y-4">
          <label htmlFor="finding-to-remediate" className="text-xs font-bold uppercase tracking-wider text-slate-400 block">
            Select Finding to Remediate
          </label>
          <select
            id="finding-to-remediate"
            value={selectedFinding?.id}
            onChange={(e) => {
              setSelectedFindingId(e.target.value);
              setCurrentPatch(null);
              setVerificationResult(null);
            }}
            className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
          >
            {findings.map(f => (
              <option key={f.id} value={f.id}>
                [{f.severity.toUpperCase()}] {f.id} - {f.title}
              </option>
            ))}
          </select>

          {selectedFinding && (
            <div className="space-y-3 pt-3 border-t border-slate-800 text-xs">
              <div className="flex items-center gap-2">
                <SeverityBadge severity={selectedFinding.severity} size="sm" />
                <span className="font-mono text-cyan-400 font-semibold">{selectedFinding.id}</span>
              </div>

              <div className="font-semibold text-slate-200 text-sm">
                {selectedFinding.title}
              </div>

              <div className="text-slate-400 font-mono">
                {selectedFinding.file_path}:{selectedFinding.start_line}
              </div>

              <p className="text-slate-300 text-xs leading-relaxed">
                {selectedFinding.description}
              </p>

              <button
                onClick={handleGeneratePreview}
                disabled={loadingPatch}
                className="w-full mt-4 flex items-center justify-center gap-2 py-2.5 px-4 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-white font-semibold text-xs shadow-md shadow-cyan-600/20 transition disabled:opacity-50"
              >
                {loadingPatch ? (
                  <>
                    <Loader2 className="w-3.5 h-3.5 animate-spin" />
                    <span>Generating Targeted Patch...</span>
                  </>
                ) : (
                  <>
                    <Wrench className="w-3.5 h-3.5" />
                    <span>Generate Safe Remediation Patch</span>
                  </>
                )}
              </button>
            </div>
          )}
        </div>

        {/* Patch Preview & Diff Area */}
        <div className="lg:col-span-2 space-y-4">
          {currentPatch ? (
            <div className="rounded-2xl border border-slate-800 bg-sentinel-900/60 p-5 space-y-4">
              <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2 pb-3 border-b border-slate-800">
                <div>
                  <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
                    <FileCheck2 className="w-4 h-4 text-emerald-400" />
                    Patch Preview: {currentPatch.file_path}
                  </h3>
                  <span className="text-[11px] text-slate-400 font-mono">
                    Patch ID: {currentPatch.patch_id}
                  </span>
                </div>

                <div className="flex items-center gap-2">
                  {currentPatch.status === 'applied' && (
                    <button
                      onClick={handleRollback}
                      disabled={rollingBack}
                      className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-rose-300 text-xs font-semibold border border-rose-900/40 transition disabled:opacity-50"
                    >
                      <RotateCcw className="w-3.5 h-3.5" />
                      <span>{rollingBack ? 'Reverting...' : 'Rollback'}</span>
                    </button>
                  )}

                  {currentPatch.status !== 'applied' && (
                    <button
                      onClick={handleApplyPatch}
                      disabled={applying || !currentPatch.has_changes}
                      className="flex items-center gap-1.5 px-4 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold shadow-md shadow-emerald-600/20 transition disabled:cursor-not-allowed disabled:opacity-50"
                    >
                      <CheckCircle2 className="w-3.5 h-3.5" />
                      <span>
                        {applying
                          ? 'Applying...'
                          : currentPatch.has_changes
                            ? 'Approve & Apply Patch'
                            : 'No patch available'}
                      </span>
                    </button>
                  )}

                  <button
                    onClick={handleVerifyPatch}
                    disabled={verifying}
                    className="flex items-center gap-1.5 px-4 py-1.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-semibold shadow-md shadow-indigo-600/20 transition disabled:opacity-50"
                  >
                    <ShieldCheck className="w-3.5 h-3.5" />
                    <span>{verifying ? 'Scanning...' : 'Run Verification'}</span>
                  </button>
                </div>
              </div>

              {!currentPatch.has_changes && (
                <p className="border border-amber-900/60 bg-amber-950/20 px-3 py-2 text-xs text-amber-200" role="status">
                  No supported automatic patch is available for this finding. The source file has not been changed.
                </p>
              )}

              {/* Technical explanation */}
              <div className="bg-slate-950 p-3 rounded-lg border border-slate-800 text-xs text-slate-300">
                <span className="font-semibold text-cyan-400 block mb-1">Technical Fix Mechanism:</span>
                {currentPatch.explanation}
              </div>

              {/* Unified Diff */}
              <DiffViewer diffText={currentPatch.unified_diff} filePath={currentPatch.file_path} />

              {/* Verification Result Card */}
              {verificationResult && (
                <div className={`p-4 rounded-xl border text-xs flex items-start gap-3 ${
                  verificationResult.verified 
                    ? 'border-emerald-800 bg-emerald-950/40 text-emerald-300' 
                    : 'border-rose-800 bg-rose-950/40 text-rose-300'
                }`}>
                  {verificationResult.verified ? (
                    <CheckCircle2 className="w-5 h-5 shrink-0 text-emerald-400" />
                  ) : (
                    <AlertCircle className="w-5 h-5 shrink-0 text-rose-400" />
                  )}
                  <div>
                    <span className="font-bold block text-sm">
                      {verificationResult.verified ? 'Verification Passed!' : 'Verification Failed'}
                    </span>
                    <p className="mt-0.5 leading-relaxed">{verificationResult.message}</p>
                  </div>
                </div>
              )}
            </div>
          ) : (
            <div className="rounded-2xl border border-slate-800 bg-sentinel-900/30 p-12 text-center text-xs text-slate-500">
              Select an issue from the list on the left and click "Generate Safe Remediation Patch" to preview the unified diff and verification workflow.
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
