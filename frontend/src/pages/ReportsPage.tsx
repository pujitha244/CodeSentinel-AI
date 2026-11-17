import React, { useState } from 'react';
import { Audit, Project } from '../types';
import { api } from '../services/api';
import { FileText, Download, ExternalLink, Code2, Copy, Check } from 'lucide-react';

interface ReportsPageProps {
  currentProject: Project | null;
  latestAudit: Audit | null;
}

export const ReportsPage: React.FC<ReportsPageProps> = ({ currentProject, latestAudit }) => {
  const [copied, setCopied] = useState(false);
  const [markdownContent, setMarkdownContent] = useState<string>('');
  const [loadingMarkdown, setLoadingMarkdown] = useState(false);

  if (!latestAudit || !currentProject) {
    return (
      <div className="py-20 text-center text-xs text-slate-500">
        No audit reports available. Please run an audit first.
      </div>
    );
  }

  const handleFetchMarkdown = async () => {
    setLoadingMarkdown(true);
    try {
      const text = await api.getReportMarkdown(latestAudit.id);
      setMarkdownContent(text);
      setLoadingMarkdown(false);
    } catch {
      setLoadingMarkdown(false);
    }
  };

  const handleDownloadJson = async () => {
    const data = await api.getReportJson(latestAudit.id);
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `codesentinel-report-${latestAudit.id}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleCopyMarkdown = () => {
    navigator.clipboard.writeText(markdownContent);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const htmlUrl = api.getReportHtmlUrl(latestAudit.id);

  return (
    <div className="flex flex-col gap-6 py-6 px-6 max-w-7xl mx-auto">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-white tracking-tight">Audit Reports & Export</h1>
        <p className="text-xs text-slate-400 mt-1">
          Export confidential security findings, cross-file vulnerability investigations, and engineering health scorecards.
        </p>
      </div>

      {/* Export Cards Grid */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {/* HTML Report Card */}
        <div className="rounded-2xl border border-slate-800 bg-sentinel-900/60 p-5 flex flex-col justify-between">
          <div>
            <div className="p-3 rounded-xl bg-cyan-950 border border-cyan-800 text-cyan-400 w-fit mb-3">
              <FileText className="w-6 h-6" />
            </div>
            <h3 className="font-bold text-sm text-slate-100">Standalone HTML Report</h3>
            <p className="text-xs text-slate-400 mt-1 leading-relaxed">
              Self-contained, printable executive presentation with color-coded severity metrics, tables, and chain summaries.
            </p>
          </div>

          <div className="mt-6 flex items-center gap-2">
            <a
              href={htmlUrl}
              target="_blank"
              rel="noopener noreferrer"
              className="flex-1 flex items-center justify-center gap-2 py-2 px-3 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-semibold text-xs transition"
            >
              <span>View in Browser</span>
              <ExternalLink className="w-3.5 h-3.5" />
            </a>
          </div>
        </div>

        {/* JSON Export Card */}
        <div className="rounded-2xl border border-slate-800 bg-sentinel-900/60 p-5 flex flex-col justify-between">
          <div>
            <div className="p-3 rounded-xl bg-indigo-950 border border-indigo-800 text-indigo-400 w-fit mb-3">
              <Code2 className="w-6 h-6" />
            </div>
            <h3 className="font-bold text-sm text-slate-100">Structured JSON Findings</h3>
            <p className="text-xs text-slate-400 mt-1 leading-relaxed">
              Standardized JSON schema containing all normalized findings, reachability confidence, and React Flow nodes.
            </p>
          </div>

          <div className="mt-6 flex items-center gap-2">
            <button
              onClick={handleDownloadJson}
              className="flex-1 flex items-center justify-center gap-2 py-2 px-3 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white font-semibold text-xs transition"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Download JSON</span>
            </button>
          </div>
        </div>

        {/* Markdown Export Card */}
        <div className="rounded-2xl border border-slate-800 bg-sentinel-900/60 p-5 flex flex-col justify-between">
          <div>
            <div className="p-3 rounded-xl bg-violet-950 border border-violet-800 text-violet-400 w-fit mb-3">
              <FileText className="w-6 h-6" />
            </div>
            <h3 className="font-bold text-sm text-slate-100">GitHub Markdown Summary</h3>
            <p className="text-xs text-slate-400 mt-1 leading-relaxed">
              Formatted Markdown document ideal for pasting directly into GitHub PR comments or security advisories.
            </p>
          </div>

          <div className="mt-6 flex items-center gap-2">
            <button
              onClick={handleFetchMarkdown}
              className="flex-1 flex items-center justify-center gap-2 py-2 px-3 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 font-semibold text-xs transition border border-slate-700"
            >
              <span>{loadingMarkdown ? 'Loading...' : 'Preview Markdown'}</span>
            </button>
          </div>
        </div>
      </div>

      {/* Markdown Preview Area */}
      {markdownContent && (
        <div className="rounded-2xl border border-slate-800 bg-sentinel-900/60 p-5 space-y-3">
          <div className="flex items-center justify-between pb-2 border-b border-slate-800">
            <span className="text-xs font-mono font-bold text-slate-300">Markdown Preview</span>
            <button
              onClick={handleCopyMarkdown}
              className="flex items-center gap-1.5 px-3 py-1 rounded bg-slate-800 hover:bg-slate-700 text-xs text-cyan-400 transition"
            >
              {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copied ? 'Copied!' : 'Copy to Clipboard'}</span>
            </button>
          </div>

          <pre className="p-4 rounded-xl bg-slate-950 text-slate-300 font-mono text-xs overflow-x-auto max-h-96 whitespace-pre-wrap">
            {markdownContent}
          </pre>
        </div>
      )}
    </div>
  );
};
