import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Finding, Category, Severity } from '../types';
import { SeverityBadge } from '../components/common/SeverityBadge';
import { 
  ShieldAlert, 
  Search, 
  Filter, 
  ChevronDown, 
  ChevronRight, 
  Wrench, 
  Bot, 
  FileCode,
  CheckCircle2,
  AlertTriangle
} from 'lucide-react';
import { MonacoCodeViewer } from '../components/common/MonacoCodeViewer';

interface FindingsPageProps {
  findings: Finding[];
}

export const FindingsPage: React.FC<FindingsPageProps> = ({ findings }) => {
  const navigate = useNavigate();
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedSeverity, setSelectedSeverity] = useState<string>('all');
  const [selectedCategory, setSelectedCategory] = useState<string>('all');
  const [expandedId, setExpandedId] = useState<string | null>(findings[0]?.id || null);

  const categories: Array<{ id: string; label: string }> = [
    { id: 'all', label: 'All Categories' },
    { id: 'security', label: 'Security' },
    { id: 'secret', label: 'Secrets' },
    { id: 'quality', label: 'Code Quality' },
    { id: 'logic_gap', label: 'Logic Gaps' },
    { id: 'loose_end', label: 'Loose Ends' },
    { id: 'dependency', label: 'Dependencies' }
  ];

  const severities = ['all', 'critical', 'high', 'medium', 'low', 'info'];

  const filtered = findings.filter(f => {
    const matchesSearch = 
      f.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
      f.file_path.toLowerCase().includes(searchTerm.toLowerCase()) ||
      f.description.toLowerCase().includes(searchTerm.toLowerCase()) ||
      f.id.toLowerCase().includes(searchTerm.toLowerCase());
    
    const matchesSev = selectedSeverity === 'all' || f.severity === selectedSeverity;
    const matchesCat = selectedCategory === 'all' || f.category === selectedCategory;

    return matchesSearch && matchesSev && matchesCat;
  });

  return (
    <div className="flex flex-col gap-6 py-6 px-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight">Security & Engineering Findings</h1>
          <p className="text-xs text-slate-400 mt-1">
            Normalized, correlated findings extracted from AST analysis, taint flows, secret detectors, and quality scanners.
          </p>
        </div>

        <div className="flex items-center gap-2 text-xs font-mono text-slate-400 bg-slate-900 px-3 py-1.5 rounded-lg border border-slate-800">
          <span className="font-bold text-slate-200">{filtered.length}</span> of {findings.length} findings displayed
        </div>
      </div>

      {/* Filters Bar */}
      <div className="flex flex-col md:flex-row gap-3 items-stretch md:items-center justify-between bg-sentinel-900/60 p-3 rounded-xl border border-slate-800">
        <div className="relative flex-1">
          <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
          <input
            type="text"
            placeholder="Search findings by ID, title, file, or keyword..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full pl-9 pr-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
          />
        </div>

        <div className="flex flex-wrap items-center gap-2">
          {/* Category Dropdown */}
          <select
            value={selectedCategory}
            onChange={(e) => setSelectedCategory(e.target.value)}
            className="px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-300 focus:outline-none focus:border-cyan-500 font-medium"
          >
            {categories.map(c => (
              <option key={c.id} value={c.id}>{c.label}</option>
            ))}
          </select>

          {/* Severity Dropdown */}
          <select
            value={selectedSeverity}
            onChange={(e) => setSelectedSeverity(e.target.value)}
            className="px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-300 focus:outline-none focus:border-cyan-500 font-medium uppercase"
          >
            {severities.map(s => (
              <option key={s} value={s}>{s === 'all' ? 'All Severities' : s}</option>
            ))}
          </select>
        </div>
      </div>

      {/* Findings List */}
      <div className="space-y-3">
        {filtered.map(f => {
          const isExpanded = expandedId === f.id;
          return (
            <div
              key={f.id}
              className={`rounded-xl border transition-all duration-200 overflow-hidden ${
                isExpanded 
                  ? 'border-slate-700 bg-sentinel-900/90 shadow-xl' 
                  : 'border-slate-800/80 bg-sentinel-900/40 hover:border-slate-700 hover:bg-sentinel-900/60'
              }`}
            >
              {/* Collapsed Header Bar */}
              <div
                onClick={() => setExpandedId(isExpanded ? null : f.id)}
                className="flex items-center justify-between p-4 cursor-pointer"
              >
                <div className="flex items-center gap-3">
                  {isExpanded ? (
                    <ChevronDown className="w-4 h-4 text-slate-400" />
                  ) : (
                    <ChevronRight className="w-4 h-4 text-slate-500" />
                  )}
                  <SeverityBadge severity={f.severity} size="sm" />
                  <span className="font-mono text-xs font-bold text-slate-300">{f.id}</span>
                  <span className="font-semibold text-xs text-slate-100">{f.title}</span>
                </div>

                <div className="flex items-center gap-4 text-xs font-mono text-slate-400">
                  <span className="truncate max-w-[220px]">{f.file_path}:{f.start_line}</span>
                  <span className="hidden sm:inline px-2 py-0.5 rounded bg-slate-800 text-slate-300 text-[10px] uppercase">
                    {f.category}
                  </span>
                </div>
              </div>

              {/* Expanded Details Drawer */}
              {isExpanded && (
                <div className="p-5 border-t border-slate-800/80 bg-slate-950/60 space-y-4">
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
                    <div>
                      <span className="font-semibold uppercase tracking-wider text-slate-400 text-[10px]">
                        Mechanism & Description
                      </span>
                      <p className="text-slate-300 mt-1 leading-relaxed">{f.description}</p>
                    </div>

                    <div>
                      <span className="font-semibold uppercase tracking-wider text-slate-400 text-[10px]">
                        Security & Operational Impact
                      </span>
                      <p className="text-slate-300 mt-1 leading-relaxed">{f.impact}</p>
                    </div>
                  </div>

                  {f.snippet && (
                    <div>
                      <div className="flex items-center justify-between pb-1 text-[11px] font-mono text-slate-400">
                        <span>Source Snippet ({f.file_path}:{f.start_line})</span>
                        <span className="text-slate-500">Confidence: {Math.round(f.confidence * 100)}%</span>
                      </div>
                      <MonacoCodeViewer
                        code={f.snippet}
                        language={f.file_path.endsWith('.js') ? 'javascript' : 'python'}
                        highlightLine={1}
                        height="120px"
                      />
                    </div>
                  )}

                  <div className="bg-emerald-950/20 border border-emerald-900/40 p-3 rounded-lg text-xs">
                    <span className="font-bold text-emerald-400 uppercase tracking-wider text-[10px] block mb-1">
                      Remediation Strategy
                    </span>
                    <p className="text-slate-300">{f.recommendation}</p>
                  </div>

                  {/* Actions */}
                  <div className="flex items-center justify-end gap-3 pt-2">
                    <button
                      onClick={() => navigate('/assistant')}
                      className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-semibold transition"
                    >
                      <Bot className="w-3.5 h-3.5 text-cyan-400" />
                      <span>Ask Assistant</span>
                    </button>

                    <button
                      onClick={() => navigate('/remediation')}
                      className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold shadow-md shadow-cyan-600/20 transition"
                    >
                      <Wrench className="w-3.5 h-3.5" />
                      <span>Preview Fix in Safe Lab</span>
                    </button>
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
};
