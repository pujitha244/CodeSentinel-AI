import React from 'react';

interface DiffViewerProps {
  diffText: string;
  filePath: string;
}

export const DiffViewer: React.FC<DiffViewerProps> = ({ diffText, filePath }) => {
  const lines = diffText.split('\n');

  return (
    <div className="rounded-lg border border-slate-800 bg-[#0d1117] overflow-hidden font-mono text-xs">
      <div className="flex items-center justify-between px-4 py-2 bg-slate-900 border-b border-slate-800 text-slate-400">
        <span className="font-semibold text-slate-300">{filePath}</span>
        <span className="text-[11px] uppercase tracking-wider text-slate-500">Unified Patch Diff</span>
      </div>

      <div className="overflow-x-auto p-2 max-h-96">
        {lines.map((line, idx) => {
          let lineClass = 'text-slate-400';
          let bgClass = '';

          if (line.startsWith('+') && !line.startsWith('+++')) {
            lineClass = 'text-emerald-400 font-medium';
            bgClass = 'bg-emerald-950/40 border-l-2 border-emerald-500';
          } else if (line.startsWith('-') && !line.startsWith('---')) {
            lineClass = 'text-rose-400 line-through';
            bgClass = 'bg-rose-950/40 border-l-2 border-rose-500';
          } else if (line.startsWith('@@')) {
            lineClass = 'text-cyan-400 font-semibold';
            bgClass = 'bg-cyan-950/20';
          }

          return (
            <div key={idx} className={`px-3 py-0.5 whitespace-pre ${lineClass} ${bgClass}`}>
              {line || ' '}
            </div>
          );
        })}
      </div>
    </div>
  );
};
