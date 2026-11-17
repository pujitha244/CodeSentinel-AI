import React, { useState } from 'react';
import { Finding } from '../types';
import { ListTodo, Search, AlertCircle, FileCode, CheckSquare } from 'lucide-react';

interface LooseEndsPageProps {
  findings: Finding[];
}

export const LooseEndsPage: React.FC<LooseEndsPageProps> = ({ findings }) => {
  const [searchTerm, setSearchTerm] = useState('');
  const looseEnds = findings.filter(f => f.category === 'loose_end');

  const filtered = looseEnds.filter(l => 
    l.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
    l.file_path.toLowerCase().includes(searchTerm.toLowerCase()) ||
    l.description.toLowerCase().includes(searchTerm.toLowerCase())
  );

  return (
    <div className="flex flex-col gap-6 py-6 px-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <span className="px-2 py-0.5 rounded bg-violet-950 text-violet-300 border border-violet-800 text-[10px] font-mono font-bold uppercase">
              Signature Intelligence
            </span>
            <h1 className="text-2xl font-bold text-white tracking-tight">Loose Ends Tracker</h1>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Tracks deferred technical debt, TODOs, FIXMEs, placeholder stubs, and unimplemented runtime exceptions.
          </p>
        </div>

        <div className="relative w-full md:w-72">
          <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
          <input
            type="text"
            placeholder="Search loose ends..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full pl-9 pr-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
          />
        </div>
      </div>

      {/* Loose Ends Table */}
      <div className="rounded-2xl border border-slate-800 bg-sentinel-900/60 overflow-hidden shadow-xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-950/80 border-b border-slate-800 text-slate-400 uppercase font-mono text-[10px]">
              <tr>
                <th className="py-3 px-4">Tag / Type</th>
                <th className="py-3 px-4">Summary</th>
                <th className="py-3 px-4">File Location</th>
                <th className="py-3 px-4">Snippet</th>
                <th className="py-3 px-4">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/80 text-slate-300">
              {filtered.map((item) => {
                let badgeColor = 'bg-slate-800 text-slate-300 border-slate-700';
                if (item.title.includes('TODO')) badgeColor = 'bg-blue-950 text-blue-300 border-blue-800';
                if (item.title.includes('FIXME')) badgeColor = 'bg-amber-950 text-amber-300 border-amber-800';
                if (item.title.includes('HACK')) badgeColor = 'bg-orange-950 text-orange-300 border-orange-800';
                if (item.title.includes('Placeholder') || item.title.includes('Unimplemented')) badgeColor = 'bg-rose-950 text-rose-300 border-rose-800';

                return (
                  <tr key={item.id} className="hover:bg-slate-900/50 transition">
                    <td className="py-3 px-4 font-mono font-semibold">
                      <span className={`px-2 py-0.5 rounded text-[10px] border ${badgeColor}`}>
                        {item.title.split(':')[0]}
                      </span>
                    </td>
                    <td className="py-3 px-4 font-medium text-slate-200 max-w-xs truncate">
                      {item.title}
                    </td>
                    <td className="py-3 px-4 font-mono text-cyan-400 whitespace-nowrap">
                      {item.file_path}:{item.start_line}
                    </td>
                    <td className="py-3 px-4 font-mono text-[11px] text-slate-400 max-w-xs truncate">
                      <code>{item.snippet}</code>
                    </td>
                    <td className="py-3 px-4 text-emerald-400 text-[11px] max-w-xs truncate">
                      {item.recommendation}
                    </td>
                  </tr>
                );
              })}

              {filtered.length === 0 && (
                <tr>
                  <td colSpan={5} className="py-8 text-center text-slate-500">
                    No matching loose ends detected.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
