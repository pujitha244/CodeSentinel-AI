import React, { useEffect, useState } from 'react';
import { ArchitectureGraph } from '../../types';
import { FileCode, Layers, GitBranch, Search, Filter } from 'lucide-react';

interface ArchitectureDependencyGraphProps {
  graph: ArchitectureGraph;
  onSelectFile?: (filePath: string) => void;
}

export const ArchitectureDependencyGraph: React.FC<ArchitectureDependencyGraphProps> = ({
  graph,
  onSelectFile
}) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedNode, setSelectedNode] = useState<ArchitectureGraph['nodes'][number] | null>(graph.nodes[0] || null);

  useEffect(() => {
    setSelectedNode(graph.nodes[0] || null);
  }, [graph]);

  const filteredNodes = graph.nodes.filter(n => 
    n.data.label.toLowerCase().includes(searchTerm.toLowerCase())
  );

  return (
    <div className="rounded-2xl border border-slate-800 bg-sentinel-950 p-6 flex flex-col gap-6">
      {/* Header & Controls */}
      <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div>
          <h2 className="text-lg font-bold text-slate-100 flex items-center gap-2">
            <Layers className="w-5 h-5 text-indigo-400" />
            Module relationships
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Visual structural graph extracted statically from repository source files, imports, and inter-file calls.
          </p>
        </div>

        <div className="flex items-center gap-3 w-full md:w-auto">
          <div className="relative flex-1 md:w-64">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
            <input
              type="text"
              placeholder="Search components..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full pl-9 pr-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
            />
          </div>
          <div className="flex items-center gap-2 text-xs text-slate-400 font-mono bg-slate-900 px-3 py-1.5 rounded-lg border border-slate-800">
            <span>{graph.summary.file_count} files</span>
            <span>•</span>
            <span>{graph.summary.edge_count} edges</span>
          </div>
        </div>
      </div>

      {/* Grid of File Modules */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {filteredNodes.map(node => {
          const isSelected = selectedNode?.id === node.id;
          const label = node.data.label;

          // Find inbound & outbound edges for this node
          const outgoing = graph.edges.filter(e => e.source === node.id);
          const incoming = graph.edges.filter(e => e.target === node.id);

          return (
            <button
              type="button"
              aria-pressed={isSelected}
              aria-label={`Inspect module ${label}`}
              key={node.id}
              onClick={() => {
                setSelectedNode(node);
                if (onSelectFile) onSelectFile(label);
              }}
              className={`w-full text-left rounded-lg border p-4 transition-colors bg-slate-900/80 hover:bg-slate-900 ${
                isSelected 
                  ? 'border-indigo-500 ring-1 ring-indigo-500/30'
                  : 'border-slate-800 hover:border-slate-700'
              }`}
            >
              <div className="flex items-center justify-between mb-3">
                <div className="flex items-center gap-2">
                  <FileCode className="w-4 h-4 text-indigo-400" />
                  <span className="font-semibold text-xs text-slate-200 font-mono truncate max-w-[160px]">
                    {label}
                  </span>
                </div>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-indigo-300 border border-slate-700 uppercase">
                  {node.data.language || 'Code'}
                </span>
              </div>

              <div className="flex items-center justify-between text-[11px] text-slate-400 font-mono mt-4 pt-3 border-t border-slate-800/80">
                <span>{node.data.functionCount || 0} functions</span>
                <div className="flex items-center gap-2">
                  <span className="text-cyan-400">↑ {outgoing.length} out</span>
                  <span className="text-emerald-400">↓ {incoming.length} in</span>
                </div>
              </div>
            </button>
          );
        })}
        {filteredNodes.length === 0 && (
          <p className="col-span-full py-8 text-center text-xs text-slate-500" role="status">
            No modules match this search.
          </p>
        )}
      </div>

      {/* Selected Node Connections Panel */}
      {selectedNode && (
        <div className="rounded-xl border border-indigo-900/50 bg-indigo-950/20 p-4">
          <h4 className="text-xs font-bold uppercase tracking-wider text-indigo-400 mb-2">
            Selected Node Relationships: {selectedNode.data.label}
          </h4>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs font-mono">
            <div>
              <span className="text-slate-400 font-semibold">Imports / Calls Outward:</span>
              <ul className="mt-1 space-y-1 text-slate-300">
                {graph.edges.filter(e => e.source === selectedNode.id).map(e => (
                  <li key={e.id} className="truncate">
                    → <span className="text-cyan-300">{e.target.replace('file-', '')}</span> ({e.label})
                  </li>
                ))}
                {graph.edges.filter(e => e.source === selectedNode.id).length === 0 && (
                  <li className="text-slate-500">None detected</li>
                )}
              </ul>
            </div>
            <div>
              <span className="text-slate-400 font-semibold">Referenced By (Inward):</span>
              <ul className="mt-1 space-y-1 text-slate-300">
                {graph.edges.filter(e => e.target === selectedNode.id).map(e => (
                  <li key={e.id} className="truncate">
                    ← <span className="text-emerald-300">{e.source.replace('file-', '')}</span> ({e.label})
                  </li>
                ))}
                {graph.edges.filter(e => e.target === selectedNode.id).length === 0 && (
                  <li className="text-slate-500">None detected</li>
                )}
              </ul>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
