import React, { useEffect, useState } from 'react';
import { Project, ArchitectureGraph } from '../types';
import { api } from '../services/api';
import { ArchitectureDependencyGraph } from '../components/visualizer/ArchitectureDependencyGraph';
import { Layers, Loader2, AlertCircle } from 'lucide-react';

interface ArchitecturePageProps {
  currentProject: Project | null;
}

export const ArchitecturePage: React.FC<ArchitecturePageProps> = ({ currentProject }) => {
  const [graph, setGraph] = useState<ArchitectureGraph | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (currentProject) {
      setLoading(true);
      api.getArchitectureGraph(currentProject.id)
        .then(res => {
          setGraph(res);
          setLoading(false);
        })
        .catch(err => {
          setError(err.message || 'Failed to load architecture graph');
          setLoading(false);
        });
    }
  }, [currentProject]);

  if (!currentProject) {
    return (
      <div className="py-20 text-center text-xs text-slate-500">
        Please load or ingest a project to view the architecture graph.
      </div>
    );
  }

  if (loading) {
    return (
      <div className="py-20 flex flex-col items-center justify-center gap-3 text-xs text-slate-400">
        <Loader2 className="w-6 h-6 text-cyan-400 animate-spin" />
        <span>Extracting AST call graph & module relationships...</span>
      </div>
    );
  }

  if (error || !graph) {
    return (
      <div className="p-6 text-xs text-rose-400 flex items-center gap-2">
        <AlertCircle className="w-4 h-4" />
        <span>{error || 'Unable to build architecture graph.'}</span>
      </div>
    );
  }

  return (
    <div className="py-6 px-6 max-w-7xl mx-auto flex flex-col gap-6">
      <ArchitectureDependencyGraph graph={graph} />
    </div>
  );
};
