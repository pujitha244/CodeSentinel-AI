import React from 'react';
import { Shield, Sparkles, Activity, Play, FolderGit2, AlertCircle } from 'lucide-react';
import { Project } from '../../types';

interface NavbarProps {
  currentProject: Project | null;
  onLoadDemo: () => void;
  isLoadingDemo?: boolean;
}

export const Navbar: React.FC<NavbarProps> = ({
  currentProject,
  onLoadDemo,
  isLoadingDemo = false
}) => {
  return (
    <header className="sticky top-0 z-40 w-full border-b border-slate-800 bg-sentinel-950/80 backdrop-blur-md">
      <div className="flex h-16 items-center justify-between px-6">
        {/* Brand identity */}
        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-gradient-to-tr from-cyan-600 to-indigo-600 shadow-lg shadow-cyan-500/20">
            <Shield className="h-5 w-5 text-white" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="font-extrabold text-base tracking-tight text-white">
                CodeSentinel <span className="text-cyan-400">AI</span>
              </span>
              <span className="rounded bg-indigo-950/80 border border-indigo-700/60 px-1.5 py-0.5 text-[10px] font-mono font-semibold text-indigo-300">
                v1.0 • Mycrobo Hackathon
              </span>
            </div>
            <p className="text-[11px] text-slate-400 hidden sm:block">
              Understand Your Code • Discover Hidden Risks • Fix With Confidence
            </p>
          </div>
        </div>

        {/* Center / Project indicator */}
        <div className="hidden md:flex items-center gap-2 px-3 py-1.5 rounded-lg border border-slate-800 bg-slate-900/60 text-xs">
          <FolderGit2 className="w-4 h-4 text-cyan-400" />
          <span className="text-slate-400">Active Project:</span>
          <span className="font-semibold text-slate-200 max-w-[200px] truncate">
            {currentProject ? currentProject.name : 'No project loaded'}
          </span>
        </div>

        {/* Actions */}
        <div className="flex items-center gap-3">
          <button
            onClick={onLoadDemo}
            disabled={isLoadingDemo}
            className="flex items-center gap-2 rounded-lg bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white px-3.5 py-2 text-xs font-semibold shadow-md shadow-cyan-600/20 transition disabled:opacity-50"
          >
            <Play className="w-3.5 h-3.5 fill-current" />
            <span>{isLoadingDemo ? 'Loading Sample...' : 'Try Demo Project'}</span>
          </button>
        </div>
      </div>
    </header>
  );
};
