import React from 'react';
import { FolderGit2, LogOut, Play, Shield } from 'lucide-react';
import { Link } from 'react-router-dom';
import { Project } from '../../types';

interface NavbarProps {
  currentProject: Project | null;
  projects: Project[];
  onSelectProject: (projectId: string) => void;
  onLoadDemo: () => void;
  onSignOut?: () => void;
  isLoadingDemo?: boolean;
}

export const Navbar: React.FC<NavbarProps> = ({
  currentProject,
  projects,
  onSelectProject,
  onLoadDemo,
  onSignOut,
  isLoadingDemo = false
}) => (
  <header className="sticky top-0 z-40 w-full border-b border-slate-800 bg-sentinel-950">
    <div className="flex min-h-14 items-center justify-between gap-4 px-4 sm:px-6">
      <Link to="/" className="flex min-w-0 items-center gap-2.5" aria-label="CodeSentinel AI overview">
        <span className="flex h-8 w-8 shrink-0 items-center justify-center border border-cyan-900 bg-cyan-950/60">
          <Shield className="h-4 w-4 text-cyan-300" />
        </span>
        <span className="truncate text-sm font-semibold tracking-tight text-slate-100">
          CodeSentinel <span className="text-cyan-400">AI</span>
        </span>
      </Link>

      <div className="flex min-w-0 items-center gap-2">
        <FolderGit2 className="hidden h-4 w-4 shrink-0 text-slate-500 sm:block" aria-hidden="true" />
        <label className="sr-only" htmlFor="active-project">Active project</label>
        <select
          id="active-project"
          value={currentProject?.id ?? ''}
          onChange={(event) => onSelectProject(event.target.value)}
          disabled={projects.length === 0}
          className="max-w-[42vw] border border-slate-800 bg-slate-900 px-2.5 py-2 text-xs text-slate-200 outline-none transition focus:border-cyan-700 disabled:text-slate-500 sm:max-w-64"
        >
          {projects.length === 0 && <option value="">No project loaded</option>}
          {projects.map((project) => (
            <option key={project.id} value={project.id}>{project.name}</option>
          ))}
        </select>
      </div>

      <div className="flex shrink-0 items-center gap-2">
        {onSignOut && (
          <button
            type="button"
            onClick={onSignOut}
            className="inline-flex items-center gap-2 border border-slate-700 px-3 py-2 text-xs font-medium text-slate-300 transition hover:border-slate-500 hover:bg-slate-900"
            aria-label="Sign out"
          >
            <LogOut className="h-3.5 w-3.5" aria-hidden="true" />
            <span className="hidden sm:inline">Sign out</span>
          </button>
        )}
        <button
          type="button"
          onClick={onLoadDemo}
          disabled={isLoadingDemo}
          className="inline-flex items-center gap-2 border border-cyan-800 bg-cyan-950/50 px-3 py-2 text-xs font-medium text-cyan-200 transition hover:border-cyan-600 hover:bg-cyan-900/50 disabled:cursor-wait disabled:opacity-60"
        >
          <Play className="h-3.5 w-3.5 fill-current" aria-hidden="true" />
          <span className="hidden sm:inline">{isLoadingDemo ? 'Loading demo…' : 'Load demo'}</span>
          <span className="sm:hidden">{isLoadingDemo ? '…' : 'Demo'}</span>
        </button>
      </div>
    </div>
  </header>
);
