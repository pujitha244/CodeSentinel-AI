import React from 'react';
import { NavLink } from 'react-router-dom';
import {
  LayoutDashboard,
  ShieldAlert,
  GitMerge,
  Sparkles,
  Layers,
  Wrench,
  Bot,
  FileText,
  Settings,
  PlusCircle,
  HelpCircle,
  Code2,
  ListTodo,
  PackageSearch,
  Home
} from 'lucide-react';

export const Sidebar: React.FC = () => {
  const navItems = [
    { to: '/', label: 'Overview', icon: Home },
    { to: '/dashboard', label: 'Dashboard', icon: LayoutDashboard },
    { to: '/audit/new', label: 'New Audit', icon: PlusCircle, badge: 'Run' },
    { 
      to: '/chains', 
      label: 'Vulnerability Chains', 
      icon: GitMerge, 
      highlight: true, 
      badge: 'Flagship' 
    },
    { to: '/findings', label: 'Security Findings', icon: ShieldAlert },
    { to: '/quality', label: 'Code Quality & Slop', icon: Code2 },
    { to: '/logic-gaps', label: 'Logic Gaps & Boundaries', icon: HelpCircle },
    { to: '/loose-ends', label: 'Loose Ends Tracker', icon: ListTodo },
    { to: '/dependencies', label: 'Dependency Risks', icon: PackageSearch },
    { to: '/architecture', label: 'Architecture Graph', icon: Layers },
    { to: '/remediation', label: 'Safe Auto-Fix Lab', icon: Wrench, badge: 'Fix' },
    { to: '/assistant', label: 'AI Security Assistant', icon: Bot },
    { to: '/reports', label: 'Reports & Export', icon: FileText },
    { to: '/settings', label: 'Settings', icon: Settings },
  ];

  return (
    <aside className="w-64 border-r border-slate-800 bg-sentinel-950 flex flex-col justify-between p-4 min-h-[calc(100vh-4rem)]">
      <div className="space-y-1">
        <div className="px-3 py-2 text-[10px] font-bold uppercase tracking-wider text-slate-500">
          Platform Navigation
        </div>
        {navItems.map((item) => {
          const Icon = item.icon;
          return (
            <NavLink
              key={item.to}
              to={item.to}
              className={({ isActive }) =>
                `flex items-center justify-between px-3 py-2.5 rounded-lg text-xs font-semibold transition-all duration-150 ${
                  isActive
                    ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 shadow-sm'
                    : item.highlight
                    ? 'text-slate-200 hover:bg-rose-950/20 hover:text-rose-400 border border-rose-900/30 bg-rose-950/10'
                    : 'text-slate-400 hover:bg-slate-900 hover:text-slate-200'
                }`
              }
            >
              <div className="flex items-center gap-3">
                <Icon className={`w-4 h-4 ${item.highlight ? 'text-rose-400 animate-pulse' : ''}`} />
                <span>{item.label}</span>
              </div>
              {item.badge && (
                <span
                  className={`text-[9px] font-mono px-1.5 py-0.5 rounded uppercase font-bold ${
                    item.badge === 'Flagship'
                      ? 'bg-rose-900/80 text-rose-300 border border-rose-700/60'
                      : 'bg-slate-800 text-slate-300'
                  }`}
                >
                  {item.badge}
                </span>
              )}
            </NavLink>
          );
        })}
      </div>

      <div className="p-3 rounded-xl border border-slate-800/80 bg-slate-900/50 text-[11px] text-slate-400">
        <div className="font-semibold text-slate-300 mb-1">Confidential Audit</div>
        <p className="text-[10px] text-slate-500 leading-tight">
          Isolated sandbox static analysis with AST verification. Untrusted code is never executed.
        </p>
      </div>
    </aside>
  );
};
