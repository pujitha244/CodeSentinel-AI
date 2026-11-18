import React from 'react';
import { NavLink } from 'react-router-dom';
import {
  Bot,
  Code2,
  FileText,
  GitMerge,
  HelpCircle,
  Home,
  Layers,
  LayoutDashboard,
  ListTodo,
  PackageSearch,
  PlusCircle,
  Settings,
  ShieldAlert,
  Wrench
} from 'lucide-react';

const groups = [
  {
    label: 'Workspace',
    items: [
      { to: '/', label: 'Overview', icon: Home },
      { to: '/dashboard', label: 'Dashboard', icon: LayoutDashboard },
      { to: '/audit/new', label: 'New audit', icon: PlusCircle }
    ]
  },
  {
    label: 'Analysis',
    items: [
      { to: '/chains', label: 'Vulnerability chains', icon: GitMerge, flagship: true },
      { to: '/findings', label: 'Security findings', icon: ShieldAlert },
      { to: '/quality', label: 'Code quality', icon: Code2 },
      { to: '/logic-gaps', label: 'Logic gaps', icon: HelpCircle },
      { to: '/loose-ends', label: 'Loose ends', icon: ListTodo },
      { to: '/dependencies', label: 'Dependencies', icon: PackageSearch },
      { to: '/architecture', label: 'Architecture', icon: Layers }
    ]
  },
  {
    label: 'Tools',
    items: [
      { to: '/remediation', label: 'Remediation lab', icon: Wrench },
      { to: '/assistant', label: 'Security assistant', icon: Bot },
      { to: '/reports', label: 'Reports', icon: FileText },
      { to: '/settings', label: 'Settings', icon: Settings }
    ]
  }
];

export const Sidebar: React.FC = () => (
  <aside className="sticky top-14 block h-[calc(100vh-3.5rem)] w-14 shrink-0 overflow-y-auto border-r border-slate-800 bg-sentinel-950 px-2 py-4 md:w-56">
    <nav aria-label="Main navigation" className="space-y-5">
      {groups.map((group) => (
        <section key={group.label}>
          <h2 className="mb-1.5 px-3 text-[10px] font-semibold uppercase tracking-[0.14em] text-slate-600 max-md:sr-only">
            {group.label}
          </h2>
          <div className="space-y-0.5">
            {group.items.map((item) => {
              const Icon = item.icon;
              return (
                <NavLink
                  key={item.to}
                  to={item.to}
                  end={item.to === '/'}
                  title={item.label}
                  aria-label={item.label}
                  className={({ isActive }) =>
                    `group flex min-h-9 items-center gap-2.5 border-l-2 px-2.5 text-xs transition-colors max-md:justify-center max-md:px-0 ${
                      isActive
                        ? 'border-cyan-500 bg-cyan-950/30 font-medium text-cyan-200'
                        : 'border-transparent text-slate-400 hover:bg-slate-900 hover:text-slate-200'
                    }`
                  }
                >
                  <Icon
                    className={`h-4 w-4 shrink-0 ${
                      item.flagship ? 'text-cyan-400' : 'text-current opacity-80'
                    }`}
                    aria-hidden="true"
                  />
                  <span className="truncate max-md:sr-only">{item.label}</span>
                  {item.flagship && (
                    <span className="ml-auto text-[9px] font-medium uppercase tracking-wide text-cyan-500 max-md:hidden">
                      Core
                    </span>
                  )}
                </NavLink>
              );
            })}
          </div>
        </section>
      ))}
    </nav>
  </aside>
);
