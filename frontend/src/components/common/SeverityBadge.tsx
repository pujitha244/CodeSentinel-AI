import React from 'react';
import { Severity } from '../../types';
import { AlertOctagon, AlertTriangle, AlertCircle, Info, ShieldAlert } from 'lucide-react';

interface SeverityBadgeProps {
  severity: Severity | string;
  size?: 'sm' | 'md' | 'lg';
  showIcon?: boolean;
}

export const SeverityBadge: React.FC<SeverityBadgeProps> = ({ 
  severity, 
  size = 'md', 
  showIcon = true 
}) => {
  const sev = severity.toLowerCase();

  const styles: Record<string, { bg: string; text: string; border: string; icon: any }> = {
    critical: {
      bg: 'bg-rose-950/70',
      text: 'text-rose-400',
      border: 'border-rose-800/80',
      icon: ShieldAlert
    },
    high: {
      bg: 'bg-orange-950/70',
      text: 'text-orange-400',
      border: 'border-orange-800/80',
      icon: AlertOctagon
    },
    medium: {
      bg: 'bg-amber-950/70',
      text: 'text-amber-400',
      border: 'border-amber-800/80',
      icon: AlertTriangle
    },
    low: {
      bg: 'bg-sky-950/70',
      text: 'text-sky-400',
      border: 'border-sky-800/80',
      icon: AlertCircle
    },
    info: {
      bg: 'bg-slate-900/80',
      text: 'text-slate-400',
      border: 'border-slate-700/80',
      icon: Info
    }
  };

  const style = styles[sev] || styles.info;
  const IconComponent = style.icon;

  const sizeClasses = {
    sm: 'text-xs px-2 py-0.5 gap-1',
    md: 'text-xs px-2.5 py-1 gap-1.5',
    lg: 'text-sm px-3.5 py-1.5 gap-2'
  }[size];

  return (
    <span className={`inline-flex items-center font-semibold uppercase tracking-wider rounded-md border ${style.bg} ${style.text} ${style.border} ${sizeClasses}`}>
      {showIcon && <IconComponent className={size === 'sm' ? 'w-3 h-3' : 'w-3.5 h-3.5'} />}
      {severity}
    </span>
  );
};
