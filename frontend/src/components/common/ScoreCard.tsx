import React from 'react';

interface ScoreCardProps {
  title: string;
  score: number;
  maxScore?: number;
  subtitle: string;
  invertColors?: boolean; // For slop score where lower is better
  icon?: React.ReactNode;
}

export const ScoreCard: React.FC<ScoreCardProps> = ({
  title,
  score,
  maxScore = 100,
  subtitle,
  invertColors = false,
  icon
}) => {
  // Determine color scale
  const normalized = (score / maxScore) * 100;
  
  let colorClass = 'text-emerald-400 border-emerald-500/30 bg-emerald-950/20';
  let badgeText = 'Excellent';

  if (!invertColors) {
    if (normalized < 50) {
      colorClass = 'text-rose-400 border-rose-500/30 bg-rose-950/20';
      badgeText = 'Critical Risk';
    } else if (normalized < 75) {
      colorClass = 'text-amber-400 border-amber-500/30 bg-amber-950/20';
      badgeText = 'Needs Work';
    } else if (normalized < 90) {
      colorClass = 'text-sky-400 border-sky-500/30 bg-sky-950/20';
      badgeText = 'Good';
    }
  } else {
    // For slop: low score is clean, high score is slop
    if (normalized > 50) {
      colorClass = 'text-rose-400 border-rose-500/30 bg-rose-950/20';
      badgeText = 'High Slop';
    } else if (normalized > 20) {
      colorClass = 'text-amber-400 border-amber-500/30 bg-amber-950/20';
      badgeText = 'Moderate Slop';
    } else {
      colorClass = 'text-emerald-400 border-emerald-500/30 bg-emerald-950/20';
      badgeText = 'Pristine';
    }
  }

  return (
    <div className="relative overflow-hidden rounded-xl border border-slate-800 bg-sentinel-900/90 p-5 backdrop-blur shadow-sm hover:border-slate-700 transition">
      <div className="flex items-center justify-between">
        <span className="text-xs font-medium uppercase tracking-wider text-slate-400">{title}</span>
        {icon && <div className="text-slate-400">{icon}</div>}
      </div>

      <div className="mt-3 flex items-baseline gap-2">
        <span className={`text-3xl font-extrabold tracking-tight font-mono ${colorClass.split(' ')[0]}`}>
          {score}
        </span>
        <span className="text-xs text-slate-500 font-mono">/{maxScore}</span>
        <span className={`ml-auto text-xs px-2 py-0.5 rounded-full border font-medium ${colorClass}`}>
          {badgeText}
        </span>
      </div>

      <p className="mt-2 text-xs text-slate-400 line-clamp-1">{subtitle}</p>

      {/* Progress bar */}
      <div className="mt-3 h-1.5 w-full overflow-hidden rounded-full bg-slate-800">
        <div 
          className={`h-full transition-all duration-700 ${
            invertColors 
              ? (normalized > 50 ? 'bg-rose-500' : (normalized > 20 ? 'bg-amber-500' : 'bg-emerald-500'))
              : (normalized < 50 ? 'bg-rose-500' : (normalized < 75 ? 'bg-amber-500' : 'bg-emerald-500'))
          }`}
          style={{ width: `${Math.min(100, Math.max(5, normalized))}%` }}
        />
      </div>
    </div>
  );
};
