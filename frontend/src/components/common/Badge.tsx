import React from 'react';
import { Severity, HealthLabel, RemediationStatus } from '../../types';

interface BadgeProps {
  variant?: Severity | HealthLabel | RemediationStatus | 'default';
  children: React.ReactNode;
  className?: string;
}

export const Badge: React.FC<BadgeProps> = ({ variant = 'default', children, className = '' }) => {
  const getStyles = () => {
    switch (variant) {
      case 'critical':
      case 'CRITICAL':
      case 'FAILED':
        return 'bg-rose-500/10 text-rose-400 border-rose-500/30';
      case 'warning':
      case 'high':
      case 'AT RISK':
      case 'IN_PROGRESS':
        return 'bg-amber-500/10 text-amber-400 border-amber-500/30';
      case 'DEGRADED':
      case 'medium':
        return 'bg-yellow-500/10 text-yellow-400 border-yellow-500/30';
      case 'HEALTHY':
      case 'RESOLVED':
        return 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30';
      case 'info':
      case 'low':
      case 'OPEN':
        return 'bg-sky-500/10 text-sky-400 border-sky-500/30';
      default:
        return 'bg-slate-800 text-slate-300 border-slate-700';
    }
  };

  return (
    <span
      className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-mono font-medium border ${getStyles()} ${className}`}
    >
      {children}
    </span>
  );
};
