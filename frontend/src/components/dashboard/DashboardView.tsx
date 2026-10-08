import React, { useEffect, useState } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  Server,
  Wrench,
  Activity,
  ArrowUpRight,
  RefreshCw,
  GitCompare,
  Camera,
  CheckCircle2,
  LockKeyhole,
} from 'lucide-react';
import { api, ApiError } from '../../api/client';
import { DecayReport, BaselineStats, Asset, SecurityControl, Remediation, SecurityProperty } from '../../types';
import { Badge } from '../common/Badge';
import { LoadingSpinner } from '../common/LoadingSpinner';
import { EmptyState } from '../common/EmptyState';
import { NavTab } from '../layout/Navbar';

interface DashboardViewProps {
  onNavigate: (tab: NavTab) => void;
}

export const DashboardView: React.FC<DashboardViewProps> = ({ onNavigate }) => {
  const [decay, setDecay] = useState<DecayReport | null>(null);
  const [baseline, setBaseline] = useState<BaselineStats | null>(null);
  const [assets, setAssets] = useState<Asset[]>([]);
  const [controls, setControls] = useState<SecurityControl[]>([]);
  const [remediations, setRemediations] = useState<Remediation[]>([]);
  const [properties, setProperties] = useState<SecurityProperty[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [isRefreshing, setIsRefreshing] = useState(false);

  const loadDashboardData = async () => {
    setIsRefreshing(true);
    setError(null);
    try {
      api.clearCache();
      const [bData, aData, cData, rData, pData] = await Promise.all([
        api.getBaseline().catch((error: unknown) => {
          if (error instanceof ApiError && error.status === 404) {
            return null;
          }
          throw error;
        }),
        api.listAssets(),
        api.listControls(),
        api.listRemediations(),
        api.listProperties(),
      ]);

      setBaseline(bData);
      setAssets(aData);
      setControls(cData);
      setRemediations(rData);
      setProperties(pData);

      if (bData?.is_active) {
        const dData = await api.getDecayReport();
        setDecay(dData);
      } else {
        setDecay(null);
      }
    } catch (err: any) {
      setError(err.message || 'Failed to load dashboard overview data.');
    } finally {
      setIsLoading(false);
      setIsRefreshing(false);
    }
  };

  useEffect(() => {
    const refresh = () => {
      loadDashboardData();
    };
    window.addEventListener('state:updated', refresh);
    refresh();
    return () => window.removeEventListener('state:updated', refresh);
  }, []);

  if (isLoading) {
    return <LoadingSpinner size="lg" label="Loading security metrics & topology..." />;
  }

  if (error) {
    return (
      <section className="mx-auto max-w-2xl rounded-2xl border border-rose-400/20 bg-rose-400/[0.06] p-6 sm:p-8" aria-labelledby="dashboard-error-title">
        <div className="flex items-start gap-4">
          <div className="flex size-10 shrink-0 items-center justify-center rounded-xl border border-rose-400/20 bg-rose-400/10 text-rose-300">
            <ShieldAlert className="size-5" aria-hidden="true" />
          </div>
          <div className="min-w-0 flex-1">
            <p className="text-[11px] font-semibold uppercase tracking-[0.18em] text-rose-300/80">Dashboard unavailable</p>
            <h1 id="dashboard-error-title" className="mt-1 text-lg font-semibold text-slate-100">We couldn&apos;t load your security overview</h1>
            <p className="mt-2 break-words text-sm leading-6 text-slate-400">{error}</p>
            <button
              onClick={loadDashboardData}
              disabled={isRefreshing}
              className="mt-5 inline-flex min-h-10 items-center gap-2 rounded-lg border border-rose-300/20 bg-rose-400/10 px-4 text-sm font-medium text-rose-200 transition hover:bg-rose-400/20 disabled:cursor-not-allowed disabled:opacity-60"
            >
              <RefreshCw className={`size-4 ${isRefreshing ? 'animate-spin' : ''}`} aria-hidden="true" />
              Try again
            </button>
          </div>
        </div>
      </section>
    );
  }

  if (!baseline?.is_active && assets.length === 0) {
    return (
      <div className="mx-auto max-w-3xl py-6 sm:py-12">
        <EmptyState
          icon={Camera}
          title="No Baseline Established"
          description="SECURESHADOW requires a known-good baseline snapshot to detect architectural drift and control degradation."
          actionText="Establish Initial Baseline"
          onAction={() => onNavigate('baseline')}
        />
      </div>
    );
  }

  const currentProtection = decay ? decay.current_protection : 100.0;
  const decayPercent = decay ? decay.decay_percent : 0.0;
  const healthLabel = decay ? decay.health_label : 'HEALTHY';
  const openRemediationsCount = remediations.filter((r) => r.status !== 'RESOLVED').length;
  const healthDescription = healthLabel === 'HEALTHY'
    ? 'All assumptions intact'
    : healthLabel === 'AT RISK'
      ? 'Control bypass active'
      : 'Protection needs attention';
  const protectionColor = currentProtection >= 90
    ? 'bg-emerald-400'
    : currentProtection >= 70
      ? 'bg-yellow-400'
      : currentProtection >= 40
        ? 'bg-amber-400'
        : 'bg-rose-400';

  return (
    <div className="space-y-6 pb-6 sm:space-y-8">
      <section className="relative overflow-hidden rounded-2xl border border-slate-800/90 bg-slate-900/70 p-5 shadow-[0_18px_60px_-36px_rgba(0,0,0,0.85)] sm:p-7 lg:p-8">
        <div className="pointer-events-none absolute -right-12 -top-20 size-64 rounded-full bg-cyan-400/[0.06] blur-3xl" aria-hidden="true" />
        <div className="relative flex flex-col gap-6 xl:flex-row xl:items-end xl:justify-between">
          <div className="min-w-0">
            <div className="mb-3 flex flex-wrap items-center gap-2">
              <span className="inline-flex items-center gap-2 rounded-full border border-cyan-400/15 bg-cyan-400/[0.07] px-2.5 py-1 text-[10px] font-semibold uppercase tracking-[0.16em] text-cyan-200">
                <Activity className="size-3.5" aria-hidden="true" /> Security operations
              </span>
              <span className="text-xs text-slate-500">Protection overview</span>
            </div>
            <h1 className="max-w-3xl text-2xl font-semibold tracking-tight text-white sm:text-3xl">
              Security posture &amp; control integrity
            </h1>
            <p className="mt-2 max-w-2xl text-sm leading-6 text-slate-400 sm:text-[15px]">
              Monitor how architectural changes affect the controls protecting your infrastructure.
            </p>
          </div>
          <div className="flex w-full flex-col gap-2 sm:w-auto sm:flex-row sm:items-center">
            <button
              onClick={loadDashboardData}
              disabled={isRefreshing}
              className="inline-flex min-h-11 items-center justify-center gap-2 rounded-lg border border-slate-700/90 bg-slate-950/50 px-4 text-sm font-medium text-slate-300 transition hover:border-slate-600 hover:bg-slate-800/80 hover:text-white disabled:cursor-not-allowed disabled:opacity-60"
              aria-label="Refresh dashboard metrics"
            >
              <RefreshCw className={`size-4 ${isRefreshing ? 'animate-spin' : ''}`} aria-hidden="true" />
              Refresh
            </button>
            <button
              onClick={() => onNavigate('drift')}
              className="inline-flex min-h-11 items-center justify-center gap-2 rounded-lg bg-cyan-500 px-4 text-sm font-semibold text-slate-950 shadow-lg shadow-cyan-950/30 transition hover:bg-cyan-300 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-300 focus-visible:ring-offset-2 focus-visible:ring-offset-slate-950"
            >
              <GitCompare className="size-4" aria-hidden="true" />
              Scan for drift
            </button>
          </div>
        </div>
        <div className="relative mt-6 flex flex-wrap items-center gap-x-5 gap-y-2 border-t border-slate-800/80 pt-4 text-xs text-slate-400">
          <span className="inline-flex items-center gap-2">
            <span className="relative flex size-2">
              <span className="absolute inline-flex size-full animate-ping rounded-full bg-emerald-400/50" />
              <span className="relative inline-flex size-2 rounded-full bg-emerald-400" />
            </span>
            Monitoring active
          </span>
          <span className="inline-flex items-center gap-1.5"><LockKeyhole className="size-3.5 text-slate-500" aria-hidden="true" /> Baseline {baseline?.is_active ? 'established' : 'not established'}</span>
          <span className="inline-flex items-center gap-1.5"><CheckCircle2 className="size-3.5 text-slate-500" aria-hidden="true" /> {properties.length} tracked guarantees</span>
        </div>
      </section>

      <section aria-label="Security posture metrics" className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <article className="group rounded-2xl border border-slate-800/90 bg-slate-900/70 p-5 transition-colors hover:border-slate-700 sm:p-6">
          <div className="flex items-start justify-between gap-3">
            <div>
              <p className="text-xs font-medium text-slate-400">Protection level</p>
              <p className="mt-3 text-4xl font-semibold tracking-tight text-white tabular-nums">{currentProtection.toFixed(0)}<span className="ml-0.5 text-2xl text-slate-400">%</span></p>
            </div>
            <div className={`flex size-10 items-center justify-center rounded-xl border ${currentProtection >= 90 ? 'border-emerald-400/20 bg-emerald-400/10 text-emerald-300' : 'border-amber-400/20 bg-amber-400/10 text-amber-300'}`}>
              {currentProtection >= 90 ? <ShieldCheck className="size-5" aria-hidden="true" /> : <ShieldAlert className="size-5" aria-hidden="true" />}
            </div>
          </div>
          <div className="mt-5 h-1.5 overflow-hidden rounded-full bg-slate-800" role="progressbar" aria-label="Current protection level" aria-valuemin={0} aria-valuemax={100} aria-valuenow={Math.max(0, Math.min(100, currentProtection))}>
            <div className={`h-full rounded-full transition-all duration-500 ${protectionColor}`} style={{ width: `${Math.max(0, Math.min(100, currentProtection))}%` }} />
          </div>
          <div className="mt-3 flex items-center justify-between gap-2 text-[11px]">
            <span className="text-slate-500">Baseline: 100%</span>
            <span className={decayPercent > 0 ? 'font-medium text-rose-300' : 'text-slate-400'}>Decay: −{decayPercent.toFixed(0)}%</span>
          </div>
        </article>

        <article className="group rounded-2xl border border-slate-800/90 bg-slate-900/70 p-5 transition-colors hover:border-slate-700 sm:p-6">
          <div className="flex items-start justify-between gap-3">
            <div>
              <p className="text-xs font-medium text-slate-400">System health</p>
              <p className="mt-3 text-xl font-semibold tracking-tight text-white">{healthDescription}</p>
            </div>
            <div className="flex size-10 items-center justify-center rounded-xl border border-slate-700/80 bg-slate-950/60 text-slate-300">
              <Activity className="size-5" aria-hidden="true" />
            </div>
          </div>
          <div className="mt-4 flex items-center justify-between gap-3">
            <Badge variant={healthLabel}>{healthLabel}</Badge>
            <span className="text-right text-xs text-slate-500">{decay?.contributors.length || 0} broken assumptions</span>
          </div>
        </article>

        <article className="group rounded-2xl border border-slate-800/90 bg-slate-900/70 p-5 transition-colors hover:border-slate-700 sm:p-6">
          <div className="flex items-start justify-between gap-3">
            <div>
              <p className="text-xs font-medium text-slate-400">Infrastructure</p>
              <p className="mt-3 text-4xl font-semibold tracking-tight text-white tabular-nums">{assets.length}<span className="ml-2 text-sm font-medium text-slate-400">assets</span></p>
            </div>
            <div className="flex size-10 items-center justify-center rounded-xl border border-cyan-400/20 bg-cyan-400/10 text-cyan-200">
              <Server className="size-5" aria-hidden="true" />
            </div>
          </div>
          <div className="mt-5 flex items-center justify-between border-t border-slate-800/80 pt-3 text-xs">
            <span className="text-slate-400">{controls.length} security controls</span>
            <span className="text-slate-500">{baseline?.stats.total_edges || 0} paths</span>
          </div>
        </article>

        <article className="group rounded-2xl border border-slate-800/90 bg-slate-900/70 p-5 transition-colors hover:border-slate-700 sm:p-6">
          <div className="flex items-start justify-between gap-3">
            <div>
              <p className="text-xs font-medium text-slate-400">Remediations</p>
              <p className="mt-3 text-4xl font-semibold tracking-tight text-white tabular-nums">{openRemediationsCount}<span className="ml-2 text-sm font-medium text-slate-400">active</span></p>
            </div>
            <div className="flex size-10 items-center justify-center rounded-xl border border-amber-400/20 bg-amber-400/10 text-amber-200">
              <Wrench className="size-5" aria-hidden="true" />
            </div>
          </div>
          <div className="mt-5 flex items-center justify-between border-t border-slate-800/80 pt-3 text-xs">
            <span className="text-slate-400">{remediations.length} total tracked</span>
            <button onClick={() => onNavigate('repairs')} className="inline-flex min-h-7 items-center gap-1 font-medium text-cyan-300 transition hover:text-cyan-200 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-300" aria-label="Manage remediations">
              Manage <ArrowUpRight className="size-3.5" aria-hidden="true" />
            </button>
          </div>
        </article>
      </section>

      <section className="overflow-hidden rounded-2xl border border-slate-800/90 bg-slate-900/65" aria-labelledby="properties-title">
        <div className="flex flex-col gap-3 border-b border-slate-800/90 px-5 py-5 sm:flex-row sm:items-center sm:justify-between sm:px-6">
          <div>
            <div className="flex items-center gap-2">
              <div className="flex size-8 items-center justify-center rounded-lg border border-slate-700/80 bg-slate-950/70 text-cyan-300">
                <LockKeyhole className="size-4" aria-hidden="true" />
              </div>
              <h2 id="properties-title" className="text-sm font-semibold text-slate-100 sm:text-base">Security properties &amp; guarantees</h2>
            </div>
            <p className="mt-2 max-w-2xl text-xs leading-5 text-slate-400 sm:ml-10 sm:text-sm">
              Conditions that must remain true for each control to protect your assets.
            </p>
          </div>
          <span className="inline-flex w-fit items-center rounded-full border border-slate-700/80 bg-slate-950/60 px-3 py-1.5 text-xs font-medium text-slate-300">
            {properties.length} active {properties.length === 1 ? 'guarantee' : 'guarantees'}
          </span>
        </div>

        {properties.length === 0 ? (
          <div className="px-5 py-12 text-center sm:px-6">
            <div className="mx-auto flex size-11 items-center justify-center rounded-xl border border-slate-800 bg-slate-950/70 text-slate-500">
              <LockKeyhole className="size-5" aria-hidden="true" />
            </div>
            <p className="mt-3 text-sm font-medium text-slate-300">No security properties yet</p>
            <p className="mt-1 text-xs text-slate-500">Capture a baseline or add properties in your inventory.</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[760px] text-left text-sm">
              <thead className="bg-slate-950/45 text-[11px] font-medium uppercase tracking-wider text-slate-500">
                <tr>
                  <th scope="col" className="px-5 py-3.5 font-medium sm:px-6">Property ID</th>
                  <th scope="col" className="px-5 py-3.5 font-medium sm:px-6">Guarantee description</th>
                  <th scope="col" className="px-5 py-3.5 font-medium sm:px-6">Protected control</th>
                  <th scope="col" className="px-5 py-3.5 font-medium sm:px-6">Severity</th>
                  <th scope="col" className="px-5 py-3.5 font-medium sm:px-6">Protection</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/80">
                {properties.map((prop) => (
                  <tr key={prop.property_id} className="transition-colors hover:bg-slate-800/25">
                    <td className="whitespace-nowrap px-5 py-4 font-mono text-xs font-medium text-cyan-300 sm:px-6">{prop.property_id}</td>
                    <td className="max-w-md px-5 py-4 leading-5 text-slate-300 sm:px-6">{prop.description}</td>
                    <td className="whitespace-nowrap px-5 py-4 font-mono text-xs text-slate-400 sm:px-6">{prop.control_id}</td>
                    <td className="whitespace-nowrap px-5 py-4 sm:px-6"><Badge variant={prop.severity as any}>{prop.severity.toUpperCase()}</Badge></td>
                    <td className="whitespace-nowrap px-5 py-4 sm:px-6">
                      <div className="flex items-center gap-3">
                        <span className="min-w-9 font-mono text-xs font-medium tabular-nums text-slate-200">{currentProtection.toFixed(0)}%</span>
                        <div className="h-1.5 w-16 overflow-hidden rounded-full bg-slate-800" role="progressbar" aria-label={`${prop.property_id} protection`} aria-valuemin={0} aria-valuemax={100} aria-valuenow={Math.max(0, Math.min(100, currentProtection))}>
                          <div className={`h-full rounded-full ${protectionColor}`} style={{ width: `${Math.max(0, Math.min(100, currentProtection))}%` }} />
                        </div>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
};

export default DashboardView;
