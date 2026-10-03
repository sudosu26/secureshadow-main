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
} from 'lucide-react';
import { api } from '../../api/client';
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
      const [bData, aData, cData, rData, pData] = await Promise.all([
        api.getBaseline().catch(() => null),
        api.listAssets().catch(() => []),
        api.listControls().catch(() => []),
        api.listRemediations().catch(() => []),
        api.listProperties().catch(() => []),
      ]);

      setBaseline(bData);
      setAssets(aData);
      setControls(cData);
      setRemediations(rData);
      setProperties(pData);

      // Attempt to load decay report if baseline is active
      if (bData?.is_active) {
        try {
          const dData = await api.getDecayReport();
          setDecay(dData);
        } catch {
          setDecay(null);
        }
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
    loadDashboardData();
  }, []);

  if (isLoading) {
    return <LoadingSpinner size="lg" label="Loading security metrics & topology..." />;
  }

  if (error) {
    return (
      <div className="p-6 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-300">
        <h3 className="font-semibold text-sm font-mono mb-2">Error Loading Dashboard</h3>
        <p className="text-xs mb-4">{error}</p>
        <button
          onClick={loadDashboardData}
          className="px-3 py-1.5 rounded-lg bg-rose-600 hover:bg-rose-500 text-white text-xs font-mono"
        >
          Retry
        </button>
      </div>
    );
  }

  // If no baseline captured yet, show real empty state
  if (!baseline?.is_active && assets.length === 0) {
    return (
      <EmptyState
        icon={Camera}
        title="No Baseline Established"
        description="SECURESHADOW requires a known-good baseline snapshot to detect architectural drift and control degradation."
        actionText="Establish Initial Baseline"
        onAction={() => onNavigate('baseline')}
      />
    );
  }

  const currentProtection = decay ? decay.current_protection : 100.0;
  const decayPercent = decay ? decay.decay_percent : 0.0;
  const healthLabel = decay ? decay.health_label : 'HEALTHY';
  const openRemediationsCount = remediations.filter((r) => r.status !== 'RESOLVED').length;

  return (
    <div className="space-y-6">
      {/* Header & Quick Action Row */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-slate-800">
        <div>
          <h1 className="text-xl font-bold font-mono text-slate-100 flex items-center gap-2">
            <Activity className="w-5 h-5 text-cyan-400" />
            Security Posture & Control Integrity
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Real-time monitoring of control effectiveness against architectural drift.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={loadDashboardData}
            disabled={isRefreshing}
            className="p-2 rounded-lg bg-slate-900 border border-slate-800 text-slate-400 hover:text-slate-200 transition-colors"
            title="Refresh Metrics"
          >
            <RefreshCw className={`w-4 h-4 ${isRefreshing ? 'animate-spin' : ''}`} />
          </button>

          <button
            onClick={() => onNavigate('drift')}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-mono font-medium transition-colors shadow-sm shadow-cyan-950"
          >
            <GitCompare className="w-3.5 h-3.5" />
            Scan for Drift
          </button>
        </div>
      </div>

      {/* KPI Cards Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Protection Level */}
        <div className="p-5 rounded-xl bg-slate-900/80 border border-slate-800 relative overflow-hidden">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-mono text-slate-400 uppercase tracking-wider">
              Protection Level
            </span>
            {currentProtection >= 90 ? (
              <ShieldCheck className="w-5 h-5 text-emerald-400" />
            ) : (
              <ShieldAlert className="w-5 h-5 text-amber-400" />
            )}
          </div>
          <div className="text-3xl font-bold font-mono text-slate-100 mb-2">
            {currentProtection.toFixed(0)}%
          </div>
          {/* Progress bar */}
          <div className="w-full h-1.5 rounded-full bg-slate-800 overflow-hidden mb-2">
            <div
              className={`h-full transition-all duration-500 ${
                currentProtection >= 90
                  ? 'bg-emerald-500'
                  : currentProtection >= 70
                  ? 'bg-yellow-500'
                  : currentProtection >= 40
                  ? 'bg-amber-500'
                  : 'bg-rose-500'
              }`}
              style={{ width: `${currentProtection}%` }}
            />
          </div>
          <div className="text-[11px] font-mono text-slate-400 flex justify-between">
            <span>Baseline: 100%</span>
            <span className={decayPercent > 0 ? 'text-rose-400 font-semibold' : 'text-slate-400'}>
              Decay: -{decayPercent.toFixed(0)}%
            </span>
          </div>
        </div>

        {/* System Health Status */}
        <div className="p-5 rounded-xl bg-slate-900/80 border border-slate-800 flex flex-col justify-between">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-mono text-slate-400 uppercase tracking-wider">
              System Health
            </span>
            <Badge variant={healthLabel}>{healthLabel}</Badge>
          </div>
          <div className="text-lg font-bold font-mono text-slate-200 mt-2">
            {healthLabel === 'HEALTHY'
              ? 'All Assumptions Intact'
              : healthLabel === 'AT RISK'
              ? 'Control Bypass Active'
              : 'Degraded Protection'}
          </div>
          <p className="text-[11px] font-mono text-slate-500 mt-2">
            {decay?.contributors.length || 0} Broken Assumption Factor(s)
          </p>
        </div>

        {/* Tracked Infrastructure */}
        <div className="p-5 rounded-xl bg-slate-900/80 border border-slate-800 flex flex-col justify-between">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-mono text-slate-400 uppercase tracking-wider">
              Infrastructure
            </span>
            <Server className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="text-3xl font-bold font-mono text-slate-100">
            {assets.length} <span className="text-xs text-slate-400 font-normal">Assets</span>
          </div>
          <div className="text-[11px] font-mono text-slate-400 flex items-center justify-between mt-2 pt-2 border-t border-slate-800/80">
            <span>{controls.length} Security Controls</span>
            <span>{baseline?.stats.total_edges || 0} Paths</span>
          </div>
        </div>

        {/* Open Remediations */}
        <div className="p-5 rounded-xl bg-slate-900/80 border border-slate-800 flex flex-col justify-between">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-mono text-slate-400 uppercase tracking-wider">
              Remediations
            </span>
            <Wrench className="w-4 h-4 text-amber-400" />
          </div>
          <div className="text-3xl font-bold font-mono text-slate-100">
            {openRemediationsCount} <span className="text-xs text-slate-400 font-normal">Active</span>
          </div>
          <div className="text-[11px] font-mono text-slate-400 flex items-center justify-between mt-2 pt-2 border-t border-slate-800/80">
            <span>Total Tracked: {remediations.length}</span>
            <button
              onClick={() => onNavigate('repairs')}
              className="text-cyan-400 hover:text-cyan-300 flex items-center gap-0.5"
            >
              Manage <ArrowUpRight className="w-3 h-3" />
            </button>
          </div>
        </div>
      </div>

      {/* Properties Breakdown Table */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/60 overflow-hidden">
        <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between">
          <div>
            <h2 className="text-sm font-bold font-mono text-slate-200">
              Tracked Security Properties & Assumed Guarantees
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Formal conditions under which each control is guaranteed to protect assets.
            </p>
          </div>
          <span className="text-xs font-mono text-slate-500">
            {properties.length} Active Guarantees
          </span>
        </div>

        {properties.length === 0 ? (
          <div className="p-8 text-center text-xs font-mono text-slate-500">
            No properties registered. Capture a baseline or add properties in inventory.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-950/70 border-b border-slate-800 text-slate-400 font-mono">
                <tr>
                  <th className="px-6 py-3 font-semibold">Property ID</th>
                  <th className="px-6 py-3 font-semibold">Guarantee Description</th>
                  <th className="px-6 py-3 font-semibold">Protected Control</th>
                  <th className="px-6 py-3 font-semibold">Severity</th>
                  <th className="px-6 py-3 font-semibold">Effective Protection</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-mono">
                {properties.map((prop) => (
                  <tr key={prop.property_id} className="hover:bg-slate-800/30 transition-colors">
                    <td className="px-6 py-3.5 text-cyan-400 font-semibold">{prop.property_id}</td>
                    <td className="px-6 py-3.5 text-slate-200 font-sans max-w-md">
                      {prop.description}
                    </td>
                    <td className="px-6 py-3.5 text-slate-300">{prop.control_id}</td>
                    <td className="px-6 py-3.5">
                      <Badge variant={prop.severity as any}>{prop.severity.toUpperCase()}</Badge>
                    </td>
                    <td className="px-6 py-3.5">
                      <div className="flex items-center gap-2">
                        <span className="font-semibold text-slate-200">
                          {currentProtection.toFixed(0)}%
                        </span>
                        <div className="w-16 h-1.5 rounded-full bg-slate-800 overflow-hidden">
                          <div
                            className={`h-full ${
                              currentProtection >= 90 ? 'bg-emerald-500' : 'bg-amber-500'
                            }`}
                            style={{ width: `${currentProtection}%` }}
                          />
                        </div>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};
