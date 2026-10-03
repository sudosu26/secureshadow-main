import React, { useState } from 'react';
import { GitCompare, AlertTriangle, ShieldAlert, Sparkles, RefreshCw } from 'lucide-react';
import { api } from '../../api/client';
import { ChangeEvent, DriftDetectionResponse } from '../../types';
import { Badge } from '../common/Badge';
import { EmptyState } from '../common/EmptyState';

export const DriftView: React.FC = () => {
  const [driftData, setDriftData] = useState<DriftDetectionResponse | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [isDrifting, setIsDrifting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [statusMsg, setStatusMsg] = useState<string | null>(null);

  const handleIntroduceDrift = async () => {
    setIsDrifting(true);
    setError(null);
    setStatusMsg(null);
    try {
      const res = await api.submitCurrentState('demo_drift');
      setStatusMsg(
        `Architectural drift introduced: rogue uninspected bypass added (${res.total_nodes} nodes).`
      );
    } catch (err: any) {
      setError(err.message || 'Failed to introduce architectural drift.');
    } finally {
      setIsDrifting(false);
    }
  };

  const handleRunDetection = async () => {
    setIsLoading(true);
    setError(null);
    try {
      const res = await api.detectDrift();
      setDriftData(res);
      setStatusMsg(
        `Drift scan completed: ${res.total_changes} change(s) detected (${res.critical_count} critical).`
      );
    } catch (err: any) {
      setError(err.message || 'Drift detection failed. Ensure baseline is set and current state is submitted.');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header & Actions */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-slate-800">
        <div>
          <h1 className="text-xl font-bold font-mono text-slate-100 flex items-center gap-2">
            <GitCompare className="w-5 h-5 text-cyan-400" />
            Architectural Drift Detection
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Detects new uninspected communication paths, rogue assets, or removed controls bypassing established policies.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={handleIntroduceDrift}
            disabled={isDrifting || isLoading}
            className="flex items-center gap-2 px-3.5 py-1.5 rounded-lg bg-amber-500/10 hover:bg-amber-500/20 text-amber-300 border border-amber-500/30 text-xs font-mono font-medium transition-colors"
          >
            {isDrifting ? (
              <span className="w-3.5 h-3.5 border-2 border-amber-400/30 border-t-amber-400 rounded-full animate-spin" />
            ) : (
              <Sparkles className="w-3.5 h-3.5 text-amber-400" />
            )}
            Introduce Drift Scenario
          </button>

          <button
            onClick={handleRunDetection}
            disabled={isLoading}
            className="flex items-center gap-2 px-4 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white text-xs font-mono font-medium transition-colors shadow-sm shadow-cyan-950"
          >
            {isLoading ? (
              <RefreshCw className="w-3.5 h-3.5 animate-spin" />
            ) : (
              <GitCompare className="w-3.5 h-3.5" />
            )}
            Run Drift Detection
          </button>
        </div>
      </div>

      {/* Notifications */}
      {statusMsg && (
        <div className="p-4 rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-300 text-xs font-mono flex items-center gap-2.5">
          <Sparkles className="w-4 h-4 text-cyan-400 shrink-0" />
          <span>{statusMsg}</span>
        </div>
      )}

      {error && (
        <div className="p-4 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs font-mono flex items-center gap-2.5">
          <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Results View */}
      {!driftData ? (
        <EmptyState
          icon={GitCompare}
          title="No Drift Analysis Executed"
          description="Click 'Run Drift Detection' to compare the active environment graph against the baseline snapshot and identify violations."
          actionText="Run Detection Now"
          onAction={handleRunDetection}
        />
      ) : driftData.changes.length === 0 ? (
        <div className="p-12 text-center rounded-xl border border-slate-800 bg-slate-900/40">
          <h3 className="text-base font-semibold text-emerald-400 font-mono mb-1">
            Zero Architectural Drift Detected
          </h3>
          <p className="text-xs text-slate-400 font-mono">
            Current infrastructure perfectly matches the verified baseline. No uninspected routes found.
          </p>
        </div>
      ) : (
        <div className="space-y-4">
          <div className="flex items-center justify-between px-1">
            <div className="flex items-center gap-3 text-xs font-mono text-slate-300">
              <span>Total Changes: <strong>{driftData.total_changes}</strong></span>
              <span className="text-rose-400">Critical: <strong>{driftData.critical_count}</strong></span>
              <span className="text-amber-400">Warning: <strong>{driftData.warning_count}</strong></span>
            </div>
          </div>

          <div className="rounded-xl border border-slate-800 bg-slate-900/60 overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs font-mono">
                <thead className="bg-slate-950/80 border-b border-slate-800 text-slate-400">
                  <tr>
                    <th className="px-6 py-3 font-semibold">Severity</th>
                    <th className="px-6 py-3 font-semibold">Change Type</th>
                    <th className="px-6 py-3 font-semibold">Event Description</th>
                    <th className="px-6 py-3 font-semibold">Breaks Assumption?</th>
                    <th className="px-6 py-3 font-semibold">Violated Condition</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {driftData.changes.map((change: ChangeEvent, idx: number) => (
                    <tr key={idx} className="hover:bg-slate-800/30 transition-colors">
                      <td className="px-6 py-4">
                        <Badge variant={change.severity}>
                          {change.severity.toUpperCase()}
                        </Badge>
                      </td>
                      <td className="px-6 py-4 text-cyan-400 font-semibold">
                        {change.change_type}
                      </td>
                      <td className="px-6 py-4 text-slate-200 font-sans max-w-sm">
                        {change.description}
                      </td>
                      <td className="px-6 py-4">
                        {change.potentially_breaks_assumptions ? (
                          <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-rose-500/20 text-rose-300 border border-rose-500/40">
                            <ShieldAlert className="w-3.5 h-3.5 text-rose-400" />
                            YES (BREACH)
                          </span>
                        ) : (
                          <span className="text-slate-500">NO</span>
                        )}
                      </td>
                      <td className="px-6 py-4 text-slate-300 font-sans max-w-xs">
                        {change.affected_assumption_desc ? (
                          <span className="text-amber-300/90 text-[11px]">
                            {change.affected_assumption_desc}
                          </span>
                        ) : (
                          <span className="text-slate-600">None</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
