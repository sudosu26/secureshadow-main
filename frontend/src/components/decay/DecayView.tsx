import React, { useEffect, useState } from 'react';
import { TrendingDown, ShieldAlert, AlertCircle, RefreshCw } from 'lucide-react';
import { api } from '../../api/client';
import { DecayReport, DecayContributor } from '../../types';
import { Badge } from '../common/Badge';
import { LoadingSpinner } from '../common/LoadingSpinner';
import { EmptyState } from '../common/EmptyState';

export const DecayView: React.FC = () => {
  const [report, setReport] = useState<DecayReport | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchDecay = async () => {
    setIsLoading(true);
    setError(null);
    try {
      const data = await api.getDecayReport();
      setReport(data);
    } catch (err: any) {
      if (err.status === 400) {
        setReport(null);
      } else {
        setError(err.message || 'Failed to fetch decay attribution report.');
      }
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchDecay();
  }, []);

  if (isLoading) {
    return <LoadingSpinner size="lg" label="Computing protection decay attribution..." />;
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-slate-800">
        <div>
          <h1 className="text-xl font-bold font-mono text-slate-100 flex items-center gap-2">
            <TrendingDown className="w-5 h-5 text-rose-400" />
            Protection Decay Evidence & Attribution
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Deterministic attribution model explaining exactly which structural changes eroded security guarantees.
          </p>
        </div>

        <button
          onClick={fetchDecay}
          className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-xs font-mono text-slate-300 hover:text-white transition-colors"
        >
          <RefreshCw className="w-3.5 h-3.5" />
          Recalculate Decay
        </button>
      </div>

      {error && (
        <div className="p-4 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs font-mono flex items-center gap-2.5">
          <AlertCircle className="w-4 h-4 text-rose-400 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {!report ? (
        <EmptyState
          icon={TrendingDown}
          title="No Protection Decay Calculated"
          description="Capture a baseline and execute a drift scan to calculate protection erosion scores."
          actionText="Recalculate Now"
          onAction={fetchDecay}
        />
      ) : (
        <div className="space-y-6">
          {/* Executive Summary Card */}
          <div className="p-6 rounded-xl bg-slate-900/80 border border-slate-800 space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
              <div>
                <span className="text-[11px] font-mono text-slate-400 uppercase tracking-wider">
                  Target Security Guarantee
                </span>
                <h2 className="text-base font-semibold text-slate-100 mt-0.5">
                  {report.property_desc}
                </h2>
              </div>
              <Badge variant={report.health_label}>{report.health_label}</Badge>
            </div>

            {/* Metrics visual row */}
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 pt-4 border-t border-slate-800/80">
              <div>
                <span className="text-xs font-mono text-slate-400">Baseline Guarantee</span>
                <div className="text-2xl font-bold font-mono text-slate-100">
                  {report.baseline_protection.toFixed(1)}%
                </div>
              </div>

              <div>
                <span className="text-xs font-mono text-slate-400">Current Protection Level</span>
                <div
                  className={`text-2xl font-bold font-mono ${
                    report.current_protection >= 90
                      ? 'text-emerald-400'
                      : report.current_protection >= 70
                      ? 'text-yellow-400'
                      : 'text-rose-400'
                  }`}
                >
                  {report.current_protection.toFixed(1)}%
                </div>
              </div>

              <div>
                <span className="text-xs font-mono text-slate-400">Protection Erosion (Decay)</span>
                <div className="text-2xl font-bold font-mono text-rose-400">
                  -{report.decay_percent.toFixed(1)}%
                </div>
              </div>
            </div>

            {/* Plain English Narrative */}
            <div className="p-4 rounded-lg bg-slate-950/80 border border-slate-800/80 text-xs font-sans leading-relaxed text-slate-300">
              <span className="font-semibold text-cyan-400 font-mono">Executive Summary: </span>
              {report.decay_percent === 0 ? (
                <span>
                  The security control remains fully effective. All external communication paths traverse the
                  authorized inspection controls as expected.
                </span>
              ) : (
                <span>
                  While the primary security control remains active and reports healthy configuration,
                  unreviewed infrastructure changes have introduced direct data flows that bypass inspection.
                  As a consequence, real protection has eroded by <strong>{report.decay_percent.toFixed(1)}%</strong>,
                  leaving sensitive customer data vulnerable to uninspected traffic.
                </span>
              )}
            </div>
          </div>

          {/* Attribution Evidence Table */}
          <div className="rounded-xl border border-slate-800 bg-slate-900/60 overflow-hidden">
            <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between">
              <div>
                <h3 className="text-sm font-bold font-mono text-slate-200">
                  Cause Attribution & Mathematical Breakdown
                </h3>
                <p className="text-xs text-slate-400 mt-0.5">
                  Exact penalty calculation per broken assumption: Base Impact Weight × Property Severity Multiplier.
                </p>
              </div>
              <span className="text-xs font-mono text-slate-500">
                {report.contributors.length} Contributing Factor(s)
              </span>
            </div>

            {report.contributors.length === 0 ? (
              <div className="p-8 text-center text-xs font-mono text-slate-500">
                No active decay contributors found. All environmental assumptions hold true.
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs font-mono">
                  <thead className="bg-slate-950/80 border-b border-slate-800 text-slate-400">
                    <tr>
                      <th className="px-6 py-3 font-semibold">Deduction</th>
                      <th className="px-6 py-3 font-semibold">Root Cause Event</th>
                      <th className="px-6 py-3 font-semibold">Broken Security Assumption</th>
                      <th className="px-6 py-3 font-semibold">Risk Mechanism</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60">
                    {report.contributors.map((contrib: DecayContributor, idx: number) => (
                      <tr key={idx} className="hover:bg-slate-800/30 transition-colors">
                        <td className="px-6 py-4 text-rose-400 font-bold text-sm">
                          -{contrib.impact_percent.toFixed(1)}%
                        </td>
                        <td className="px-6 py-4 text-slate-200 font-sans max-w-sm">
                          {contrib.change_desc}
                        </td>
                        <td className="px-6 py-4 text-amber-300 font-sans max-w-md">
                          {contrib.assumption_desc}
                        </td>
                        <td className="px-6 py-4 text-slate-400 font-sans text-[11px] max-w-xs">
                          {contrib.change_desc.includes('data flow') || contrib.change_desc.includes('path')
                            ? 'Bypasses the Web Application Firewall, allowing direct external ingress.'
                            : 'Unreviewed asset introduced without security baseline policy checks.'}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
