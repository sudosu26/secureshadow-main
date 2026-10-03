import React, { useEffect, useState } from 'react';
import {
  Wrench,
  CheckCircle2,
  AlertTriangle,
  Play,
  RotateCw,
  Clock,
  Sparkles,
  ArrowRight,
  ShieldCheck,
} from 'lucide-react';
import { api } from '../../api/client';
import { RepairCandidate, RepairResponse, Remediation } from '../../types';
import { Badge } from '../common/Badge';
import { LoadingSpinner } from '../common/LoadingSpinner';
import { EmptyState } from '../common/EmptyState';
import { Modal } from '../common/Modal';

export const RepairsView: React.FC = () => {
  const [repairsData, setRepairsData] = useState<RepairResponse | null>(null);
  const [remediations, setRemediations] = useState<Remediation[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  // Apply modal
  const [selectedCandidate, setSelectedCandidate] = useState<RepairCandidate | null>(null);
  const [isApplying, setIsApplying] = useState(false);

  // Verifying action state
  const [verifyingId, setVerifyingId] = useState<string | null>(null);

  const loadData = async () => {
    setIsLoading(true);
    setError(null);
    try {
      const [rData, remsData] = await Promise.all([
        api.getRepairs().catch(() => null),
        api.listRemediations().catch(() => []),
      ]);
      setRepairsData(rData);
      setRemediations(remsData);
    } catch (err: any) {
      setError(err.message || 'Failed to load repair recommendations.');
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleApplyRepair = async () => {
    if (!selectedCandidate) return;
    setIsApplying(true);
    setError(null);
    setSuccessMsg(null);
    try {
      const newRem = await api.applyRemediation({
        repair_id: selectedCandidate.repair_id,
        description: selectedCandidate.description,
        action_type: selectedCandidate.action_type,
        target_entity: selectedCandidate.restored_assumptions[0] || 'bypass_path',
      });
      setSuccessMsg(
        `Remediation record '${newRem.remediation_id}' created with status IN_PROGRESS.`
      );
      setSelectedCandidate(null);
      await loadData();
    } catch (err: any) {
      setError(err.message || 'Failed to apply remediation action.');
    } finally {
      setIsApplying(false);
    }
  };

  const handleVerifyRemediation = async (remediationId: string) => {
    setVerifyingId(remediationId);
    setError(null);
    setSuccessMsg(null);
    try {
      const res = await api.verifyRemediation(remediationId);
      if (res.status === 'RESOLVED') {
        setSuccessMsg(
          `Remediation verified and marked RESOLVED! Protection restored to ${res.current_protection.toFixed(0)}%.`
        );
      } else {
        setError(res.message);
      }
      await loadData();
    } catch (err: any) {
      setError(err.message || 'Verification execution failed.');
    } finally {
      setVerifyingId(null);
    }
  };

  if (isLoading) {
    return <LoadingSpinner size="lg" label="Evaluating repair candidates & cost optimization..." />;
  }

  const recommended = repairsData?.recommended_repair;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-slate-800">
        <div>
          <h1 className="text-xl font-bold font-mono text-slate-100 flex items-center gap-2">
            <Wrench className="w-5 h-5 text-cyan-400" />
            Repair Optimization & Remediation Tracking
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Cost-benefit optimization selecting minimum-cost remediations to restore security guarantees.
          </p>
        </div>

        <button
          onClick={loadData}
          className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-xs font-mono text-slate-300 hover:text-white transition-colors"
        >
          <RotateCw className="w-3.5 h-3.5" />
          Refresh
        </button>
      </div>

      {/* Notifications */}
      {successMsg && (
        <div className="p-4 rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 text-xs font-mono flex items-center gap-3">
          <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
          <span>{successMsg}</span>
        </div>
      )}

      {error && (
        <div className="p-4 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs font-mono flex items-center gap-3">
          <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Recommended Repair Card */}
      {recommended && (
        <div className="p-6 rounded-xl bg-emerald-950/20 border border-emerald-500/40 relative overflow-hidden">
          <div className="flex items-center gap-2 text-emerald-400 text-xs font-mono font-bold tracking-wider uppercase mb-2">
            <Sparkles className="w-4 h-4" />
            Recommended Minimum-Cost Remediation
          </div>

          <h2 className="text-base font-semibold text-slate-100 mb-3">
            {recommended.description}
          </h2>

          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 py-3 border-y border-emerald-500/20 text-xs font-mono mb-4">
            <div>
              <span className="text-slate-400">Action Type</span>
              <div className="text-slate-200 font-semibold uppercase mt-0.5">
                {recommended.action_type.replace('_', ' ')}
              </div>
            </div>

            <div>
              <span className="text-slate-400">Total Cost Score</span>
              <div className="text-emerald-400 font-bold text-sm mt-0.5">
                {recommended.total_cost.toFixed(1)} / 100
              </div>
            </div>

            <div>
              <span className="text-slate-400">Security Restored</span>
              <div className="text-emerald-400 font-bold text-sm mt-0.5">
                +{recommended.security_improvement.toFixed(0)}%
              </div>
            </div>

            <div>
              <span className="text-slate-400">Cost-Effectiveness</span>
              <div className="text-cyan-400 font-bold text-sm mt-0.5">
                {recommended.cost_effectiveness_ratio.toFixed(2)}
              </div>
            </div>
          </div>

          <button
            onClick={() => setSelectedCandidate(recommended)}
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-mono font-medium transition-colors shadow-sm shadow-emerald-950"
          >
            Apply This Repair
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </div>
      )}

      {/* Candidate Repairs Table */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/60 overflow-hidden">
        <div className="px-6 py-4 border-b border-slate-800">
          <h3 className="text-sm font-bold font-mono text-slate-200">
            All Evaluated Candidate Repairs (Cost vs. Efficacy)
          </h3>
          <p className="text-xs text-slate-400 mt-0.5">
            Ranked by multi-factor cost model: 0.35×Implementation + 0.30×Business Impact + 0.25×Operational Risk + 0.10×Time.
          </p>
        </div>

        {!repairsData || repairsData.candidates.length === 0 ? (
          <div className="p-8 text-center text-xs font-mono text-slate-500">
            No repair candidates generated. Trigger drift detection to compute interventions.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-slate-950/80 border-b border-slate-800 text-slate-400">
                <tr>
                  <th className="px-6 py-3 font-semibold">Action</th>
                  <th className="px-6 py-3 font-semibold">Remediation Description</th>
                  <th className="px-6 py-3 font-semibold">Total Cost</th>
                  <th className="px-6 py-3 font-semibold">Restoration</th>
                  <th className="px-6 py-3 font-semibold">Cost-Ratio</th>
                  <th className="px-6 py-3 font-semibold text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {repairsData.candidates.map((cand: RepairCandidate) => (
                  <tr key={cand.repair_id} className="hover:bg-slate-800/30 transition-colors">
                    <td className="px-6 py-4">
                      <span className="font-semibold text-slate-300 uppercase">
                        {cand.action_type.replace('_', ' ')}
                      </span>
                      {cand.is_recommended && (
                        <span className="block text-[10px] text-emerald-400 font-bold">
                          ★ RECOMMENDED
                        </span>
                      )}
                    </td>
                    <td className="px-6 py-4 text-slate-200 font-sans max-w-sm">
                      {cand.description}
                    </td>
                    <td className="px-6 py-4 font-bold text-slate-300">
                      {cand.total_cost.toFixed(1)}
                    </td>
                    <td className="px-6 py-4 text-emerald-400 font-bold">
                      +{cand.security_improvement.toFixed(0)}%
                    </td>
                    <td className="px-6 py-4 text-cyan-400 font-semibold">
                      {cand.cost_effectiveness_ratio.toFixed(2)}
                    </td>
                    <td className="px-6 py-4 text-right">
                      <button
                        onClick={() => setSelectedCandidate(cand)}
                        className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-mono font-medium border border-slate-700 transition-colors"
                      >
                        Apply
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Tracked Remediations Section (Part B.3) */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/60 overflow-hidden">
        <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between">
          <div>
            <h3 className="text-sm font-bold font-mono text-slate-200 flex items-center gap-2">
              <ShieldCheck className="w-4 h-4 text-cyan-400" />
              Active Remediation Lifecycle Tracker
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Closed-loop remediation workflow: applied fixes are tracked and verified against the live graph.
            </p>
          </div>
          <span className="text-xs font-mono text-slate-500">
            {remediations.length} Tracked Action(s)
          </span>
        </div>

        {remediations.length === 0 ? (
          <div className="p-8 text-center text-xs font-mono text-slate-500">
            No remediation actions applied yet. Select a candidate repair above to begin tracking.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-slate-950/80 border-b border-slate-800 text-slate-400">
                <tr>
                  <th className="px-6 py-3 font-semibold">Remediation ID</th>
                  <th className="px-6 py-3 font-semibold">Action Type</th>
                  <th className="px-6 py-3 font-semibold">Description</th>
                  <th className="px-6 py-3 font-semibold">Status</th>
                  <th className="px-6 py-3 font-semibold">Applied At</th>
                  <th className="px-6 py-3 font-semibold text-right">Verify Resolution</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {remediations.map((rem: Remediation) => (
                  <tr key={rem.remediation_id} className="hover:bg-slate-800/30 transition-colors">
                    <td className="px-6 py-4 text-cyan-400 font-semibold">{rem.remediation_id}</td>
                    <td className="px-6 py-4 text-slate-300 uppercase">
                      {rem.action_type.replace('_', ' ')}
                    </td>
                    <td className="px-6 py-4 text-slate-200 font-sans max-w-sm">
                      {rem.description}
                    </td>
                    <td className="px-6 py-4">
                      <Badge variant={rem.status}>{rem.status}</Badge>
                    </td>
                    <td className="px-6 py-4 text-slate-400">
                      {new Date(rem.created_at).toLocaleTimeString()}
                    </td>
                    <td className="px-6 py-4 text-right">
                      {rem.status !== 'RESOLVED' ? (
                        <button
                          onClick={() => handleVerifyRemediation(rem.remediation_id)}
                          disabled={verifyingId === rem.remediation_id}
                          className="flex items-center gap-1.5 ml-auto px-3 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white text-xs font-mono font-medium transition-colors shadow-sm"
                        >
                          {verifyingId === rem.remediation_id ? (
                            <span className="w-3.5 h-3.5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                          ) : (
                            <Play className="w-3.5 h-3.5" />
                          )}
                          Verify Resolution
                        </button>
                      ) : (
                        <span className="text-emerald-400 text-xs font-semibold inline-flex items-center gap-1">
                          <CheckCircle2 className="w-4 h-4" /> Verified
                        </span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Confirmation Modal */}
      <Modal
        isOpen={!!selectedCandidate}
        onClose={() => setSelectedCandidate(null)}
        title="Confirm Remediation Action"
      >
        {selectedCandidate && (
          <div className="space-y-4">
            <p className="text-xs text-slate-300 leading-relaxed font-sans">
              You are applying the following security remediation to isolate or remove the detected drift:
            </p>

            <div className="p-3.5 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono space-y-1.5">
              <div><strong className="text-slate-400">Action:</strong> {selectedCandidate.action_type}</div>
              <div><strong className="text-slate-400">Description:</strong> {selectedCandidate.description}</div>
              <div><strong className="text-slate-400">Estimated Cost:</strong> {selectedCandidate.total_cost.toFixed(1)} / 100</div>
              <div><strong className="text-slate-400">Restoration:</strong> +{selectedCandidate.security_improvement.toFixed(0)}%</div>
            </div>

            <p className="text-[11px] text-slate-400 font-mono">
              Applying this repair creates an <span className="text-cyan-400">IN_PROGRESS</span> remediation task.
              You can verify whether the security finding is resolved by clicking 'Verify Resolution'.
            </p>

            <div className="flex justify-end gap-2 pt-2">
              <button
                onClick={() => setSelectedCandidate(null)}
                className="px-3 py-1.5 rounded-lg text-xs font-mono text-slate-400 hover:text-slate-200"
              >
                Cancel
              </button>
              <button
                onClick={handleApplyRepair}
                disabled={isApplying}
                className="px-4 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white text-xs font-mono font-medium"
              >
                {isApplying ? 'Applying...' : 'Confirm & Apply'}
              </button>
            </div>
          </div>
        )}
      </Modal>
    </div>
  );
};
