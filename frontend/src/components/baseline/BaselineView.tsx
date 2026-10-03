import React, { useEffect, useState } from 'react';
import { Camera, FileCode, CheckCircle2, AlertTriangle, Layers, Network, Shield } from 'lucide-react';
import { api } from '../../api/client';
import { BaselineStats } from '../../types';
import { LoadingSpinner } from '../common/LoadingSpinner';
import { EmptyState } from '../common/EmptyState';
import { Modal } from '../common/Modal';

export const BaselineView: React.FC = () => {
  const [baseline, setBaseline] = useState<BaselineStats | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [isCapturing, setIsCapturing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  // Terraform modal state
  const [isTfModalOpen, setIsTfModalOpen] = useState(false);
  const [tfJsonString, setTfJsonString] = useState('');
  const [tfParseError, setTfParseError] = useState<string | null>(null);

  const fetchBaseline = async () => {
    setIsLoading(true);
    setError(null);
    try {
      const data = await api.getBaseline();
      setBaseline(data);
    } catch (err: any) {
      if (err.status === 404) {
        setBaseline(null);
      } else {
        setError(err.message || 'Error fetching baseline status.');
      }
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchBaseline();
  }, []);

  const handleCaptureDemo = async () => {
    setIsCapturing(true);
    setError(null);
    setSuccessMsg(null);
    try {
      const res = await api.captureBaseline('demo');
      setSuccessMsg(
        `Baseline established successfully with ${res.total_nodes} nodes and ${res.total_edges} edges.`
      );
      await fetchBaseline();
    } catch (err: any) {
      setError(err.message || 'Failed to capture demo baseline.');
    } finally {
      setIsCapturing(false);
    }
  };

  const handleCaptureTerraform = async () => {
    setTfParseError(null);
    let parsed: any = null;
    try {
      parsed = JSON.parse(tfJsonString);
    } catch {
      setTfParseError('Invalid JSON format. Please ensure input is valid JSON.');
      return;
    }

    setIsCapturing(true);
    setIsTfModalOpen(false);
    setError(null);
    setSuccessMsg(null);

    try {
      const res = await api.captureBaseline('terraform', parsed);
      setSuccessMsg(
        `Terraform baseline captured: ${res.total_nodes} nodes, ${res.total_edges} edges.`
      );
      await fetchBaseline();
    } catch (err: any) {
      setError(err.message || 'Failed to ingest Terraform configuration.');
    } finally {
      setIsCapturing(false);
    }
  };

  if (isLoading) {
    return <LoadingSpinner size="lg" label="Checking baseline status..." />;
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-slate-800">
        <div>
          <h1 className="text-xl font-bold font-mono text-slate-100 flex items-center gap-2">
            <Camera className="w-5 h-5 text-cyan-400" />
            Baseline Topology & Assumptions
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            The reference state of your infrastructure against which all architectural drift is measured.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          {/* Production Ingestion Path */}
          <div className="flex items-center gap-2 p-1 pl-2.5 pr-1 rounded-lg bg-slate-900/90 border border-cyan-500/30">
            <span className="text-[10px] font-mono uppercase tracking-wider text-cyan-400 font-bold flex items-center gap-1.5">
              <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 shadow-sm shadow-cyan-400" />
              Real Infra
            </span>
            <button
              onClick={() => setIsTfModalOpen(true)}
              disabled={isCapturing}
              className="flex items-center gap-1.5 px-3 py-1 rounded-md bg-slate-800 hover:bg-slate-700 text-slate-100 text-xs font-mono font-medium border border-slate-700 transition-colors"
            >
              <FileCode className="w-3.5 h-3.5 text-cyan-400" />
              Ingest Terraform Plan
            </button>
          </div>

          {/* Sample Demo Sandbox Path */}
          <div className="flex items-center gap-2 p-1 pl-2.5 pr-1 rounded-lg bg-slate-900/90 border border-amber-500/30">
            <span className="text-[10px] font-mono uppercase tracking-wider text-amber-400 font-bold flex items-center gap-1.5">
              <span className="w-1.5 h-1.5 rounded-full bg-amber-400" />
              Sample Demo
            </span>
            <button
              onClick={handleCaptureDemo}
              disabled={isCapturing}
              className="flex items-center gap-1.5 px-3 py-1 rounded-md bg-amber-500/15 hover:bg-amber-500/25 border border-amber-500/40 text-amber-200 text-xs font-mono font-medium transition-colors"
            >
              {isCapturing ? (
                <span className="w-3.5 h-3.5 border-2 border-amber-300/30 border-t-amber-300 rounded-full animate-spin" />
              ) : (
                <Camera className="w-3.5 h-3.5 text-amber-400" />
              )}
              Capture Demo Baseline
            </button>
          </div>
        </div>
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

      {!baseline?.is_active ? (
        <EmptyState
          icon={Camera}
          title="No Active Baseline Snapshot"
          description="Capture a baseline using the canonical WAF reference model or by submitting a terraform show -json state."
          actionText="Capture Demo Baseline"
          onAction={handleCaptureDemo}
        />
      ) : (
        <div className="space-y-6">
          {/* Stats Grid */}
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            <div className="p-5 rounded-xl bg-slate-900/80 border border-slate-800">
              <div className="flex items-center justify-between text-xs font-mono text-slate-400 uppercase mb-2">
                <span>Total Nodes</span>
                <Layers className="w-4 h-4 text-cyan-400" />
              </div>
              <div className="text-3xl font-bold font-mono text-slate-100">
                {baseline.stats.total_nodes}
              </div>
              <div className="text-[11px] font-mono text-slate-500 mt-2">
                {Object.entries(baseline.stats.node_types || {})
                  .map(([type, count]) => `${count} ${type}`)
                  .join(' • ')}
              </div>
            </div>

            <div className="p-5 rounded-xl bg-slate-900/80 border border-slate-800">
              <div className="flex items-center justify-between text-xs font-mono text-slate-400 uppercase mb-2">
                <span>Active Edges</span>
                <Network className="w-4 h-4 text-cyan-400" />
              </div>
              <div className="text-3xl font-bold font-mono text-slate-100">
                {baseline.stats.total_edges}
              </div>
              <div className="text-[11px] font-mono text-slate-500 mt-2">
                {Object.entries(baseline.stats.edge_relationships || {})
                  .map(([rel, count]) => `${count} ${rel}`)
                  .join(' • ')}
              </div>
            </div>

            <div className="p-5 rounded-xl bg-slate-900/80 border border-slate-800">
              <div className="flex items-center justify-between text-xs font-mono text-slate-400 uppercase mb-2">
                <span>Enforced Assumptions</span>
                <Shield className="w-4 h-4 text-emerald-400" />
              </div>
              <div className="text-3xl font-bold font-mono text-slate-100">
                {baseline.assumptions.length}
              </div>
              <div className="text-[11px] font-mono text-emerald-400/90 mt-2">
                Conditions required for control efficacy
              </div>
            </div>
          </div>

          {/* Declared Assumptions Panel */}
          <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-6">
            <h2 className="text-sm font-bold font-mono text-slate-200 mb-1">
              Explicit Environmental Assumptions
            </h2>
            <p className="text-xs text-slate-400 mb-4">
              Preconditions required for active security controls to function. If infrastructure drift violates these, decay begins.
            </p>

            <ul className="space-y-2">
              {baseline.assumptions.map((asm, idx) => (
                <li
                  key={idx}
                  className="p-3 rounded-lg bg-slate-950 border border-slate-800/80 font-mono text-xs flex items-start gap-3 text-slate-200"
                >
                  <span className="text-cyan-400 font-bold shrink-0">ASM-00{idx + 1}:</span>
                  <span>{asm}</span>
                </li>
              ))}
            </ul>
          </div>
        </div>
      )}

      {/* Terraform Ingestion Modal */}
      <Modal
        isOpen={isTfModalOpen}
        onClose={() => setIsTfModalOpen(false)}
        title="Ingest Terraform State / Plan (JSON)"
        maxWidth="lg"
      >
        <div className="space-y-4">
          <p className="text-xs text-slate-400 leading-relaxed">
            Paste the output of <code className="text-cyan-300">terraform show -json</code>.
            SECURESHADOW will parse AWS EC2, ALBs, WAF ACLs, and Security Groups into a typed security graph.
          </p>

          {tfParseError && (
            <div className="p-2.5 rounded bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs font-mono">
              {tfParseError}
            </div>
          )}

          <textarea
            value={tfJsonString}
            onChange={(e) => setTfJsonString(e.target.value)}
            rows={10}
            placeholder='{ "format_version": "1.0", "values": { "root_module": { "resources": [...] } } }'
            className="w-full p-3 rounded-lg bg-slate-950 border border-slate-800 font-mono text-xs text-slate-100 placeholder-slate-700 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500"
          />

          <div className="flex justify-end gap-2 pt-2">
            <button
              onClick={() => setIsTfModalOpen(false)}
              className="px-3 py-1.5 rounded-lg text-xs font-mono text-slate-400 hover:text-slate-200"
            >
              Cancel
            </button>
            <button
              onClick={handleCaptureTerraform}
              disabled={!tfJsonString.trim()}
              className="px-4 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white text-xs font-mono font-medium"
            >
              Parse & Capture Baseline
            </button>
          </div>
        </div>
      </Modal>
    </div>
  );
};
