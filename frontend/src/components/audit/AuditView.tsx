import React, { useEffect, useState } from 'react';
import { ScrollText, RefreshCw, User, Calendar, Shield, Activity } from 'lucide-react';
import { api } from '../../api/client';
import { AuditLog } from '../../types';
import { LoadingSpinner } from '../common/LoadingSpinner';

export const AuditView: React.FC = () => {
  const [logs, setLogs] = useState<AuditLog[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [filterAction, setFilterAction] = useState<string>('ALL');

  const fetchLogs = async () => {
    setIsLoading(true);
    try {
      const data = await api.listAuditLogs(100);
      setLogs(data);
    } catch {
      setLogs([]);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchLogs();
  }, []);

  const filteredLogs = logs.filter((log) => {
    if (filterAction === 'ALL') return true;
    return log.action.includes(filterAction);
  });

  const getActionBadgeColor = (action: string) => {
    if (action.includes('BASELINE')) return 'bg-cyan-500/10 text-cyan-400 border-cyan-500/30';
    if (action.includes('DRIFT')) return 'bg-rose-500/10 text-rose-400 border-rose-500/30';
    if (action.includes('REPAIR') || action.includes('REMEDIATION'))
      return 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30';
    if (action.includes('SCHEDULED')) return 'bg-amber-500/10 text-amber-400 border-amber-500/30';
    return 'bg-slate-800 text-slate-300 border-slate-700';
  };

  if (isLoading) {
    return <LoadingSpinner size="lg" label="Loading persistent audit logs..." />;
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-slate-800">
        <div>
          <h1 className="text-xl font-bold font-mono text-slate-100 flex items-center gap-2">
            <ScrollText className="w-5 h-5 text-cyan-400" />
            Security Engine Audit Trail
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Persisted cryptographic timeline of all baselines, detections, remediations, and scheduled scans.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <select
            value={filterAction}
            onChange={(e) => setFilterAction(e.target.value)}
            className="p-1.5 rounded-lg bg-slate-900 border border-slate-800 text-xs font-mono text-slate-300 focus:outline-none"
          >
            <option value="ALL">All Actions</option>
            <option value="BASELINE">Baseline Actions</option>
            <option value="DRIFT">Drift Detections</option>
            <option value="REPAIR">Repairs & Remediations</option>
            <option value="SCHEDULED">Scheduled Scans</option>
          </select>

          <button
            onClick={fetchLogs}
            className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-xs font-mono text-slate-300 hover:text-white transition-colors"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            Refresh
          </button>
        </div>
      </div>

      {/* Log Feed Table */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/60 overflow-hidden">
        {filteredLogs.length === 0 ? (
          <div className="p-12 text-center text-xs font-mono text-slate-500">
            No audit records found matching criteria.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-slate-950/80 border-b border-slate-800 text-slate-400">
                <tr>
                  <th className="px-6 py-3 font-semibold">Timestamp</th>
                  <th className="px-6 py-3 font-semibold">Actor</th>
                  <th className="px-6 py-3 font-semibold">Action</th>
                  <th className="px-6 py-3 font-semibold">Entity Type</th>
                  <th className="px-6 py-3 font-semibold">Metadata / Details</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {filteredLogs.map((log) => (
                  <tr key={log.id} className="hover:bg-slate-800/30 transition-colors">
                    <td className="px-6 py-3.5 text-slate-400 whitespace-nowrap">
                      {new Date(log.timestamp).toLocaleString()}
                    </td>
                    <td className="px-6 py-3.5 text-slate-200">
                      <span className="inline-flex items-center gap-1.5 text-cyan-300 font-semibold">
                        <User className="w-3 h-3 text-slate-500" />
                        {log.username}
                      </span>
                    </td>
                    <td className="px-6 py-3.5">
                      <span
                        className={`inline-block px-2.5 py-0.5 rounded-full text-[10px] font-bold border ${getActionBadgeColor(
                          log.action
                        )}`}
                      >
                        {log.action}
                      </span>
                    </td>
                    <td className="px-6 py-3.5 text-slate-400 uppercase">
                      {log.entity_type || '—'}
                    </td>
                    <td className="px-6 py-3.5 text-slate-300 font-sans text-[11px] max-w-md">
                      {log.details && Object.keys(log.details).length > 0 ? (
                        <div className="flex flex-wrap gap-1.5">
                          {Object.entries(log.details).map(([key, value]) => (
                            <span
                              key={key}
                              className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-slate-800 border border-slate-700 text-[10px] font-mono"
                            >
                              <span className="text-slate-400">{key}:</span>
                              <span className="text-cyan-300 font-semibold">{String(value)}</span>
                            </span>
                          ))}
                        </div>
                      ) : (
                        '—'
                      )}
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
