import React, { useEffect, useState } from 'react';
import { Boxes, Plus, Trash2, Shield, Network, Server, AlertCircle, CheckCircle2 } from 'lucide-react';
import { api } from '../../api/client';
import { Asset, SecurityControl, CommunicationPath } from '../../types';
import { LoadingSpinner } from '../common/LoadingSpinner';
import { Modal } from '../common/Modal';

export const InventoryView: React.FC = () => {
  const [activeSubTab, setActiveSubTab] = useState<'assets' | 'controls' | 'paths'>('assets');
  const [assets, setAssets] = useState<Asset[]>([]);
  const [controls, setControls] = useState<SecurityControl[]>([]);
  const [paths, setPaths] = useState<CommunicationPath[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  // Modal states
  const [isAssetModalOpen, setIsAssetModalOpen] = useState(false);
  const [isControlModalOpen, setIsControlModalOpen] = useState(false);
  const [isPathModalOpen, setIsPathModalOpen] = useState(false);

  // Form states
  const [newAsset, setNewAsset] = useState({ asset_id: '', name: '', asset_type: 'service', ip_address: '' });
  const [newControl, setNewControl] = useState({ control_id: '', name: '', control_type: 'waf', status: 'active' });
  const [newPath, setNewPath] = useState({ path_id: '', source_id: '', destination_id: '', protocol: 'HTTPS' });

  const loadInventory = async () => {
    setIsLoading(true);
    setError(null);
    try {
      const [aData, cData, pData] = await Promise.all([
        api.listAssets(),
        api.listControls(),
        api.listPaths().catch(() => []),
      ]);
      setAssets(aData);
      setControls(cData);
      setPaths(pData);
    } catch (err: any) {
      setError(err.message || 'Failed to load inventory.');
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadInventory();
  }, []);

  const handleCreateAsset = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await api.createAsset(newAsset);
      setSuccessMsg(`Asset '${newAsset.name}' created successfully.`);
      setIsAssetModalOpen(false);
      setNewAsset({ asset_id: '', name: '', asset_type: 'service', ip_address: '' });
      await loadInventory();
    } catch (err: any) {
      setError(err.message || 'Failed to create asset.');
    }
  };

  const handleDeleteAsset = async (assetId: string) => {
    if (!confirm(`Delete asset '${assetId}'?`)) return;
    try {
      await api.deleteAsset(assetId);
      setSuccessMsg(`Asset '${assetId}' removed.`);
      await loadInventory();
    } catch (err: any) {
      setError(err.message || 'Failed to delete asset.');
    }
  };

  const handleCreateControl = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await api.createControl(newControl);
      setSuccessMsg(`Security Control '${newControl.name}' created.`);
      setIsControlModalOpen(false);
      setNewControl({ control_id: '', name: '', control_type: 'waf', status: 'active' });
      await loadInventory();
    } catch (err: any) {
      setError(err.message || 'Failed to create security control.');
    }
  };

  const handleDeleteControl = async (controlId: string) => {
    if (!confirm(`Delete control '${controlId}'?`)) return;
    try {
      await api.deleteControl(controlId);
      setSuccessMsg(`Control '${controlId}' removed.`);
      await loadInventory();
    } catch (err: any) {
      setError(err.message || 'Failed to delete control.');
    }
  };

  const handleCreatePath = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await api.createPath(newPath);
      setSuccessMsg(`Communication path '${newPath.path_id}' created.`);
      setIsPathModalOpen(false);
      setNewPath({ path_id: '', source_id: '', destination_id: '', protocol: 'HTTPS' });
      await loadInventory();
    } catch (err: any) {
      setError(err.message || 'Failed to create communication path.');
    }
  };

  const handleDeletePath = async (pathId: string) => {
    if (!confirm(`Delete communication path '${pathId}'?`)) return;
    try {
      await api.deletePath(pathId);
      setSuccessMsg(`Path '${pathId}' removed.`);
      await loadInventory();
    } catch (err: any) {
      setError(err.message || 'Failed to delete communication path.');
    }
  };

  if (isLoading) {
    return <LoadingSpinner size="lg" label="Loading infrastructure inventory..." />;
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-slate-800">
        <div>
          <h1 className="text-xl font-bold font-mono text-slate-100 flex items-center gap-2">
            <Boxes className="w-5 h-5 text-cyan-400" />
            Infrastructure Inventory & Topology
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Registered nodes, security mechanisms, and active communication paths.
          </p>
        </div>

        <div className="flex items-center gap-2">
          {activeSubTab === 'assets' && (
            <button
              onClick={() => setIsAssetModalOpen(true)}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-mono font-medium shadow-sm transition-colors"
            >
              <Plus className="w-3.5 h-3.5" />
              Add Asset
            </button>
          )}

          {activeSubTab === 'controls' && (
            <button
              onClick={() => setIsControlModalOpen(true)}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-mono font-medium shadow-sm transition-colors"
            >
              <Plus className="w-3.5 h-3.5" />
              Add Control
            </button>
          )}

          {activeSubTab === 'paths' && (
            <button
              onClick={() => setIsPathModalOpen(true)}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-mono font-medium shadow-sm transition-colors"
            >
              <Plus className="w-3.5 h-3.5" />
              Add Path
            </button>
          )}
        </div>
      </div>

      {/* Notifications */}
      {successMsg && (
        <div className="p-3.5 rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 text-xs font-mono flex items-center gap-2.5">
          <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
          <span>{successMsg}</span>
        </div>
      )}

      {error && (
        <div className="p-3.5 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs font-mono flex items-center gap-2.5">
          <AlertCircle className="w-4 h-4 text-rose-400 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Sub-tab Switchers */}
      <div className="flex border-b border-slate-800 gap-2">
        <button
          onClick={() => setActiveSubTab('assets')}
          className={`flex items-center gap-2 px-4 py-2 border-b-2 text-xs font-mono font-semibold transition-colors ${
            activeSubTab === 'assets'
              ? 'border-cyan-400 text-cyan-400'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <Server className="w-3.5 h-3.5" />
          Assets ({assets.length})
        </button>

        <button
          onClick={() => setActiveSubTab('controls')}
          className={`flex items-center gap-2 px-4 py-2 border-b-2 text-xs font-mono font-semibold transition-colors ${
            activeSubTab === 'controls'
              ? 'border-cyan-400 text-cyan-400'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <Shield className="w-3.5 h-3.5" />
          Controls ({controls.length})
        </button>

        <button
          onClick={() => setActiveSubTab('paths')}
          className={`flex items-center gap-2 px-4 py-2 border-b-2 text-xs font-mono font-semibold transition-colors ${
            activeSubTab === 'paths'
              ? 'border-cyan-400 text-cyan-400'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <Network className="w-3.5 h-3.5" />
          Communication Paths ({paths.length})
        </button>
      </div>

      {/* Table: Assets */}
      {activeSubTab === 'assets' && (
        <div className="rounded-xl border border-slate-800 bg-slate-900/60 overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-slate-950/80 border-b border-slate-800 text-slate-400">
                <tr>
                  <th className="px-6 py-3 font-semibold">Asset ID</th>
                  <th className="px-6 py-3 font-semibold">Name</th>
                  <th className="px-6 py-3 font-semibold">Type</th>
                  <th className="px-6 py-3 font-semibold">IP Address</th>
                  <th className="px-6 py-3 font-semibold">Protecting Controls</th>
                  <th className="px-6 py-3 font-semibold text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {assets.map((asset) => (
                  <tr key={asset.asset_id} className="hover:bg-slate-800/30 transition-colors">
                    <td className="px-6 py-4 text-cyan-400 font-semibold">{asset.asset_id}</td>
                    <td className="px-6 py-4 text-slate-200 font-sans">{asset.name}</td>
                    <td className="px-6 py-4 uppercase text-slate-300">{asset.asset_type}</td>
                    <td className="px-6 py-4 text-slate-400">{asset.ip_address || '—'}</td>
                    <td className="px-6 py-4 text-slate-400 font-sans">
                      {asset.protecting_controls?.join(', ') || 'None'}
                    </td>
                    <td className="px-6 py-4 text-right">
                      <button
                        onClick={() => handleDeleteAsset(asset.asset_id)}
                        className="p-1.5 rounded-lg text-slate-500 hover:text-rose-400 hover:bg-slate-800 transition-colors"
                        title="Delete Asset"
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Table: Controls */}
      {activeSubTab === 'controls' && (
        <div className="rounded-xl border border-slate-800 bg-slate-900/60 overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-slate-950/80 border-b border-slate-800 text-slate-400">
                <tr>
                  <th className="px-6 py-3 font-semibold">Control ID</th>
                  <th className="px-6 py-3 font-semibold">Name</th>
                  <th className="px-6 py-3 font-semibold">Type</th>
                  <th className="px-6 py-3 font-semibold">Status</th>
                  <th className="px-6 py-3 font-semibold">Protected Targets</th>
                  <th className="px-6 py-3 font-semibold text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {controls.map((ctrl) => (
                  <tr key={ctrl.control_id} className="hover:bg-slate-800/30 transition-colors">
                    <td className="px-6 py-4 text-cyan-400 font-semibold">{ctrl.control_id}</td>
                    <td className="px-6 py-4 text-slate-200 font-sans">{ctrl.name}</td>
                    <td className="px-6 py-4 uppercase text-slate-300">{ctrl.control_type}</td>
                    <td className="px-6 py-4">
                      <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 uppercase">
                        {ctrl.status}
                      </span>
                    </td>
                    <td className="px-6 py-4 text-slate-400 font-sans">
                      {ctrl.protects?.join(', ') || 'None'}
                    </td>
                    <td className="px-6 py-4 text-right">
                      <button
                        onClick={() => handleDeleteControl(ctrl.control_id)}
                        className="p-1.5 rounded-lg text-slate-500 hover:text-rose-400 hover:bg-slate-800 transition-colors"
                        title="Delete Control"
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Table: Paths */}
      {activeSubTab === 'paths' && (
        <div className="rounded-xl border border-slate-800 bg-slate-900/60 overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-slate-950/80 border-b border-slate-800 text-slate-400">
                <tr>
                  <th className="px-6 py-3 font-semibold">Path ID</th>
                  <th className="px-6 py-3 font-semibold">Source Asset</th>
                  <th className="px-6 py-3 font-semibold">Destination Asset</th>
                  <th className="px-6 py-3 font-semibold">Protocol</th>
                  <th className="px-6 py-3 font-semibold">Traversed Controls</th>
                  <th className="px-6 py-3 font-semibold text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {paths.map((p) => (
                  <tr key={p.path_id} className="hover:bg-slate-800/30 transition-colors">
                    <td className="px-6 py-4 text-cyan-400 font-semibold">{p.path_id}</td>
                    <td className="px-6 py-4 text-slate-200">{p.source_id}</td>
                    <td className="px-6 py-4 text-slate-200">{p.destination_id}</td>
                    <td className="px-6 py-4 text-slate-300 uppercase">{p.protocol}</td>
                    <td className="px-6 py-4 text-slate-400">
                      {p.passes_through?.join(', ') || 'Direct / Uninspected'}
                    </td>
                    <td className="px-6 py-4 text-right">
                      <button
                        onClick={() => handleDeletePath(p.path_id)}
                        className="p-1.5 rounded-lg text-slate-500 hover:text-rose-400 hover:bg-slate-800 transition-colors"
                        title="Delete Path"
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Create Asset Modal */}
      <Modal isOpen={isAssetModalOpen} onClose={() => setIsAssetModalOpen(false)} title="Register New Asset">
        <form onSubmit={handleCreateAsset} className="space-y-4 font-mono text-xs">
          <div>
            <label className="block text-slate-300 mb-1">Asset ID</label>
            <input
              type="text"
              required
              value={newAsset.asset_id}
              onChange={(e) => setNewAsset({ ...newAsset, asset_id: e.target.value })}
              placeholder="e.g. asset-004"
              className="w-full p-2.5 rounded-lg bg-slate-950 border border-slate-800 text-slate-100"
            />
          </div>
          <div>
            <label className="block text-slate-300 mb-1">Asset Name</label>
            <input
              type="text"
              required
              value={newAsset.name}
              onChange={(e) => setNewAsset({ ...newAsset, name: e.target.value })}
              placeholder="e.g. Auth Gateway"
              className="w-full p-2.5 rounded-lg bg-slate-950 border border-slate-800 text-slate-100 font-sans"
            />
          </div>
          <div>
            <label className="block text-slate-300 mb-1">Asset Type</label>
            <select
              value={newAsset.asset_type}
              onChange={(e) => setNewAsset({ ...newAsset, asset_type: e.target.value })}
              className="w-full p-2.5 rounded-lg bg-slate-950 border border-slate-800 text-slate-100"
            >
              <option value="service">Microservice</option>
              <option value="database">Database</option>
              <option value="api">API Endpoint</option>
              <option value="compute">Compute Instance</option>
              <option value="storage">Object Storage</option>
            </select>
          </div>
          <div>
            <label className="block text-slate-300 mb-1">IP Address / Host</label>
            <input
              type="text"
              value={newAsset.ip_address}
              onChange={(e) => setNewAsset({ ...newAsset, ip_address: e.target.value })}
              placeholder="10.0.1.20"
              className="w-full p-2.5 rounded-lg bg-slate-950 border border-slate-800 text-slate-100"
            />
          </div>
          <div className="flex justify-end gap-2 pt-2">
            <button
              type="button"
              onClick={() => setIsAssetModalOpen(false)}
              className="px-3 py-1.5 text-slate-400 hover:text-slate-200"
            >
              Cancel
            </button>
            <button
              type="submit"
              className="px-4 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-medium"
            >
              Register Asset
            </button>
          </div>
        </form>
      </Modal>

      {/* Create Control Modal */}
      <Modal isOpen={isControlModalOpen} onClose={() => setIsControlModalOpen(false)} title="Register Security Control">
        <form onSubmit={handleCreateControl} className="space-y-4 font-mono text-xs">
          <div>
            <label className="block text-slate-300 mb-1">Control ID</label>
            <input
              type="text"
              required
              value={newControl.control_id}
              onChange={(e) => setNewControl({ ...newControl, control_id: e.target.value })}
              placeholder="ctrl-002"
              className="w-full p-2.5 rounded-lg bg-slate-950 border border-slate-800 text-slate-100"
            />
          </div>
          <div>
            <label className="block text-slate-300 mb-1">Control Name</label>
            <input
              type="text"
              required
              value={newControl.name}
              onChange={(e) => setNewControl({ ...newControl, name: e.target.value })}
              placeholder="e.g. AWS WAF Core RuleSet"
              className="w-full p-2.5 rounded-lg bg-slate-950 border border-slate-800 text-slate-100 font-sans"
            />
          </div>
          <div>
            <label className="block text-slate-300 mb-1">Control Type</label>
            <select
              value={newControl.control_type}
              onChange={(e) => setNewControl({ ...newControl, control_type: e.target.value })}
              className="w-full p-2.5 rounded-lg bg-slate-950 border border-slate-800 text-slate-100"
            >
              <option value="waf">Web Application Firewall (WAF)</option>
              <option value="firewall">Network Firewall / Security Group</option>
              <option value="iam">IAM Access Policy</option>
              <option value="encryption">TLS / Encryption Gateway</option>
            </select>
          </div>
          <div className="flex justify-end gap-2 pt-2">
            <button
              type="button"
              onClick={() => setIsControlModalOpen(false)}
              className="px-3 py-1.5 text-slate-400 hover:text-slate-200"
            >
              Cancel
            </button>
            <button
              type="submit"
              className="px-4 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-medium"
            >
              Register Control
            </button>
          </div>
        </form>
      </Modal>

      {/* Create Path Modal */}
      <Modal isOpen={isPathModalOpen} onClose={() => setIsPathModalOpen(false)} title="Register Communication Path">
        <form onSubmit={handleCreatePath} className="space-y-4 font-mono text-xs">
          <div>
            <label className="block text-slate-300 mb-1">Path ID</label>
            <input
              type="text"
              required
              value={newPath.path_id}
              onChange={(e) => setNewPath({ ...newPath, path_id: e.target.value })}
              placeholder="path-004"
              className="w-full p-2.5 rounded-lg bg-slate-950 border border-slate-800 text-slate-100"
            />
          </div>
          <div>
            <label className="block text-slate-300 mb-1">Source Asset</label>
            <select
              required
              value={newPath.source_id}
              onChange={(e) => setNewPath({ ...newPath, source_id: e.target.value })}
              className="w-full p-2.5 rounded-lg bg-slate-950 border border-slate-800 text-slate-100"
            >
              <option value="">Select Source Asset</option>
              {assets.map((a) => (
                <option key={a.asset_id} value={a.asset_id}>
                  {a.name} ({a.asset_id})
                </option>
              ))}
            </select>
          </div>
          <div>
            <label className="block text-slate-300 mb-1">Destination Asset</label>
            <select
              required
              value={newPath.destination_id}
              onChange={(e) => setNewPath({ ...newPath, destination_id: e.target.value })}
              className="w-full p-2.5 rounded-lg bg-slate-950 border border-slate-800 text-slate-100"
            >
              <option value="">Select Destination Asset</option>
              {assets.map((a) => (
                <option key={a.asset_id} value={a.asset_id}>
                  {a.name} ({a.asset_id})
                </option>
              ))}
            </select>
          </div>
          <div>
            <label className="block text-slate-300 mb-1">Protocol</label>
            <input
              type="text"
              value={newPath.protocol}
              onChange={(e) => setNewPath({ ...newPath, protocol: e.target.value })}
              placeholder="HTTPS"
              className="w-full p-2.5 rounded-lg bg-slate-950 border border-slate-800 text-slate-100"
            />
          </div>
          <div className="flex justify-end gap-2 pt-2">
            <button
              type="button"
              onClick={() => setIsPathModalOpen(false)}
              className="px-3 py-1.5 text-slate-400 hover:text-slate-200"
            >
              Cancel
            </button>
            <button
              type="submit"
              className="px-4 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-medium"
            >
              Register Path
            </button>
          </div>
        </form>
      </Modal>
    </div>
  );
};
