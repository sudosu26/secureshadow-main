import React, { useState, useEffect } from 'react';
import { AuthProvider, useAuth } from './context/AuthContext';
import { Navbar, NavTab } from './components/layout/Navbar';
import { LoginView } from './components/auth/LoginView';
import { DashboardView } from './components/dashboard/DashboardView';
import { BaselineView } from './components/baseline/BaselineView';
import { DriftView } from './components/drift/DriftView';
import { DecayView } from './components/decay/DecayView';
import { RepairsView } from './components/repairs/RepairsView';
import { InventoryView } from './components/inventory/InventoryView';
import { AuditView } from './components/audit/AuditView';
import { LoadingSpinner } from './components/common/LoadingSpinner';
import { AlertCircle, Home } from 'lucide-react';

const VALID_TABS: NavTab[] = [
  'dashboard',
  'baseline',
  'drift',
  'decay',
  'repairs',
  'inventory',
  'audit',
];

const TAB_TITLES: Record<NavTab, string> = {
  dashboard: 'SECURESHADOW — Protection Dashboard',
  baseline: 'SECURESHADOW — Baseline Topology & Assumptions',
  drift: 'SECURESHADOW — Architectural Drift Detection',
  decay: 'SECURESHADOW — Protection Decay Evidence',
  repairs: 'SECURESHADOW — Remediation & Repair Actions',
  inventory: 'SECURESHADOW — Infrastructure Inventory',
  audit: 'SECURESHADOW — Engine Audit Trail',
};

const MainLayout: React.FC = () => {
  const { isAuthenticated, isLoading } = useAuth();
  const [activeTab, setActiveTab] = useState<NavTab>('dashboard');
  const [isNotFound, setIsNotFound] = useState(false);
  const [currentPath, setCurrentPath] = useState(window.location.pathname);

  // Sync state with URL pathname
  useEffect(() => {
    const handleLocationChange = () => {
      const rawPath = window.location.pathname.replace(/^\/+/, '').split('/')[0];
      setCurrentPath(window.location.pathname);

      if (!rawPath || rawPath === '') {
        setActiveTab('dashboard');
        setIsNotFound(false);
      } else if (VALID_TABS.includes(rawPath as NavTab)) {
        setActiveTab(rawPath as NavTab);
        setIsNotFound(false);
      } else {
        setIsNotFound(true);
      }
    };

    handleLocationChange();
    window.addEventListener('popstate', handleLocationChange);
    return () => window.removeEventListener('popstate', handleLocationChange);
  }, []);

  // Update dynamic document title per view
  useEffect(() => {
    if (!isAuthenticated) {
      document.title = 'SECURESHADOW — Operator Login';
    } else if (isNotFound) {
      document.title = 'SECURESHADOW — 404 Route Not Found';
    } else {
      document.title = TAB_TITLES[activeTab] || 'SECURESHADOW';
    }
  }, [activeTab, isAuthenticated, isNotFound]);

  const handleSelectTab = (tab: NavTab) => {
    setIsNotFound(false);
    setActiveTab(tab);
    window.history.pushState(null, '', `/${tab}`);
  };

  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-[#090d16]">
        <LoadingSpinner size="lg" label="Initializing secure session..." />
      </div>
    );
  }

  if (!isAuthenticated) {
    return <LoginView />;
  }

  return (
    <div className="min-h-screen bg-[#090d16] text-slate-100 flex flex-col font-sans">
      <Navbar activeTab={activeTab} onSelectTab={handleSelectTab} />
      <main className="flex-1 max-w-7xl w-full mx-auto p-4 sm:p-6 lg:p-8">
        {isNotFound ? (
          <div className="max-w-md mx-auto my-16 p-8 rounded-xl bg-slate-900/90 border border-slate-800 text-center space-y-4 shadow-xl">
            <div className="w-12 h-12 rounded-xl bg-rose-500/10 border border-rose-500/30 flex items-center justify-center text-rose-400 mx-auto">
              <AlertCircle className="w-6 h-6" />
            </div>
            <div>
              <span className="text-3xl font-mono font-bold text-rose-400">404</span>
              <h1 className="text-base font-mono font-semibold text-slate-100 mt-1">
                Route Not Found
              </h1>
              <p className="text-xs text-slate-400 mt-2 font-mono break-all">
                The requested URL <code className="text-cyan-300 font-semibold">{currentPath}</code> does not exist on this console.
              </p>
            </div>
            <div className="pt-2">
              <button
                onClick={() => handleSelectTab('dashboard')}
                className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-mono font-medium transition-colors"
              >
                <Home className="w-4 h-4" />
                Return to Dashboard
              </button>
            </div>
          </div>
        ) : (
          <>
            {activeTab === 'dashboard' && <DashboardView onNavigate={handleSelectTab} />}
            {activeTab === 'baseline' && <BaselineView />}
            {activeTab === 'drift' && <DriftView />}
            {activeTab === 'decay' && <DecayView />}
            {activeTab === 'repairs' && <RepairsView />}
            {activeTab === 'inventory' && <InventoryView />}
            {activeTab === 'audit' && <AuditView />}
          </>
        )}
      </main>
      <footer className="border-t border-slate-800/80 py-4 text-center text-xs font-mono text-slate-500">
        SECURESHADOW • Control Decay Detection & Automated Remediation System
      </footer>
    </div>
  );
};

export const App: React.FC = () => {
  return (
    <AuthProvider>
      <MainLayout />
    </AuthProvider>
  );
};

export default App;
