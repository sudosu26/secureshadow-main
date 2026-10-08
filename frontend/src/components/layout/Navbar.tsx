import React, { useState } from 'react';
import {
  Shield,
  LayoutDashboard,
  Camera,
  GitCompare,
  TrendingDown,
  Wrench,
  Boxes,
  ScrollText,
  LogOut,
  UserCheck,
  KeyRound,
} from 'lucide-react';
import { useAuth } from '../../context/AuthContext';
import { ChangePasswordModal } from '../auth/ChangePasswordModal';

export type NavTab =
  | 'dashboard'
  | 'baseline'
  | 'drift'
  | 'decay'
  | 'repairs'
  | 'inventory'
  | 'audit';

interface NavbarProps {
  activeTab: NavTab;
  onSelectTab: (tab: NavTab) => void;
}

export const Navbar: React.FC<NavbarProps> = ({ activeTab, onSelectTab }) => {
  const { user, logout } = useAuth();
  const [isPasswordModalOpen, setIsPasswordModalOpen] = useState(false);

  const navItems: { id: NavTab; label: string; icon: React.ElementType }[] = [
    { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
    { id: 'baseline', label: 'Baseline', icon: Camera },
    { id: 'drift', label: 'Drift Detection', icon: GitCompare },
    { id: 'decay', label: 'Decay Evidence', icon: TrendingDown },
    { id: 'repairs', label: 'Repairs & Actions', icon: Wrench },
    { id: 'inventory', label: 'Inventory', icon: Boxes },
    { id: 'audit', label: 'Audit Log', icon: ScrollText },
  ];

  return (
    <header className="sticky top-0 z-40 w-full border-b border-slate-800/90 bg-[#090d16]/95 shadow-[0_8px_32px_-24px_rgba(0,0,0,0.9)] backdrop-blur-xl">
      <div className="mx-auto max-w-screen-2xl px-4 sm:px-6 lg:px-8">
        <div className="flex min-h-[4.25rem] items-center justify-between gap-3 sm:gap-6">
          <a href="/dashboard" onClick={(event) => { event.preventDefault(); onSelectTab('dashboard'); }} className="flex min-w-0 items-center gap-3 rounded-lg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-300" aria-label="SECURESHADOW dashboard">
            <span className="flex size-10 shrink-0 items-center justify-center rounded-xl border border-cyan-400/20 bg-cyan-400/[0.08] text-cyan-200 shadow-inner shadow-cyan-300/5">
              <Shield className="size-5" aria-hidden="true" />
            </span>
            <span className="min-w-0">
              <span className="flex items-center gap-1 font-semibold tracking-[0.11em] text-slate-100">
                <span className="truncate text-sm sm:text-base">SECURE<span className="text-cyan-300">SHADOW</span></span>
              </span>
              <span className="hidden text-[10px] font-medium uppercase tracking-[0.15em] text-slate-500 sm:block">Control decay engine</span>
            </span>
          </a>

          <div className="flex shrink-0 items-center gap-1.5 sm:gap-2">
            <div className="hidden items-center gap-2 rounded-full border border-slate-800 bg-slate-900/70 px-3 py-1.5 sm:flex">
              <span className="size-1.5 rounded-full bg-emerald-400" aria-hidden="true" />
              <UserCheck className="size-3.5 text-slate-500" aria-hidden="true" />
              <span className="max-w-28 truncate text-xs font-medium text-slate-300">{user?.username || 'admin'}</span>
            </div>
            <button
              type="button"
              onClick={() => setIsPasswordModalOpen(true)}
              title="Rotate Admin Password"
              aria-label="Change password"
              className="flex size-9 items-center justify-center rounded-lg border border-transparent text-slate-400 transition hover:border-slate-700 hover:bg-slate-800/80 hover:text-cyan-200 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-300"
            >
              <KeyRound className="size-4" aria-hidden="true" />
            </button>
            <button
              type="button"
              onClick={logout}
              title="Sign Out"
              aria-label="Sign out"
              className="flex size-9 items-center justify-center rounded-lg border border-transparent text-slate-400 transition hover:border-rose-400/20 hover:bg-rose-400/10 hover:text-rose-300 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-rose-300"
            >
              <LogOut className="size-4" aria-hidden="true" />
            </button>
          </div>
        </div>

        <nav aria-label="Primary" className="-mx-4 overflow-x-auto border-t border-slate-800/70 px-4 scrollbar-hide sm:-mx-6 sm:px-6 lg:-mx-8 lg:px-8">
          <div className="flex min-w-max items-center gap-1 py-2">
            {navItems.map((item) => {
              const Icon = item.icon;
              const isActive = activeTab === item.id;
              return (
                <button
                  key={item.id}
                  type="button"
                  onClick={() => onSelectTab(item.id)}
                  aria-current={isActive ? 'page' : undefined}
                  className={`inline-flex min-h-9 items-center gap-2 rounded-lg border px-3 text-xs font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-300 ${
                    isActive
                      ? 'border-cyan-300/20 bg-cyan-300/[0.09] text-cyan-200'
                      : 'border-transparent text-slate-400 hover:border-slate-700/70 hover:bg-slate-800/60 hover:text-slate-100'
                  }`}
                >
                  <Icon className="size-4 shrink-0" aria-hidden="true" />
                  <span>{item.label}</span>
                </button>
              );
            })}
          </div>
        </nav>
      </div>

      <ChangePasswordModal
        isOpen={isPasswordModalOpen}
        onClose={() => setIsPasswordModalOpen(false)}
      />
    </header>
  );
};
