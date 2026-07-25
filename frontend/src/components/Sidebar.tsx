import { NavLink } from 'react-router-dom';
import {
  LayoutDashboard, AlertTriangle, ShieldAlert, BrainCircuit,
  Activity, Settings, FileText, Shield, ChevronRight,
} from 'lucide-react';

const navItems = [
  { to: '/dashboard',   label: 'Dashboard',     icon: LayoutDashboard, badge: null },
  { to: '/alerts',      label: 'Alerts',        icon: AlertTriangle,   badge: '12' },
  { to: '/incidents',   label: 'Incidents',     icon: Shield,          badge: null },
  { to: '/threat-intel',label: 'Threat Intel',  icon: ShieldAlert,     badge: null },
  { to: '/ai-analysis', label: 'AI Analysis',   icon: BrainCircuit,    badge: null },
  { to: '/reports',     label: 'Reports',       icon: FileText,        badge: null },
  { to: '/health',      label: 'System Health', icon: Activity,        badge: null },
  { to: '/settings',    label: 'Settings',      icon: Settings,        badge: null },
];

export default function Sidebar() {
  return (
    <aside className="w-60 flex flex-col border-r border-slate-800 bg-[#0d1424]" style={{ background: 'linear-gradient(180deg, #0d1424 0%, #0a0f1e 100%)' }}>
      {/* Logo */}
      <div className="h-16 flex items-center px-5 border-b border-slate-800 shrink-0">
        <div className="p-1.5 bg-blue-600/20 rounded-lg border border-blue-500/20 mr-3">
          <Shield className="w-5 h-5 text-blue-400" />
        </div>
        <div>
          <span className="text-base font-bold text-slate-100 tracking-tight">LogSentry</span>
          <p className="text-[9px] text-slate-500 font-semibold uppercase tracking-widest leading-none mt-0.5">Enterprise SIEM</p>
        </div>
      </div>

      {/* Nav section label */}
      <div className="px-4 pt-5 pb-2">
        <p className="text-[9px] font-bold text-slate-600 uppercase tracking-widest">Navigation</p>
      </div>

      {/* Nav items */}
      <nav className="flex-1 px-2 space-y-0.5 overflow-y-auto">
        {navItems.map((item) => {
          const Icon = item.icon;
          return (
            <NavLink
              key={item.to}
              to={item.to}
              className={({ isActive }) =>
                `group flex items-center justify-between px-3 py-2.5 rounded-lg text-sm font-medium transition-all duration-150 ${
                  isActive
                    ? 'bg-blue-600/15 text-blue-400 border border-blue-500/20'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
                }`
              }
            >
              {({ isActive }) => (
                <>
                  <span className="flex items-center gap-3">
                    <Icon className={`w-4 h-4 shrink-0 ${isActive ? 'text-blue-400' : 'text-slate-500 group-hover:text-slate-300'}`} />
                    {item.label}
                  </span>
                  {item.badge ? (
                    <span className="px-1.5 py-0.5 text-[10px] font-bold bg-red-500/20 text-red-400 border border-red-500/30 rounded-full">
                      {item.badge}
                    </span>
                  ) : (
                    <ChevronRight className={`w-3 h-3 shrink-0 transition-opacity ${isActive ? 'opacity-60' : 'opacity-0 group-hover:opacity-30'}`} />
                  )}
                </>
              )}
            </NavLink>
          );
        })}
      </nav>

      {/* Footer */}
      <div className="px-4 py-4 border-t border-slate-800 shrink-0">
        <div className="flex items-center gap-2.5 mb-3">
          <span className="w-1.5 h-1.5 rounded-full bg-green-500 animate-pulse" />
          <span className="text-[11px] text-slate-400">All systems operational</span>
        </div>
        <p className="text-[10px] text-slate-600">LogSentry v1.1.0 • Enterprise</p>
      </div>
    </aside>
  );
}
