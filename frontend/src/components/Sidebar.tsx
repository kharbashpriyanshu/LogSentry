import { NavLink } from 'react-router-dom';
import {
  LayoutDashboard, AlertTriangle, ShieldAlert, BrainCircuit,
  Activity, Settings, FileText, Shield, ChevronRight, Sparkles,
} from 'lucide-react';
import { useQuery } from '@tanstack/react-query';
import { dashboardService } from '../services/dashboardService';

const NAV_ITEMS = [
  { to: '/dashboard',    label: 'Dashboard',      icon: LayoutDashboard, badgeKey: null           },
  { to: '/alerts',       label: 'Alerts',         icon: AlertTriangle,   badgeKey: 'open_alerts'   },
  { to: '/incidents',    label: 'Incidents',       icon: Shield,          badgeKey: 'open_incidents' },
  { to: '/threat-intel', label: 'Threat Intel',   icon: ShieldAlert,     badgeKey: null            },
  { to: '/ai-analysis',  label: 'AI Analyst',     icon: BrainCircuit,    badgeKey: null, isAi: true },
  { to: '/reports',      label: 'Reports',         icon: FileText,        badgeKey: null            },
  { to: '/health',       label: 'System Health',  icon: Activity,        badgeKey: null            },
  { to: '/settings',     label: 'Settings',        icon: Settings,        badgeKey: null            },
];

export default function Sidebar() {
  const { data: summary } = useQuery<any>({
    queryKey: ['dashboard_summary'],
    queryFn: () => dashboardService.getSummary(),
    refetchInterval: 10000,
    staleTime: 5000,
  });

  const badges: Record<string, number> = {
    open_alerts:    summary?.open_alerts    ?? 0,
    open_incidents: summary?.open_incidents ?? 0,
  };

  return (
    <aside className="w-64 flex flex-col border-r border-[var(--border-default)] bg-[var(--bg-sidebar)] transition-colors duration-200 select-none">
      {/* Brand Header */}
      <div className="h-16 flex items-center px-5 border-b border-[var(--border-subtle)] shrink-0 gap-3">
        <div className="w-9 h-9 rounded-xl bg-gradient-to-br from-amber-500/20 via-orange-500/10 to-blue-500/20 border border-[var(--border-default)] flex items-center justify-center shadow-xs">
          <img src="/branding/logo.svg" alt="LogSentry Logo" className="w-5 h-5 drop-shadow-xs" />
        </div>
        <div className="min-w-0">
          <div className="flex items-center gap-1.5">
            <span className="text-base font-extrabold text-[var(--text-primary)] tracking-tight">LogSentry</span>
            <span className="text-[10px] px-1.5 py-0.2 font-bold uppercase tracking-wider rounded-md bg-amber-500/15 text-amber-800 dark:text-amber-300 border border-amber-500/25">SOC</span>
          </div>
          <p className="text-[10px] text-[var(--text-muted)] font-medium tracking-wide truncate">AI Incident SIEM</p>
        </div>
      </div>

      {/* Nav section label */}
      <div className="px-4 pt-5 pb-2">
        <p className="text-[10px] font-bold text-[var(--text-muted)] uppercase tracking-wider">Navigation</p>
      </div>

      {/* Nav items */}
      <nav className="flex-1 px-3 space-y-1 overflow-y-auto">
        {NAV_ITEMS.map((item) => {
          const Icon = item.icon;
          const badgeCount = item.badgeKey ? badges[item.badgeKey] : 0;
          const showBadge = item.badgeKey !== null && badgeCount > 0;

          return (
            <NavLink
              key={item.to}
              to={item.to}
              className={({ isActive }) =>
                `group flex items-center justify-between px-3 py-2.5 rounded-xl text-sm font-medium transition-all duration-150 ${
                  isActive
                    ? 'bg-[var(--bg-sidebar-active)] text-[var(--text-primary)] font-semibold shadow-2xs border border-[var(--border-default)]'
                    : 'text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:bg-[var(--bg-sidebar-hover)]'
                }`
              }
            >
              {({ isActive }) => (
                <>
                  <span className="flex items-center gap-3">
                    <Icon className={`w-4 h-4 shrink-0 transition-colors ${
                      isActive ? 'text-amber-700 dark:text-blue-400' : 'text-[var(--text-muted)] group-hover:text-[var(--text-primary)]'
                    }`} />
                    <span>{item.label}</span>
                    {item.isAi && (
                      <Sparkles className="w-3 h-3 text-amber-500 animate-pulse ml-0.5" />
                    )}
                  </span>
                  {showBadge ? (
                    <span className="px-2 py-0.5 text-[10px] font-bold rounded-full min-w-[20px] text-center tabular-nums transition-all bg-rose-100 text-rose-800 border border-rose-200/80 dark:bg-rose-950/60 dark:text-rose-300 dark:border-rose-800/80">
                      {badgeCount > 99 ? '99+' : badgeCount}
                    </span>
                  ) : (
                    <ChevronRight className={`w-3.5 h-3.5 shrink-0 transition-all ${
                      isActive ? 'opacity-70 translate-x-0.5 text-[var(--text-muted)]' : 'opacity-0 -translate-x-1 group-hover:opacity-40'
                    }`} />
                  )}
                </>
              )}
            </NavLink>
          );
        })}
      </nav>

      {/* Footer / System Status */}
      <div className="p-4 border-t border-[var(--border-subtle)] shrink-0 bg-[var(--bg-sidebar)]">
        <div className="p-3 rounded-xl bg-[var(--bg-card)] border border-[var(--border-subtle)] shadow-xs">
          <div className="flex items-center gap-2 mb-1.5">
            <span className="relative flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
              <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
            </span>
            <span className="text-[11px] font-semibold text-[var(--text-primary)]">SIEM Core Online</span>
          </div>
          <div className="flex items-center justify-between text-[10px] text-[var(--text-muted)]">
            <span>v1.0.0 Enterprise</span>
            <a
              href="https://github.com/kharbashpriyanshu/LogSentry"
              target="_blank"
              rel="noopener noreferrer"
              className="text-[var(--text-muted)] hover:text-blue-600 dark:hover:text-blue-400 font-medium transition-colors"
            >
              GitHub &#8599;
            </a>
          </div>
        </div>
      </div>
    </aside>
  );
}
