import { NavLink } from 'react-router-dom';
import { 
  LayoutDashboard, 
  AlertTriangle, 
  ShieldAlert, 
  BrainCircuit, 
  Activity, 
  Settings 
} from 'lucide-react';
import clsx from 'clsx';

const navItems = [
  { to: '/dashboard', label: 'Dashboard', icon: LayoutDashboard },
  { to: '/alerts', label: 'Alerts', icon: AlertTriangle },
  { to: '/threat-intel', label: 'Threat Intel', icon: ShieldAlert },
  { to: '/ai-analysis', label: 'AI Analysis', icon: BrainCircuit },
  { to: '/health', label: 'System Health', icon: Activity },
  { to: '/settings', label: 'Settings', icon: Settings },
];

export default function Sidebar() {
  return (
    <div className="w-64 bg-surface border-r border-slate-700 flex flex-col">
      <div className="h-16 flex items-center px-6 border-b border-slate-700">
        <ShieldAlert className="w-8 h-8 text-primary mr-3" />
        <span className="text-xl font-bold tracking-wider text-slate-100">LogSentry</span>
      </div>
      <nav className="flex-1 px-4 py-6 space-y-2">
        {navItems.map((item) => {
          const Icon = item.icon;
          return (
            <NavLink
              key={item.to}
              to={item.to}
              className={({ isActive }) => clsx(
                'flex items-center px-4 py-3 rounded-lg transition-colors',
                isActive 
                  ? 'bg-primary/10 text-primary font-medium' 
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-700/50'
              )}
            >
              <Icon className="w-5 h-5 mr-3" />
              {item.label}
            </NavLink>
          );
        })}
      </nav>
      <div className="p-4 border-t border-slate-700 text-xs text-slate-500 text-center">
        LogSentry SIEM v1.0.0
      </div>
    </div>
  );
}
