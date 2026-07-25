import { useState, useRef, useEffect, useMemo } from 'react';
import { Bell, Search, User, ChevronDown, Settings, LogOut, Key, BookOpen, X, AlertOctagon, ShieldAlert, CheckCircle2, Cpu } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import { alertService } from '../services/alertService';
import { useQuery } from '@tanstack/react-query';

interface Notification {
  id: string;
  type: 'critical' | 'info' | 'success' | 'warning';
  title: string;
  message: string;
  time: string;
  read: boolean;
}

const NOTIFICATIONS: Notification[] = [
  { id: '1', type: 'critical', title: 'CRITICAL Alert', message: 'RCE attempt detected on web-prod-01', time: '2m ago', read: false },
  { id: '2', type: 'info',     title: 'AI Analysis Complete', message: 'Log4Shell exploit analysis ready', time: '8m ago', read: false },
  { id: '3', type: 'warning',  title: 'Threat Feed Update', message: 'AbuseIPDB: 14 new IPs flagged', time: '15m ago', read: false },
  { id: '4', type: 'success',  title: 'Report Generated', message: 'Incident report ALT-0042 exported', time: '1h ago', read: true },
  { id: '5', type: 'critical', title: 'Brute Force Surge', message: '47 failed logins from 91.108.4.33', time: '1h ago', read: true },
];

const notifIcon = {
  critical: <AlertOctagon className="w-4 h-4 text-red-400" />,
  warning:  <ShieldAlert className="w-4 h-4 text-yellow-400" />,
  success:  <CheckCircle2 className="w-4 h-4 text-green-400" />,
  info:     <Cpu className="w-4 h-4 text-blue-400" />,
};

interface SearchResult {
  type: string;
  label: string;
  sub: string;
  href: string;
}

function buildSearchResults(q: string, alerts: any[]): SearchResult[] {
  if (!q.trim()) return [];
  const lower = q.toLowerCase();
  const results: SearchResult[] = [];
  alerts.slice(0, 5).forEach(a => {
    if (a.alert_id.toLowerCase().includes(lower) || a.attack_type.toLowerCase().includes(lower) || a.source_ip.includes(lower) || a.title.toLowerCase().includes(lower)) {
      results.push({ type: 'Alert', label: a.alert_id, sub: `${a.attack_type} · ${a.severity}`, href: '/alerts' });
    }
  });
  if ('dashboard'.includes(lower)) results.push({ type: 'Page', label: 'Dashboard', sub: 'SOC Overview', href: '/dashboard' });
  if ('threat'.includes(lower) || 'intel'.includes(lower)) results.push({ type: 'Page', label: 'Threat Intelligence', sub: 'IP Reputation & IOCs', href: '/threat-intel' });
  if ('report'.includes(lower)) results.push({ type: 'Page', label: 'Reports', sub: 'Generate Incident Reports', href: '/reports' });
  return results.slice(0, 6);
}

export default function TopNav() {
  const navigate = useNavigate();
  const [searchValue, setSearchValue] = useState('');
  const [showSearch, setShowSearch] = useState(false);
  const [showNotif, setShowNotif] = useState(false);
  const [showUser, setShowUser] = useState(false);
  const [notifications, setNotifications] = useState(NOTIFICATIONS);
  const searchRef = useRef<HTMLDivElement>(null);
  const { data: alerts } = useQuery({ queryKey: ['alerts'], queryFn: alertService.getAlerts });

  const unread = notifications.filter(n => !n.read).length;

  const searchResults = useMemo(() => buildSearchResults(searchValue, alerts || []), [searchValue, alerts]);

  // Close dropdowns on outside click
  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (!searchRef.current?.contains(e.target as Node)) {
        setShowSearch(false);
      }
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, []);

  const markAllRead = () => setNotifications(n => n.map(x => ({ ...x, read: true })));

  return (
    <header className="h-14 border-b border-slate-800 flex items-center justify-between px-5 shrink-0" style={{ background: '#0d1424' }}>
      {/* Global Search */}
      <div ref={searchRef} className="relative w-80">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-slate-500 pointer-events-none" />
        <input
          type="text"
          value={searchValue}
          onChange={e => setSearchValue(e.target.value)}
          onFocus={() => setShowSearch(true)}
          placeholder="Search alerts, IPs, rules, MITRE..."
          aria-label="Global search"
          className="w-full bg-slate-900/80 border border-slate-700/60 rounded-lg py-2 pl-9 pr-8 text-sm text-slate-200 placeholder-slate-600 focus:outline-none focus:border-blue-500/60 focus:bg-slate-900 transition-all"
        />
        {searchValue && (
          <button onClick={() => { setSearchValue(''); setShowSearch(false); }} className="absolute right-2.5 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300">
            <X className="w-3.5 h-3.5" />
          </button>
        )}
        {showSearch && searchResults.length > 0 && (
          <div className="absolute top-full left-0 right-0 mt-1 bg-[#111827] border border-slate-700 rounded-xl shadow-2xl z-50 overflow-hidden animate-fade-in">
            <div className="px-3 py-2 border-b border-slate-800 text-[10px] text-slate-500 uppercase font-bold tracking-widest">Results</div>
            {searchResults.map((r, i) => (
              <button key={i} onClick={() => { navigate(r.href); setShowSearch(false); setSearchValue(''); }}
                className="w-full flex items-center gap-3 px-3 py-2.5 hover:bg-slate-800/60 text-left transition-colors">
                <span className="text-[10px] font-bold text-blue-400 bg-blue-500/10 border border-blue-500/20 px-1.5 py-0.5 rounded w-12 text-center shrink-0">{r.type}</span>
                <div className="min-w-0">
                  <p className="text-sm font-medium text-slate-200 truncate">{r.label}</p>
                  <p className="text-[11px] text-slate-500 truncate">{r.sub}</p>
                </div>
              </button>
            ))}
          </div>
        )}
      </div>

      {/* Right controls */}
      <div className="flex items-center gap-2">
        {/* System time */}
        <div className="hidden lg:flex items-center gap-2 px-3 py-1.5 bg-slate-900/60 border border-slate-800 rounded-lg">
          <span className="w-1.5 h-1.5 rounded-full bg-green-500 animate-pulse" />
          <span className="text-[11px] font-mono text-slate-400">{new Date().toLocaleTimeString('en-US', { hour12: false })}</span>
        </div>

        {/* Notifications */}
        <div className="relative">
          <button
            onClick={() => { setShowNotif(v => !v); setShowUser(false); }}
            aria-label="Notifications"
            className="relative p-2 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-slate-800/60 transition-colors"
          >
            <Bell className="w-4.5 h-4.5" />
            {unread > 0 && (
              <span className="absolute top-1.5 right-1.5 w-2 h-2 bg-red-500 rounded-full">
                <span className="absolute inset-0 rounded-full bg-red-500 animate-ping opacity-75" />
              </span>
            )}
          </button>
          {showNotif && (
            <div className="absolute right-0 top-full mt-2 w-96 bg-[#111827] border border-slate-700 rounded-xl shadow-2xl z-50 overflow-hidden animate-fade-in">
              <div className="flex items-center justify-between px-4 py-3 border-b border-slate-800">
                <span className="text-sm font-semibold text-slate-200">Notifications</span>
                <div className="flex items-center gap-3">
                  {unread > 0 && <span className="text-[10px] font-bold bg-red-500/20 text-red-400 border border-red-500/30 px-2 py-0.5 rounded-full">{unread} new</span>}
                  <button onClick={markAllRead} className="text-[11px] text-blue-400 hover:text-blue-300 font-medium">Mark all read</button>
                </div>
              </div>
              <div className="max-h-72 overflow-y-auto divide-y divide-slate-800/60">
                {notifications.map(n => (
                  <div key={n.id} className={`flex items-start gap-3 px-4 py-3 hover:bg-slate-800/40 transition-colors ${!n.read ? 'bg-slate-800/20' : ''}`}>
                    <div className="mt-0.5 shrink-0">{notifIcon[n.type]}</div>
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center justify-between gap-2">
                        <p className="text-xs font-semibold text-slate-200 truncate">{n.title}</p>
                        <span className="text-[10px] text-slate-600 shrink-0">{n.time}</span>
                      </div>
                      <p className="text-[11px] text-slate-500 mt-0.5 leading-relaxed">{n.message}</p>
                    </div>
                    {!n.read && <div className="w-1.5 h-1.5 rounded-full bg-blue-500 shrink-0 mt-1.5" />}
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* User menu */}
        <div className="relative">
          <button
            onClick={() => { setShowUser(v => !v); setShowNotif(false); }}
            className="flex items-center gap-2 px-2 py-1.5 rounded-lg hover:bg-slate-800/60 transition-colors"
          >
            <div className="w-7 h-7 rounded-full bg-gradient-to-br from-blue-500 to-violet-600 flex items-center justify-center text-white text-xs font-bold shrink-0">AC</div>
            <div className="hidden md:block text-left">
              <p className="text-xs font-semibold text-slate-200 leading-tight">alice.chen</p>
              <p className="text-[10px] text-slate-500 leading-tight">SOC Analyst</p>
            </div>
            <ChevronDown className="w-3 h-3 text-slate-500 hidden md:block" />
          </button>
          {showUser && (
            <div className="absolute right-0 top-full mt-2 w-52 bg-[#111827] border border-slate-700 rounded-xl shadow-2xl z-50 overflow-hidden animate-fade-in">
              <div className="px-4 py-3 border-b border-slate-800">
                <p className="text-sm font-semibold text-slate-200">alice.chen</p>
                <p className="text-xs text-slate-500 mt-0.5">alice@logsentry.io</p>
              </div>
              {[
                { icon: <User className="w-4 h-4" />, label: 'Profile' },
                { icon: <Key className="w-4 h-4" />, label: 'API Keys' },
                { icon: <BookOpen className="w-4 h-4" />, label: 'Documentation' },
                { icon: <Settings className="w-4 h-4" />, label: 'Preferences' },
              ].map(item => (
                <button key={item.label} className="w-full flex items-center gap-3 px-4 py-2.5 text-sm text-slate-400 hover:text-slate-200 hover:bg-slate-800/50 transition-colors">
                  {item.icon}{item.label}
                </button>
              ))}
              <div className="border-t border-slate-800">
                <button className="w-full flex items-center gap-3 px-4 py-2.5 text-sm text-red-400 hover:text-red-300 hover:bg-red-500/5 transition-colors">
                  <LogOut className="w-4 h-4" /> Sign Out
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </header>
  );
}
