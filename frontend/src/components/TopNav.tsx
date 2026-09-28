import { useState, useRef, useEffect, useMemo } from 'react';
import {
  Bell, Search, User, ChevronDown, Settings, Key, BookOpen, X,
  AlertOctagon, ShieldAlert, CheckCircle2, Cpu, Info, Sun, Moon,
  Command
} from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import { alertService } from '../services/alertService';
import { incidentService } from '../services/incidentService';
import { useQuery } from '@tanstack/react-query';
import { useTheme } from '../context/ThemeContext';
import {
  ProfileModal,
  IntegrationsModal,
  DocumentationModal,
  PreferencesModal,
  AboutModal
} from './UserModals';

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
  { id: '2', type: 'info',     title: 'AI Analysis Ready', message: 'SQL Injection triage assessment completed', time: '8m ago', read: false },
  { id: '3', type: 'warning',  title: 'Threat Feed Update', message: 'AbuseIPDB: 14 new malicious IPs flagged', time: '15m ago', read: false },
  { id: '4', type: 'success',  title: 'Report Generated', message: 'Executive security summary report exported', time: '1h ago', read: true },
  { id: '5', type: 'critical', title: 'Brute Force Surge', message: '47 failed logins from 91.108.4.33', time: '1h ago', read: true },
];

const notifIcon = {
  critical: <AlertOctagon className="w-4 h-4 text-red-600 dark:text-red-400" />,
  warning:  <ShieldAlert className="w-4 h-4 text-amber-600 dark:text-amber-400" />,
  success:  <CheckCircle2 className="w-4 h-4 text-emerald-600 dark:text-emerald-400" />,
  info:     <Cpu className="w-4 h-4 text-blue-600 dark:text-blue-400" />,
};

interface SearchResult {
  type: string;
  label: string;
  sub: string;
  href: string;
}

function buildSearchResults(q: string, alerts: any[], incidents: any[]): SearchResult[] {
  if (!q.trim()) return [];
  const lower = q.toLowerCase();
  const results: SearchResult[] = [];
  alerts.slice(0, 5).forEach(a => {
    if (a.alert_id?.toLowerCase().includes(lower) || a.attack_type?.toLowerCase().includes(lower) || a.source_ip?.includes(lower) || a.title?.toLowerCase().includes(lower) || (a.mitre_technique || '').toLowerCase().includes(lower)) {
      results.push({ type: 'Alert', label: a.alert_id, sub: `${a.attack_type} · ${a.severity}`, href: '/alerts' });
    }
  });
  incidents.slice(0, 5).forEach(i => {
    if (i.id?.toLowerCase().includes(lower) || i.title?.toLowerCase().includes(lower) || (i.category || '').toLowerCase().includes(lower)) {
      results.push({ type: 'Incident', label: i.id, sub: i.title, href: '/incidents' });
    }
  });
  if ('dashboard'.includes(lower)) results.push({ type: 'Page', label: 'Dashboard', sub: 'SOC Overview', href: '/dashboard' });
  if ('threat'.includes(lower) || 'intel'.includes(lower)) results.push({ type: 'Page', label: 'Threat Intelligence', sub: 'IP Reputation & IOCs', href: '/threat-intel' });
  if ('ai'.includes(lower) || 'analyst'.includes(lower)) results.push({ type: 'Page', label: 'AI SOC Analyst', sub: 'Automated Threat Triage', href: '/ai-analysis' });
  if ('report'.includes(lower)) results.push({ type: 'Page', label: 'Reports', sub: 'Generate Incident Reports', href: '/reports' });
  return results.slice(0, 8);
}

export default function TopNav() {
  const navigate = useNavigate();
  const { theme, toggleTheme } = useTheme();
  const [searchValue, setSearchValue] = useState('');
  const [showSearch, setShowSearch] = useState(false);
  const [showNotif, setShowNotif] = useState(false);
  const [showUser, setShowUser] = useState(false);
  const [activeModal, setActiveModal] = useState<'profile' | 'integrations' | 'docs' | 'prefs' | 'about' | null>(null);
  const [notifications, setNotifications] = useState(NOTIFICATIONS);
  const searchRef = useRef<HTMLDivElement>(null);
  const { data: alerts } = useQuery({ queryKey: ['alerts'], queryFn: alertService.getAlerts });
  const { data: incidents } = useQuery({ queryKey: ['incidents'], queryFn: incidentService.getIncidents });

  const unread = notifications.filter(n => !n.read).length;
  const searchResults = useMemo(() => buildSearchResults(searchValue, alerts || [], incidents || []), [searchValue, alerts, incidents]);

  // Keyboard shortcut Ctrl+K / Cmd+K to focus search
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault();
        searchRef.current?.querySelector('input')?.focus();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, []);

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
    <header className="h-16 border-b border-[var(--border-default)] bg-[var(--bg-nav)] backdrop-blur-md flex items-center justify-between px-6 shrink-0 z-30 transition-colors duration-200">
      {/* Global Command / Search */}
      <div ref={searchRef} className="relative w-80 lg:w-96">
        <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-[var(--text-muted)] pointer-events-none" />
        <input
          type="text"
          value={searchValue}
          onChange={e => setSearchValue(e.target.value)}
          onFocus={() => setShowSearch(true)}
          placeholder="Search telemetry, IPs, IOCs, rules..."
          aria-label="Global search"
          className="w-full bg-[var(--bg-card)] border border-[var(--border-default)] rounded-xl py-2 pl-10 pr-16 text-sm text-[var(--text-primary)] placeholder-[var(--text-faint)] focus:outline-none focus:border-amber-600/70 dark:focus:border-blue-500 focus:ring-2 focus:ring-amber-500/15 dark:focus:ring-blue-500/20 shadow-xs transition-all"
        />
        <div className="absolute right-2.5 top-1/2 -translate-y-1/2 flex items-center gap-1">
          {searchValue ? (
            <button
              onClick={() => { setSearchValue(''); setShowSearch(false); }}
              className="text-[var(--text-muted)] hover:text-[var(--text-primary)] p-0.5 rounded"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          ) : (
            <kbd className="hidden sm:inline-flex items-center gap-0.5 px-1.5 py-0.5 text-[10px] font-mono font-medium text-[var(--text-muted)] bg-[var(--bg-card-subtle)] border border-[var(--border-subtle)] rounded shadow-2xs">
              <Command className="w-2.5 h-2.5" />K
            </kbd>
          )}
        </div>

        {/* Quick Search Results Dropdown */}
        {showSearch && searchResults.length > 0 && (
          <div className="absolute top-full left-0 right-0 mt-2 bg-[var(--bg-card)] border border-[var(--border-default)] rounded-2xl shadow-xl z-50 overflow-hidden animate-fade-in divide-y divide-[var(--border-subtle)]">
            <div className="px-4 py-2 bg-[var(--bg-card-subtle)] text-[10px] text-[var(--text-muted)] uppercase font-bold tracking-wider">
              Quick Telemetry Matches
            </div>
            <div className="max-h-80 overflow-y-auto">
              {searchResults.map((r, i) => (
                <button
                  key={i}
                  onClick={() => { navigate(r.href); setShowSearch(false); setSearchValue(''); }}
                  className="w-full flex items-center gap-3 px-4 py-3 hover:bg-[var(--bg-sidebar-hover)] text-left transition-colors"
                >
                  <span className="text-[10px] font-bold text-blue-700 dark:text-blue-400 bg-blue-50 dark:bg-blue-900/30 border border-blue-200 dark:border-blue-800 px-2 py-0.5 rounded-md w-14 text-center shrink-0">
                    {r.type}
                  </span>
                  <div className="min-w-0 flex-1">
                    <p className="text-sm font-semibold text-[var(--text-primary)] truncate">{r.label}</p>
                    <p className="text-xs text-[var(--text-muted)] truncate">{r.sub}</p>
                  </div>
                </button>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Right Controls Bar */}
      <div className="flex items-center gap-3">
        {/* System Time & Heartbeat */}
        <div className="hidden lg:flex items-center gap-2 px-3 py-1.5 bg-[var(--bg-card)] border border-[var(--border-default)] rounded-xl shadow-2xs">
          <span className="relative flex h-2 w-2">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
            <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
          </span>
          <span className="text-xs font-mono font-medium text-[var(--text-muted)]">
            UTC {new Date().toLocaleTimeString('en-US', { hour12: false, timeZone: 'UTC' })}
          </span>
        </div>

        {/* Theme Toggle Button */}
        <button
          onClick={toggleTheme}
          title={theme === 'light' ? 'Switch to Dark Mode' : 'Switch to Creamy Light Mode'}
          aria-label="Toggle theme"
          className="p-2 rounded-xl text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:bg-[var(--bg-sidebar-hover)] border border-[var(--border-default)] bg-[var(--bg-card)] shadow-2xs transition-all duration-200 active:scale-95"
        >
          {theme === 'light' ? (
            <Sun className="w-4.5 h-4.5 text-amber-600 transition-transform hover:rotate-45" />
          ) : (
            <Moon className="w-4.5 h-4.5 text-blue-400 transition-transform hover:-rotate-12" />
          )}
        </button>

        {/* Notifications Button & Dropdown */}
        <div className="relative">
          <button
            onClick={() => { setShowNotif(v => !v); setShowUser(false); }}
            aria-label="Notifications"
            className="relative p-2 rounded-xl text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:bg-[var(--bg-sidebar-hover)] border border-[var(--border-default)] bg-[var(--bg-card)] shadow-2xs transition-all active:scale-95"
          >
            <Bell className="w-4.5 h-4.5" />
            {unread > 0 && (
              <span className="absolute top-1.5 right-1.5 w-2 h-2 bg-red-500 rounded-full">
                <span className="absolute inset-0 rounded-full bg-red-500 animate-ping opacity-75" />
              </span>
            )}
          </button>

          {showNotif && (
            <div className="absolute right-0 top-full mt-2 w-96 bg-[var(--bg-card)] border border-[var(--border-default)] rounded-2xl shadow-xl z-50 overflow-hidden animate-fade-in">
              <div className="flex items-center justify-between px-5 py-3.5 border-b border-[var(--border-subtle)] bg-[var(--bg-card-subtle)]">
                <div className="flex items-center gap-2">
                  <span className="text-sm font-bold text-[var(--text-primary)]">Notifications</span>
                  {unread > 0 && (
                    <span className="text-[10px] font-bold bg-rose-100/90 text-rose-800 border border-rose-200/80 dark:bg-rose-950/60 dark:text-rose-300 dark:border-rose-800 px-2 py-0.5 rounded-full">
                      {unread} new
                    </span>
                  )}
                </div>
                <button
                  onClick={markAllRead}
                  className="text-xs text-blue-600 dark:text-blue-400 hover:underline font-semibold"
                >
                  Mark all read
                </button>
              </div>

              <div className="max-h-80 overflow-y-auto divide-y divide-[var(--border-subtle)]">
                {notifications.map(n => (
                  <div
                    key={n.id}
                    className={`flex items-start gap-3.5 px-5 py-3.5 hover:bg-[var(--bg-sidebar-hover)] transition-colors ${
                      !n.read ? 'bg-amber-500/5 dark:bg-blue-500/5' : ''
                    }`}
                  >
                    <div className="mt-0.5 shrink-0">{notifIcon[n.type]}</div>
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center justify-between gap-2">
                        <p className="text-xs font-bold text-[var(--text-primary)] truncate">{n.title}</p>
                        <span className="text-[10px] text-[var(--text-muted)] font-mono shrink-0">{n.time}</span>
                      </div>
                      <p className="text-xs text-[var(--text-secondary)] mt-0.5 leading-relaxed">{n.message}</p>
                    </div>
                    {!n.read && (
                      <div className="w-1.5 h-1.5 rounded-full bg-blue-600 dark:bg-blue-400 shrink-0 mt-1.5" />
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* User Profile Avatar & Menu */}
        <div className="relative">
          <button
            className="flex items-center gap-2.5 p-1.5 rounded-xl hover:bg-[var(--bg-sidebar-hover)] border border-[var(--border-default)] bg-[var(--bg-card)] shadow-2xs transition-all"
            onClick={() => { setShowUser(!showUser); setShowNotif(false); }}
          >
            <div className="w-7 h-7 rounded-lg bg-gradient-to-br from-amber-600 to-indigo-600 flex items-center justify-center text-white text-xs font-bold shrink-0 shadow-2xs">
              DU
            </div>
            <div className="hidden md:block text-left pr-1">
              <p className="text-xs font-bold text-[var(--text-primary)] leading-tight">Demo User</p>
              <p className="text-[10px] text-[var(--text-muted)] font-medium leading-tight">SOC Analyst L2</p>
            </div>
            <ChevronDown className="w-3.5 h-3.5 text-[var(--text-muted)] hidden md:block" />
          </button>

          {showUser && (
            <div
              className="absolute right-0 top-full mt-2 w-60 bg-[var(--bg-card)] border border-[var(--border-default)] rounded-2xl shadow-xl py-2 z-50 overflow-hidden animate-fade-in"
              onMouseLeave={() => setShowUser(false)}
            >
              <div className="px-4 py-3 border-b border-[var(--border-subtle)] bg-[var(--bg-card-subtle)]">
                <p className="text-sm font-bold text-[var(--text-primary)]">Demo User</p>
                <p className="text-xs text-[var(--text-muted)] truncate">analyst@logsentry.corp</p>
              </div>

              <div className="py-1.5">
                <button
                  onClick={() => { setActiveModal('profile'); setShowUser(false); }}
                  className="w-full flex items-center gap-3 px-4 py-2 text-sm text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:bg-[var(--bg-sidebar-hover)] transition-colors text-left"
                >
                  <User className="w-4 h-4 text-blue-600 dark:text-blue-400" />
                  <span>Analyst Profile</span>
                </button>
                <button
                  onClick={() => { setActiveModal('integrations'); setShowUser(false); }}
                  className="w-full flex items-center gap-3 px-4 py-2 text-sm text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:bg-[var(--bg-sidebar-hover)] transition-colors text-left"
                >
                  <Key className="w-4 h-4 text-purple-600 dark:text-purple-400" />
                  <span>API &amp; Integrations</span>
                </button>
                <button
                  onClick={() => { setActiveModal('docs'); setShowUser(false); }}
                  className="w-full flex items-center gap-3 px-4 py-2 text-sm text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:bg-[var(--bg-sidebar-hover)] transition-colors text-left"
                >
                  <BookOpen className="w-4 h-4 text-amber-600 dark:text-amber-400" />
                  <span>SOC Documentation</span>
                </button>
                <button
                  onClick={() => { setActiveModal('prefs'); setShowUser(false); }}
                  className="w-full flex items-center gap-3 px-4 py-2 text-sm text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:bg-[var(--bg-sidebar-hover)] transition-colors text-left"
                >
                  <Settings className="w-4 h-4 text-[var(--text-muted)]" />
                  <span>User Preferences</span>
                </button>
              </div>

              <div className="border-t border-[var(--border-subtle)] pt-1">
                <button
                  onClick={() => { setActiveModal('about'); setShowUser(false); }}
                  className="w-full flex items-center gap-3 px-4 py-2 text-sm text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:bg-[var(--bg-sidebar-hover)] transition-colors text-left"
                >
                  <Info className="w-4 h-4 text-emerald-600 dark:text-emerald-400" />
                  <span>About LogSentry SIEM</span>
                </button>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* User Modals */}
      <ProfileModal isOpen={activeModal === 'profile'} onClose={() => setActiveModal(null)} />
      <IntegrationsModal isOpen={activeModal === 'integrations'} onClose={() => setActiveModal(null)} />
      <DocumentationModal isOpen={activeModal === 'docs'} onClose={() => setActiveModal(null)} />
      <PreferencesModal isOpen={activeModal === 'prefs'} onClose={() => setActiveModal(null)} />
      <AboutModal isOpen={activeModal === 'about'} onClose={() => setActiveModal(null)} />
    </header>
  );
}
