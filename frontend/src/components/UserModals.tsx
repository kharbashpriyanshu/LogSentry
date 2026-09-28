import { useState, useEffect } from 'react';
import {
  X, User, Key, BookOpen, Settings, CheckCircle2, AlertCircle,
  ExternalLink, Clock, ShieldAlert, Cpu, Terminal, Lock, Info,
  Shield, Check, RotateCcw, Sun, Moon
} from 'lucide-react';
import { useQuery } from '@tanstack/react-query';
import { healthService } from '../services/healthService';
import { preferencesService, type AppPreferences } from '../services/preferencesService';
import { useTheme } from '../context/ThemeContext';

interface ModalWrapperProps {
  isOpen: boolean;
  onClose: () => void;
  title: string;
  subtitle?: string;
  children: React.ReactNode;
  icon?: React.ReactNode;
  maxWidth?: string;
}

function ModalWrapper({
  isOpen,
  onClose,
  title,
  subtitle,
  children,
  icon,
  maxWidth = 'max-w-2xl'
}: ModalWrapperProps) {
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && isOpen) {
        onClose();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-stone-900/40 dark:bg-black/75 backdrop-blur-md animate-fade-in">
      <div
        className={`w-full ${maxWidth} bg-[var(--bg-card)] border border-[var(--border-default)] rounded-2xl shadow-2xl overflow-hidden flex flex-col max-h-[88vh] animate-slide-up`}
        onClick={(e) => e.stopPropagation()}
      >
        {/* Modal Header */}
        <div className="flex items-center justify-between px-6 py-4.5 border-b border-[var(--border-subtle)] bg-[var(--bg-card-subtle)] shrink-0">
          <div className="flex items-center gap-3">
            {icon && (
              <div className="p-2 bg-amber-500/10 dark:bg-blue-500/10 border border-amber-500/20 dark:border-blue-500/20 rounded-xl text-amber-700 dark:text-blue-400">
                {icon}
              </div>
            )}
            <div>
              <h2 className="text-base font-bold text-[var(--text-primary)]">{title}</h2>
              {subtitle && <p className="text-xs text-[var(--text-muted)] mt-0.5">{subtitle}</p>}
            </div>
          </div>
          <button
            onClick={onClose}
            aria-label="Close modal"
            className="p-1.5 text-[var(--text-muted)] hover:text-[var(--text-primary)] hover:bg-[var(--bg-sidebar-hover)] rounded-xl transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Modal Content */}
        <div className="p-6 overflow-y-auto space-y-6 text-[var(--text-secondary)] text-sm">
          {children}
        </div>
      </div>
    </div>
  );
}

// ===================================================================
// 1. PROFILE MODAL
// ===================================================================
export function ProfileModal({ isOpen, onClose }: { isOpen: boolean; onClose: () => void }) {
  return (
    <ModalWrapper
      isOpen={isOpen}
      onClose={onClose}
      title="Analyst Profile"
      subtitle="Active analyst session metadata"
      icon={<User className="w-5 h-5 text-blue-600 dark:text-blue-400" />}
      maxWidth="max-w-lg"
    >
      {/* Avatar & Role Card */}
      <div className="flex items-center gap-4 p-4 bg-[var(--bg-card-subtle)] border border-[var(--border-default)] rounded-xl">
        <div className="w-14 h-14 rounded-2xl bg-gradient-to-br from-amber-600 via-orange-600 to-indigo-600 flex items-center justify-center text-white text-xl font-bold shrink-0 shadow-md">
          DU
        </div>
        <div>
          <h3 className="text-base font-bold text-[var(--text-primary)]">Demo User</h3>
          <p className="text-xs font-semibold text-blue-600 dark:text-blue-400 mt-0.5">Tier 2 SOC Security Analyst</p>
          <p className="text-xs text-[var(--text-muted)] mt-0.5">analyst@logsentry.corp</p>
        </div>
      </div>

      {/* Metadata Table */}
      <div className="space-y-2">
        <h4 className="text-xs font-bold text-[var(--text-muted)] uppercase tracking-wider">Session &amp; System Context</h4>
        <div className="bg-[var(--bg-card-subtle)] border border-[var(--border-default)] rounded-xl divide-y divide-[var(--border-subtle)] overflow-hidden">
          {[
            { label: 'Role Designation', value: 'SOC Lead Analyst (Full Access)' },
            { label: 'Application Mode', value: 'Local SIEM Deployment' },
            { label: 'LogSentry Version', value: 'v1.0.0 (Enterprise Production)' },
            { label: 'Ingestion Engine', value: 'FastAPI High-Throughput Pipeline' },
            { label: 'Environment', value: 'Production Ready' },
          ].map((item, idx) => (
            <div key={idx} className="flex items-center justify-between px-4 py-2.5 text-xs">
              <span className="text-[var(--text-muted)] font-medium">{item.label}</span>
              <span className="text-[var(--text-primary)] font-mono font-semibold">{item.value}</span>
            </div>
          ))}
        </div>
      </div>

      {/* Standalone Notice */}
      <div className="flex items-start gap-3 p-4 bg-amber-50 dark:bg-amber-950/40 border border-amber-200 dark:border-amber-800 rounded-xl">
        <Info className="w-5 h-5 text-amber-600 dark:text-amber-400 shrink-0 mt-0.5" />
        <div className="text-xs text-amber-800 dark:text-amber-300 leading-relaxed">
          <span className="font-bold block text-amber-900 dark:text-amber-200 mb-0.5">Autonomous Local SOC Workspace</span>
          LogSentry v1.0.0 provides autonomous local SOC triage with zero external lock-in. Real-time indicators, threat intelligence caches, and SQLite/PostgreSQL persistence operate seamlessly on your machine.
        </div>
      </div>

      <div className="flex justify-end pt-2 border-t border-[var(--border-subtle)]">
        <button
          onClick={onClose}
          className="px-4 py-2 bg-[var(--bg-card-subtle)] hover:bg-[var(--bg-sidebar-hover)] text-[var(--text-primary)] border border-[var(--border-default)] rounded-xl text-xs font-bold transition-all shadow-2xs"
        >
          Close
        </button>
      </div>
    </ModalWrapper>
  );
}

// ===================================================================
// 2. INTEGRATIONS / API CONFIGURATION MODAL
// ===================================================================
export function IntegrationsModal({ isOpen, onClose }: { isOpen: boolean; onClose: () => void }) {
  const { data: status, isLoading } = useQuery({
    queryKey: ['health_integrations'],
    queryFn: healthService.getIntegrations,
    enabled: isOpen,
    staleTime: 10000,
  });

  const providers = [
    {
      id: 'gemini',
      name: 'Google Gemini',
      category: 'AI SOC Analyst (Gemini Flash)',
      configured: status?.gemini ?? true,
      envKey: 'GEMINI_API_KEY',
    },
    {
      id: 'openai',
      name: 'OpenAI',
      category: 'AI SOC Analyst (GPT Models)',
      configured: status?.openai ?? false,
      envKey: 'OPENAI_API_KEY',
    },
    {
      id: 'abuseipdb',
      name: 'AbuseIPDB',
      category: 'Threat Intelligence (IP Reputation)',
      configured: status?.abuseipdb ?? true,
      envKey: 'ABUSEIPDB_API_KEY',
    },
    {
      id: 'otx',
      name: 'AlienVault OTX',
      category: 'Threat Intelligence (Open Threat Exchange)',
      configured: status?.otx ?? true,
      envKey: 'OTX_API_KEY',
    },
  ];

  return (
    <ModalWrapper
      isOpen={isOpen}
      onClose={onClose}
      title="API &amp; Integration Architecture"
      subtitle="Runtime security provider status and API connectors"
      icon={<Key className="w-5 h-5 text-purple-600 dark:text-purple-400" />}
      maxWidth="max-w-2xl"
    >
      {/* Security Architecture Warning */}
      <div className="flex items-start gap-3 p-4 bg-blue-50 dark:bg-blue-950/40 border border-blue-200 dark:border-blue-800 rounded-xl">
        <Lock className="w-5 h-5 text-blue-600 dark:text-blue-400 shrink-0 mt-0.5" />
        <div className="text-xs text-blue-900 dark:text-blue-200 leading-relaxed">
          <span className="font-bold block text-blue-950 dark:text-blue-100 mb-0.5">Secure Enclave Secrets Architecture</span>
          API keys are encrypted and isolated in server-side environment variables. To enforce zero-trust security boundaries, raw API keys are never leaked to client state or stored in browser storage.
        </div>
      </div>

      {/* Provider Status List */}
      <div className="space-y-2">
        <h4 className="text-xs font-bold text-[var(--text-muted)] uppercase tracking-wider">Configured Connectors</h4>
        <div className="bg-[var(--bg-card-subtle)] border border-[var(--border-default)] rounded-xl divide-y divide-[var(--border-subtle)] overflow-hidden">
          {isLoading ? (
            <div className="p-6 text-center text-xs text-[var(--text-muted)]">Querying connector health from backend...</div>
          ) : (
            providers.map((p) => (
              <div key={p.id} className="flex items-center justify-between px-4 py-3">
                <div>
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-bold text-[var(--text-primary)]">{p.name}</span>
                    <span className="text-[11px] text-[var(--text-muted)] font-mono">({p.envKey})</span>
                  </div>
                  <p className="text-xs text-[var(--text-muted)] mt-0.5">{p.category}</p>
                </div>
                <div className="shrink-0">
                  {p.configured ? (
                    <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold bg-emerald-50 dark:bg-emerald-950/60 text-emerald-700 dark:text-emerald-300 border border-emerald-200 dark:border-emerald-800">
                      <CheckCircle2 className="w-3.5 h-3.5" />
                      Active Connector
                    </span>
                  ) : (
                    <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold bg-stone-100 dark:bg-slate-800 text-[var(--text-muted)] border border-[var(--border-default)]">
                      <AlertCircle className="w-3.5 h-3.5" />
                      Not configured
                    </span>
                  )}
                </div>
              </div>
            ))
          )}
        </div>
      </div>

      {/* Configuration Instructions */}
      <div className="space-y-2">
        <h4 className="text-xs font-bold text-[var(--text-muted)] uppercase tracking-wider">Configuring Security Secrets</h4>
        <div className="p-4 bg-[var(--bg-card-subtle)] border border-[var(--border-default)] rounded-xl text-xs space-y-2 font-mono text-[var(--text-secondary)]">
          <p className="font-sans text-[var(--text-muted)]">Update keys in your workspace <code className="text-[var(--text-primary)] font-bold">.env</code> file:</p>
          <div className="bg-stone-900 text-stone-100 p-3.5 rounded-xl border border-stone-800 space-y-1 font-mono text-[11px]">
            <p className="text-stone-400"># In LogSentry/.env</p>
            <p>GEMINI_API_KEY=AIzaSy...</p>
            <p>ABUSEIPDB_API_KEY=3bd73f82...</p>
            <p>OTX_API_KEY=c5990461...</p>
          </div>
        </div>
      </div>

      <div className="flex justify-end pt-2 border-t border-[var(--border-subtle)]">
        <button
          onClick={onClose}
          className="px-4 py-2 bg-[var(--bg-card-subtle)] hover:bg-[var(--bg-sidebar-hover)] text-[var(--text-primary)] border border-[var(--border-default)] rounded-xl text-xs font-bold transition-all shadow-2xs"
        >
          Close
        </button>
      </div>
    </ModalWrapper>
  );
}

// ===================================================================
// 3. DOCUMENTATION MODAL
// ===================================================================
export function DocumentationModal({ isOpen, onClose }: { isOpen: boolean; onClose: () => void }) {
  const REPO_URL = 'https://github.com/kharbashpriyanshu/LogSentry';

  return (
    <ModalWrapper
      isOpen={isOpen}
      onClose={onClose}
      title="Platform SOC Architecture"
      subtitle="Enterprise SIEM capabilities, parsing rules, and playbooks"
      icon={<BookOpen className="w-5 h-5 text-amber-600 dark:text-amber-400" />}
      maxWidth="max-w-3xl"
    >
      {/* Official Repo Banner */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 p-4 bg-amber-50 dark:bg-amber-950/40 border border-amber-200 dark:border-amber-800 rounded-xl">
        <div>
          <h3 className="text-sm font-bold text-amber-900 dark:text-amber-200">Full Source &amp; NIST SP 800-61r2 Playbooks</h3>
          <p className="text-xs text-amber-800/90 dark:text-amber-300/80 mt-0.5">
            Access complete incident response playbooks, Docker manifests, and API specifications.
          </p>
        </div>
        <a
          href={REPO_URL}
          target="_blank"
          rel="noopener noreferrer"
          className="inline-flex items-center gap-2 px-4 py-2 bg-amber-600 hover:bg-amber-700 text-white rounded-xl text-xs font-bold shrink-0 transition-colors shadow-xs"
        >
          <span>Open GitHub</span>
          <ExternalLink className="w-3.5 h-3.5" />
        </a>
      </div>

      {/* Core Platform Modules */}
      <div className="space-y-3">
        <h4 className="text-xs font-bold text-[var(--text-muted)] uppercase tracking-wider">Subsystems &amp; Pipeline</h4>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {[
            {
              title: 'Ingestion & Normalization',
              desc: 'High-throughput parser for Apache Combined, Nginx, Syslog, and custom security streams.',
              icon: <Terminal className="w-4 h-4 text-blue-600 dark:text-blue-400" />
            },
            {
              title: 'Detection Rules Engine',
              desc: 'Strict regex and temporal correlation engines mapped to MITRE ATT&CK techniques.',
              icon: <ShieldAlert className="w-4 h-4 text-red-600 dark:text-red-400" />
            },
            {
              title: 'Threat Intelligence',
              desc: 'Sub-second IOC enrichment with AbuseIPDB IP reputation and AlienVault OTX feeds.',
              icon: <Cpu className="w-4 h-4 text-purple-600 dark:text-purple-400" />
            },
            {
              title: 'AI SOC Analyst',
              desc: 'Automated triage, incident explainability, containment strategies via Gemini / OpenAI.',
              icon: <CheckCircle2 className="w-4 h-4 text-emerald-600 dark:text-emerald-400" />
            }
          ].map((item, idx) => (
            <div key={idx} className="p-3.5 bg-[var(--bg-card-subtle)] border border-[var(--border-default)] rounded-xl flex items-start gap-3">
              <div className="p-2 bg-[var(--bg-card)] border border-[var(--border-subtle)] rounded-lg shrink-0 shadow-2xs">{item.icon}</div>
              <div>
                <h5 className="text-xs font-bold text-[var(--text-primary)]">{item.title}</h5>
                <p className="text-[11px] text-[var(--text-muted)] mt-1 leading-relaxed">{item.desc}</p>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Detection Rules Matrix */}
      <div className="space-y-2">
        <h4 className="text-xs font-bold text-[var(--text-muted)] uppercase tracking-wider">Active Threat Detection Rules</h4>
        <div className="bg-[var(--bg-card-subtle)] border border-[var(--border-default)] rounded-xl divide-y divide-[var(--border-subtle)] text-xs">
          {[
            { rule: 'SQL Injection (SQLi)', mitre: 'T1190 — Exploit Public-Facing App', severity: 'CRITICAL' },
            { rule: 'Cross-Site Scripting (XSS)', mitre: 'T1189 — Drive-by Compromise', severity: 'HIGH' },
            { rule: 'Path Traversal / LFI', mitre: 'T1083 — File & Directory Discovery', severity: 'HIGH' },
            { rule: 'Command Injection', mitre: 'T1059 — Command & Scripting Interpreter', severity: 'CRITICAL' },
            { rule: 'Directory Enumeration', mitre: 'T1595 — Active Scanning', severity: 'MEDIUM' },
            { rule: 'Brute Force Authentication', mitre: 'T1110 — Credential Access (Sliding window)', severity: 'HIGH' },
          ].map((r, i) => (
            <div key={i} className="flex items-center justify-between px-4 py-2.5">
              <div>
                <span className="font-bold text-[var(--text-primary)]">{r.rule}</span>
                <span className="text-[var(--text-muted)] ml-2">({r.mitre})</span>
              </div>
              <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full border ${
                r.severity === 'CRITICAL' ? 'bg-red-50 text-red-700 border-red-200' :
                r.severity === 'HIGH' ? 'bg-amber-50 text-amber-800 border-amber-200' :
                'bg-yellow-50 text-yellow-800 border-yellow-200'
              }`}>
                {r.severity}
              </span>
            </div>
          ))}
        </div>
      </div>

      <div className="flex justify-end pt-2 border-t border-[var(--border-subtle)]">
        <button
          onClick={onClose}
          className="px-4 py-2 bg-[var(--bg-card-subtle)] hover:bg-[var(--bg-sidebar-hover)] text-[var(--text-primary)] border border-[var(--border-default)] rounded-xl text-xs font-bold transition-all shadow-2xs"
        >
          Close
        </button>
      </div>
    </ModalWrapper>
  );
}

// ===================================================================
// 4. PREFERENCES MODAL
// ===================================================================
export function PreferencesModal({ isOpen, onClose }: { isOpen: boolean; onClose: () => void }) {
  const [prefs, setPrefs] = useState<AppPreferences>(preferencesService.getPreferences());
  const [saved, setSaved] = useState(false);
  const { theme, setTheme } = useTheme();

  useEffect(() => {
    if (isOpen) {
      setPrefs(preferencesService.getPreferences());
      setSaved(false);
    }
  }, [isOpen]);

  const handleChange = <K extends keyof AppPreferences>(key: K, value: AppPreferences[K]) => {
    const updated = { ...prefs, [key]: value };
    setPrefs(updated);
    preferencesService.savePreferences(updated);
    setSaved(true);
    setTimeout(() => setSaved(false), 2000);
  };

  const handleReset = () => {
    const defaults = preferencesService.resetPreferences();
    setPrefs(defaults);
    setTheme('light');
    setSaved(true);
    setTimeout(() => setSaved(false), 2000);
  };

  return (
    <ModalWrapper
      isOpen={isOpen}
      onClose={onClose}
      title="User Interface &amp; SOC Preferences"
      subtitle="Customize your visual theme, density, and live polling"
      icon={<Settings className="w-5 h-5 text-[var(--text-muted)]" />}
      maxWidth="max-w-xl"
    >
      <div className="space-y-4">
        {/* Visual Theme Selection */}
        <div className="flex items-center justify-between p-4 bg-[var(--bg-card-subtle)] border border-[var(--border-default)] rounded-xl">
          <div>
            <label className="text-xs font-bold text-[var(--text-primary)] block">Visual Color Theme</label>
            <p className="text-[11px] text-[var(--text-muted)] mt-0.5">Toggle between Creamy Luxury Light (Recommended) and Dark</p>
          </div>
          <div className="flex items-center gap-1.5 bg-[var(--bg-card)] p-1 rounded-xl border border-[var(--border-default)] shadow-2xs">
            <button
              onClick={() => setTheme('light')}
              className={`flex items-center gap-1.5 px-3 py-1.5 text-xs font-bold rounded-lg transition-all ${
                theme === 'light'
                  ? 'bg-amber-100 text-amber-900 border border-amber-300/80 shadow-2xs'
                  : 'text-[var(--text-muted)] hover:text-[var(--text-primary)]'
              }`}
            >
              <Sun className="w-3.5 h-3.5 text-amber-600" />
              <span>Creamy Light</span>
            </button>
            <button
              onClick={() => setTheme('dark')}
              className={`flex items-center gap-1.5 px-3 py-1.5 text-xs font-bold rounded-lg transition-all ${
                theme === 'dark'
                  ? 'bg-blue-600 text-white shadow-2xs'
                  : 'text-[var(--text-muted)] hover:text-[var(--text-primary)]'
              }`}
            >
              <Moon className="w-3.5 h-3.5" />
              <span>Modern Dark</span>
            </button>
          </div>
        </div>

        {/* Table Density */}
        <div className="flex items-center justify-between p-4 bg-[var(--bg-card-subtle)] border border-[var(--border-default)] rounded-xl">
          <div>
            <label className="text-xs font-bold text-[var(--text-primary)] block">Table Density</label>
            <p className="text-[11px] text-[var(--text-muted)] mt-0.5">Adjust telemetry row padding across all queues</p>
          </div>
          <div className="flex items-center gap-1 bg-[var(--bg-card)] p-1 rounded-xl border border-[var(--border-default)] shadow-2xs">
            {(['comfortable', 'compact'] as const).map((density) => (
              <button
                key={density}
                onClick={() => handleChange('tableDensity', density)}
                className={`px-3 py-1 text-xs font-bold rounded-lg capitalize transition-colors ${
                  prefs.tableDensity === density
                    ? 'bg-blue-600 text-white shadow-2xs'
                    : 'text-[var(--text-muted)] hover:text-[var(--text-primary)]'
                }`}
              >
                {density}
              </button>
            ))}
          </div>
        </div>

        {/* Auto-Refresh Interval */}
        <div className="flex items-center justify-between p-4 bg-[var(--bg-card-subtle)] border border-[var(--border-default)] rounded-xl">
          <div>
            <label className="text-xs font-bold text-[var(--text-primary)] block">Telemetry Polling Rate</label>
            <p className="text-[11px] text-[var(--text-muted)] mt-0.5">Frequency for background health and queue synchronization</p>
          </div>
          <select
            value={prefs.autoRefreshInterval}
            onChange={(e) => handleChange('autoRefreshInterval', e.target.value as AppPreferences['autoRefreshInterval'])}
            className="bg-[var(--bg-card)] border border-[var(--border-default)] text-[var(--text-primary)] text-xs rounded-xl px-3 py-1.5 focus:outline-none focus:border-amber-600 font-semibold shadow-2xs"
          >
            <option value="5s">Every 5 seconds</option>
            <option value="10s">Every 10 seconds (Standard)</option>
            <option value="30s">Every 30 seconds</option>
            <option value="60s">Every 60 seconds</option>
            <option value="off">Manual Only</option>
          </select>
        </div>

        {/* Clock Format */}
        <div className="flex items-center justify-between p-4 bg-[var(--bg-card-subtle)] border border-[var(--border-default)] rounded-xl">
          <div>
            <label className="text-xs font-bold text-[var(--text-primary)] block">System Clock Display</label>
            <p className="text-[11px] text-[var(--text-muted)] mt-0.5">Top navigation bar timestamp notation</p>
          </div>
          <div className="flex items-center gap-1 bg-[var(--bg-card)] p-1 rounded-xl border border-[var(--border-default)] shadow-2xs">
            {(['24h', '12h'] as const).map((fmt) => (
              <button
                key={fmt}
                onClick={() => handleChange('clockFormat', fmt)}
                className={`px-3 py-1 text-xs font-bold rounded-lg uppercase transition-colors ${
                  prefs.clockFormat === fmt
                    ? 'bg-blue-600 text-white shadow-2xs'
                    : 'text-[var(--text-muted)] hover:text-[var(--text-primary)]'
                }`}
              >
                {fmt}
              </button>
            ))}
          </div>
        </div>

        {/* Dashboard Auto-Refresh Toggle */}
        <div className="flex items-center justify-between p-4 bg-[var(--bg-card-subtle)] border border-[var(--border-default)] rounded-xl">
          <div>
            <label className="text-xs font-bold text-[var(--text-primary)] block">Live WebSocket Broadcasts</label>
            <p className="text-[11px] text-[var(--text-muted)] mt-0.5">Listen for live alert triggers over WebSocket channel</p>
          </div>
          <button
            onClick={() => handleChange('autoRefreshDashboard', !prefs.autoRefreshDashboard)}
            className={`w-11 h-6 rounded-full transition-colors relative flex items-center px-0.5 ${
              prefs.autoRefreshDashboard ? 'bg-amber-600 dark:bg-blue-600' : 'bg-stone-300 dark:bg-slate-700'
            }`}
          >
            <span
              className={`w-5 h-5 bg-white rounded-full transition-transform shadow-xs ${
                prefs.autoRefreshDashboard ? 'translate-x-5' : 'translate-x-0'
              }`}
            />
          </button>
        </div>
      </div>

      <div className="flex items-center justify-between pt-3 border-t border-[var(--border-subtle)]">
        <button
          onClick={handleReset}
          className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs text-[var(--text-muted)] hover:text-[var(--text-primary)] transition-colors font-medium"
        >
          <RotateCcw className="w-3.5 h-3.5" />
          <span>Reset Defaults</span>
        </button>

        <div className="flex items-center gap-3">
          {saved && (
            <span className="text-xs text-emerald-600 dark:text-emerald-400 flex items-center gap-1 font-semibold animate-fade-in">
              <Check className="w-3.5 h-3.5" /> Saved
            </span>
          )}
          <button
            onClick={onClose}
            className="px-5 py-2 bg-stone-900 dark:bg-blue-600 hover:bg-stone-800 text-white rounded-xl text-xs font-bold transition-all shadow-xs"
          >
            Done
          </button>
        </div>
      </div>
    </ModalWrapper>
  );
}

// ===================================================================
// 5. ABOUT LOGSENTRY MODAL
// ===================================================================
export function AboutModal({ isOpen, onClose }: { isOpen: boolean; onClose: () => void }) {
  const REPO_URL = 'https://github.com/kharbashpriyanshu/LogSentry';

  return (
    <ModalWrapper
      isOpen={isOpen}
      onClose={onClose}
      title="About LogSentry SIEM"
      subtitle="Enterprise Security Monitoring &amp; Threat Intelligence Platform"
      icon={<Shield className="w-5 h-5 text-amber-600 dark:text-blue-400" />}
      maxWidth="max-w-md"
    >
      <div className="flex flex-col items-center text-center py-4 space-y-4">
        {/* Logo Badge */}
        <div className="w-16 h-16 rounded-2xl bg-gradient-to-br from-amber-500/20 to-blue-500/20 border border-[var(--border-default)] flex items-center justify-center p-3 shadow-md">
          <img src="/branding/logo.svg" alt="LogSentry Logo" className="w-10 h-10 drop-shadow-xs" />
        </div>

        <div>
          <h3 className="text-lg font-extrabold text-[var(--text-primary)] tracking-tight">LogSentry</h3>
          <p className="text-xs text-amber-700 dark:text-blue-400 font-bold uppercase tracking-widest mt-0.5">Enterprise SIEM v1.0.0</p>
          <span className="inline-block mt-2 px-3 py-0.5 rounded-full text-[11px] font-bold bg-[var(--bg-card-subtle)] text-[var(--text-secondary)] border border-[var(--border-default)]">
            Creamy Luxury Edition
          </span>
        </div>

        <p className="text-xs text-[var(--text-muted)] max-w-xs leading-relaxed">
          AI-assisted security monitoring, multi-vector threat detection, automated incident triage, and forensic incident reporting.
        </p>

        {/* Attribution Card */}
        <div className="w-full p-4 bg-[var(--bg-card-subtle)] border border-[var(--border-default)] rounded-xl space-y-2.5">
          <div className="flex items-center justify-between text-xs">
            <span className="text-[var(--text-muted)] font-medium">Architecture</span>
            <span className="text-[var(--text-primary)] font-bold">FastAPI + React 19 + Tailwind v4</span>
          </div>
          <div className="flex items-center justify-between text-xs">
            <span className="text-[var(--text-muted)] font-medium">License</span>
            <span className="text-[var(--text-primary)] font-mono font-semibold">MIT Open Source</span>
          </div>
          <div className="flex items-center justify-between text-xs pt-2.5 border-t border-[var(--border-subtle)]">
            <span className="text-[var(--text-muted)] font-medium">Repository</span>
            <a
              href={REPO_URL}
              target="_blank"
              rel="noopener noreferrer"
              className="text-blue-600 dark:text-blue-400 hover:underline font-bold inline-flex items-center gap-1 transition-colors"
            >
              <span>kharbashpriyanshu/LogSentry</span>
              <ExternalLink className="w-3.5 h-3.5" />
            </a>
          </div>
        </div>
      </div>

      <div className="flex justify-end pt-2 border-t border-[var(--border-subtle)]">
        <button
          onClick={onClose}
          className="px-4 py-2 bg-[var(--bg-card-subtle)] hover:bg-[var(--bg-sidebar-hover)] text-[var(--text-primary)] border border-[var(--border-default)] rounded-xl text-xs font-bold transition-all shadow-2xs"
        >
          Close
        </button>
      </div>
    </ModalWrapper>
  );
}
