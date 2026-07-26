import { useState, useEffect } from 'react';
import {
  X, User, Key, BookOpen, Settings, CheckCircle2, AlertCircle,
  ExternalLink, Clock, ShieldAlert, Cpu, Terminal, Lock, Info,
  Shield, Check, RotateCcw
} from 'lucide-react';
import { useQuery } from '@tanstack/react-query';
import { healthService } from '../services/healthService';
import { preferencesService, type AppPreferences } from '../services/preferencesService';

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
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-sm animate-fade-in">
      <div
        className={`w-full ${maxWidth} bg-[#111827] border border-slate-700/80 rounded-2xl shadow-2xl overflow-hidden flex flex-col max-h-[88vh]`}
        onClick={(e) => e.stopPropagation()}
      >
        {/* Modal Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800 bg-[#0d1424] shrink-0">
          <div className="flex items-center gap-3">
            {icon && (
              <div className="p-2 bg-blue-500/10 border border-blue-500/20 rounded-xl text-blue-400">
                {icon}
              </div>
            )}
            <div>
              <h2 className="text-base font-bold text-slate-100">{title}</h2>
              {subtitle && <p className="text-xs text-slate-400 mt-0.5">{subtitle}</p>}
            </div>
          </div>
          <button
            onClick={onClose}
            aria-label="Close modal"
            className="p-1.5 text-slate-400 hover:text-slate-200 hover:bg-slate-800 rounded-lg transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Modal Content */}
        <div className="p-6 overflow-y-auto space-y-6 text-slate-300 text-sm">
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
      title="User Profile"
      subtitle="Active analyst session metadata"
      icon={<User className="w-5 h-5" />}
      maxWidth="max-w-lg"
    >
      {/* Avatar & Role Card */}
      <div className="flex items-center gap-4 p-4 bg-slate-900/80 border border-slate-800 rounded-xl">
        <div className="w-14 h-14 rounded-2xl bg-gradient-to-br from-blue-500 to-violet-600 flex items-center justify-center text-white text-xl font-bold shrink-0 shadow-lg">
          DU
        </div>
        <div>
          <h3 className="text-base font-bold text-slate-100">Demo User</h3>
          <p className="text-xs font-semibold text-blue-400 mt-0.5">SOC Analyst</p>
          <p className="text-xs text-slate-500 mt-0.5">demo@logsentry.local</p>
        </div>
      </div>

      {/* Metadata Table */}
      <div className="space-y-2">
        <h4 className="text-xs font-bold text-slate-400 uppercase tracking-wider">Session & System Context</h4>
        <div className="bg-slate-900/60 border border-slate-800 rounded-xl divide-y divide-slate-800/60 overflow-hidden">
          {[
            { label: 'Role Designation', value: 'SOC Analyst (Full Monitoring)' },
            { label: 'Application Mode', value: 'Local / Standalone Demo' },
            { label: 'LogSentry Version', value: 'v1.0.0 (Enterprise SIEM)' },
            { label: 'Authentication Engine', value: 'Standalone Session (Demo)' },
            { label: 'Environment', value: 'Development / Demo' },
          ].map((item, idx) => (
            <div key={idx} className="flex items-center justify-between px-4 py-2.5 text-xs">
              <span className="text-slate-400 font-medium">{item.label}</span>
              <span className="text-slate-200 font-mono">{item.value}</span>
            </div>
          ))}
        </div>
      </div>

      {/* Honest Demo Mode / Authentication Roadmap Notice */}
      <div className="flex items-start gap-3 p-4 bg-amber-500/10 border border-amber-500/20 rounded-xl">
        <Info className="w-5 h-5 text-amber-400 shrink-0 mt-0.5" />
        <div className="text-xs text-amber-300/90 leading-relaxed">
          <span className="font-bold block text-amber-200 mb-0.5">Standalone Demo Mode</span>
          LogSentry v1.0.0 currently operates in standalone demo mode without multi-tenant authentication. True multi-user RBAC and persistent JWT authentication are scheduled for release in the v1.1.0 roadmap. No account credentials are fabricated.
        </div>
      </div>

      <div className="flex justify-end pt-2 border-t border-slate-800">
        <button
          onClick={onClose}
          className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-xs font-semibold transition-colors"
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
      name: 'Gemini',
      category: 'AI SOC Analyst (Google DeepMind)',
      configured: status?.gemini ?? false,
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
      configured: status?.abuseipdb ?? false,
      envKey: 'ABUSEIPDB_API_KEY',
    },
    {
      id: 'otx',
      name: 'AlienVault OTX',
      category: 'Threat Intelligence (Open Threat Exchange)',
      configured: status?.otx ?? false,
      envKey: 'OTX_API_KEY',
    },
  ];

  return (
    <ModalWrapper
      isOpen={isOpen}
      onClose={onClose}
      title="API / Integration Configuration"
      subtitle="Runtime provider status and security audit"
      icon={<Key className="w-5 h-5" />}
      maxWidth="max-w-2xl"
    >
      {/* Security Architecture Warning */}
      <div className="flex items-start gap-3 p-4 bg-blue-500/10 border border-blue-500/20 rounded-xl">
        <Lock className="w-5 h-5 text-blue-400 shrink-0 mt-0.5" />
        <div className="text-xs text-blue-200 leading-relaxed">
          <span className="font-bold block text-blue-100 mb-0.5">Read-Only Secure Architecture</span>
          Provider API keys are stored strictly in server-side <code className="font-mono bg-blue-950 px-1 py-0.5 rounded text-blue-300">.env</code> configuration. To enforce defense-in-depth, full secrets are never transmitted to the browser, displayed in source code, logged, or stored in localStorage.
        </div>
      </div>

      {/* Provider Status List */}
      <div className="space-y-2">
        <h4 className="text-xs font-bold text-slate-400 uppercase tracking-wider">Provider Status</h4>
        <div className="bg-slate-900/60 border border-slate-800 rounded-xl divide-y divide-slate-800/60 overflow-hidden">
          {isLoading ? (
            <div className="p-6 text-center text-xs text-slate-500">Checking provider status from backend...</div>
          ) : (
            providers.map((p) => (
              <div key={p.id} className="flex items-center justify-between px-4 py-3">
                <div>
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-semibold text-slate-200">{p.name}</span>
                    <span className="text-[11px] text-slate-500 font-mono">({p.envKey})</span>
                  </div>
                  <p className="text-xs text-slate-400 mt-0.5">{p.category}</p>
                </div>
                <div className="shrink-0">
                  {p.configured ? (
                    <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold bg-green-500/15 text-green-400 border border-green-500/30">
                      <CheckCircle2 className="w-3.5 h-3.5" />
                      Configured &#10003;
                    </span>
                  ) : (
                    <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold bg-slate-800 text-slate-400 border border-slate-700">
                      <AlertCircle className="w-3.5 h-3.5 text-slate-500" />
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
        <h4 className="text-xs font-bold text-slate-400 uppercase tracking-wider">How to Configure Secrets</h4>
        <div className="p-4 bg-slate-900 border border-slate-800 rounded-xl text-xs space-y-2 font-mono text-slate-300">
          <p className="font-sans text-slate-400">Add keys to your server <code className="text-slate-200">.env</code> file and restart Uvicorn / Docker:</p>
          <div className="bg-black/60 p-3 rounded-lg border border-slate-800 text-green-400 space-y-1">
            <p># Security Providers in .env</p>
            <p>GEMINI_API_KEY=your_gemini_key_here</p>
            <p>OPENAI_API_KEY=your_openai_key_here</p>
            <p>ABUSEIPDB_API_KEY=your_abuseipdb_key_here</p>
            <p>OTX_API_KEY=your_otx_key_here</p>
          </div>
        </div>
      </div>

      <div className="flex justify-end pt-2 border-t border-slate-800">
        <button
          onClick={onClose}
          className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-xs font-semibold transition-colors"
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
      title="LogSentry Platform Documentation"
      subtitle="Enterprise SIEM capabilities and architecture"
      icon={<BookOpen className="w-5 h-5" />}
      maxWidth="max-w-3xl"
    >
      {/* Official Repo Link Banner */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 p-4 bg-blue-500/10 border border-blue-500/20 rounded-xl">
        <div>
          <h3 className="text-sm font-bold text-blue-200">Official GitHub Repository</h3>
          <p className="text-xs text-blue-300/80 mt-0.5">
            Full README, installation guides, Docker manifests, and Python backend documentation.
          </p>
        </div>
        <a
          href={REPO_URL}
          target="_blank"
          rel="noopener noreferrer"
          className="inline-flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-xs font-semibold shrink-0 transition-colors shadow-md"
        >
          <span>Open README on GitHub</span>
          <ExternalLink className="w-3.5 h-3.5" />
        </a>
      </div>

      {/* Core Platform Modules */}
      <div className="space-y-3">
        <h4 className="text-xs font-bold text-slate-400 uppercase tracking-wider">Core SIEM Capabilities</h4>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {[
            {
              title: 'Ingestion & Normalization',
              desc: 'High-performance parser for Apache, Nginx, Syslog, CEF, SSH, and Windows Event Logs.',
              icon: <Terminal className="w-4 h-4 text-blue-400" />
            },
            {
              title: 'Detection Rules Engine',
              desc: 'Strict regex and temporal correlation engines mapped to MITRE ATT&CK techniques.',
              icon: <ShieldAlert className="w-4 h-4 text-red-400" />
            },
            {
              title: 'Threat Intelligence',
              desc: 'Real-time IOC enrichment with AbuseIPDB IP reputation and AlienVault OTX feeds.',
              icon: <Cpu className="w-4 h-4 text-purple-400" />
            },
            {
              title: 'AI SOC Analyst',
              desc: 'Automated triage, incident explainability, and executive summaries via Gemini / OpenAI.',
              icon: <CheckCircle2 className="w-4 h-4 text-green-400" />
            }
          ].map((item, idx) => (
            <div key={idx} className="p-3.5 bg-slate-900/60 border border-slate-800 rounded-xl flex items-start gap-3">
              <div className="p-2 bg-slate-800 rounded-lg shrink-0">{item.icon}</div>
              <div>
                <h5 className="text-xs font-bold text-slate-200">{item.title}</h5>
                <p className="text-[11px] text-slate-400 mt-1 leading-relaxed">{item.desc}</p>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Detection Rules Matrix */}
      <div className="space-y-2">
        <h4 className="text-xs font-bold text-slate-400 uppercase tracking-wider">Active Detection Rules</h4>
        <div className="bg-slate-900/60 border border-slate-800 rounded-xl divide-y divide-slate-800/60 text-xs">
          {[
            { rule: 'SQL Injection (SQLi)', mitre: 'T1190 — Exploit Public-Facing App', severity: 'CRITICAL' },
            { rule: 'Cross-Site Scripting (XSS)', mitre: 'T1189 — Drive-by Compromise', severity: 'HIGH' },
            { rule: 'Path Traversal / LFI', mitre: 'T1083 — File & Directory Discovery', severity: 'HIGH' },
            { rule: 'Command Injection', mitre: 'T1059 — Command & Scripting Interpreter', severity: 'CRITICAL' },
            { rule: 'Directory Enumeration', mitre: 'T1595 — Active Scanning', severity: 'MEDIUM' },
            { rule: 'Brute Force Login Surge', mitre: 'T1110 — Brute Force (Temporal correlation)', severity: 'CRITICAL' },
          ].map((r, i) => (
            <div key={i} className="flex items-center justify-between px-4 py-2.5">
              <div>
                <span className="font-semibold text-slate-200">{r.rule}</span>
                <span className="text-slate-500 ml-2">({r.mitre})</span>
              </div>
              <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-slate-800 text-slate-300 border border-slate-700">
                {r.severity}
              </span>
            </div>
          ))}
        </div>
      </div>

      <div className="flex justify-end pt-2 border-t border-slate-800">
        <button
          onClick={onClose}
          className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-xs font-semibold transition-colors"
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
    setSaved(true);
    setTimeout(() => setSaved(false), 2000);
  };

  return (
    <ModalWrapper
      isOpen={isOpen}
      onClose={onClose}
      title="Frontend Preferences"
      subtitle="Customize UI display and auto-refresh behavior"
      icon={<Settings className="w-5 h-5" />}
      maxWidth="max-w-xl"
    >
      <div className="space-y-4">
        {/* Table Density */}
        <div className="flex items-center justify-between p-3.5 bg-slate-900/60 border border-slate-800 rounded-xl">
          <div>
            <label className="text-xs font-bold text-slate-200 block">Table Density</label>
            <p className="text-[11px] text-slate-500 mt-0.5">Adjust row spacing across alerts and incident tables</p>
          </div>
          <div className="flex items-center gap-1 bg-slate-800 p-1 rounded-lg border border-slate-700">
            {(['comfortable', 'compact'] as const).map((density) => (
              <button
                key={density}
                onClick={() => handleChange('tableDensity', density)}
                className={`px-3 py-1 text-xs font-medium rounded-md capitalize transition-colors ${
                  prefs.tableDensity === density
                    ? 'bg-blue-600 text-white shadow-sm'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {density}
              </button>
            ))}
          </div>
        </div>

        {/* Auto-Refresh Interval */}
        <div className="flex items-center justify-between p-3.5 bg-slate-900/60 border border-slate-800 rounded-xl">
          <div>
            <label className="text-xs font-bold text-slate-200 block">Auto-Refresh Interval</label>
            <p className="text-[11px] text-slate-500 mt-0.5">Polling frequency for live SOC alerts and threat feeds</p>
          </div>
          <select
            value={prefs.autoRefreshInterval}
            onChange={(e) => handleChange('autoRefreshInterval', e.target.value as AppPreferences['autoRefreshInterval'])}
            className="bg-slate-800 border border-slate-700 text-slate-200 text-xs rounded-lg px-3 py-1.5 focus:outline-none focus:border-blue-500"
          >
            <option value="5s">Every 5 seconds</option>
            <option value="10s">Every 10 seconds (Default)</option>
            <option value="30s">Every 30 seconds</option>
            <option value="60s">Every 60 seconds</option>
            <option value="off">Disabled</option>
          </select>
        </div>

        {/* Timestamp Format */}
        <div className="flex items-center justify-between p-3.5 bg-slate-900/60 border border-slate-800 rounded-xl">
          <div>
            <label className="text-xs font-bold text-slate-200 block">Timestamp Format</label>
            <p className="text-[11px] text-slate-500 mt-0.5">Select how timestamps are formatted on logs and incidents</p>
          </div>
          <select
            value={prefs.timestampFormat}
            onChange={(e) => handleChange('timestampFormat', e.target.value as AppPreferences['timestampFormat'])}
            className="bg-slate-800 border border-slate-700 text-slate-200 text-xs rounded-lg px-3 py-1.5 focus:outline-none focus:border-blue-500"
          >
            <option value="iso">ISO 8601 (2026-07-26T04:15Z)</option>
            <option value="standard">Standard (Jul 26, 2026 04:15)</option>
            <option value="relative">Relative (2m ago)</option>
          </select>
        </div>

        {/* Clock Format (12h/24h) */}
        <div className="flex items-center justify-between p-3.5 bg-slate-900/60 border border-slate-800 rounded-xl">
          <div>
            <label className="text-xs font-bold text-slate-200 block">Clock Format</label>
            <p className="text-[11px] text-slate-500 mt-0.5">Top navbar and timeline clock notation</p>
          </div>
          <div className="flex items-center gap-1 bg-slate-800 p-1 rounded-lg border border-slate-700">
            {(['24h', '12h'] as const).map((fmt) => (
              <button
                key={fmt}
                onClick={() => handleChange('clockFormat', fmt)}
                className={`px-3 py-1 text-xs font-medium rounded-md uppercase transition-colors ${
                  prefs.clockFormat === fmt
                    ? 'bg-blue-600 text-white shadow-sm'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {fmt}
              </button>
            ))}
          </div>
        </div>

        {/* Dashboard Auto-Refresh Toggle */}
        <div className="flex items-center justify-between p-3.5 bg-slate-900/60 border border-slate-800 rounded-xl">
          <div>
            <label className="text-xs font-bold text-slate-200 block">Dashboard Live Polling</label>
            <p className="text-[11px] text-slate-500 mt-0.5">Enable background queries when viewing summary panels</p>
          </div>
          <button
            onClick={() => handleChange('autoRefreshDashboard', !prefs.autoRefreshDashboard)}
            className={`w-11 h-6 rounded-full transition-colors relative flex items-center px-0.5 ${
              prefs.autoRefreshDashboard ? 'bg-blue-600' : 'bg-slate-700'
            }`}
          >
            <span
              className={`w-5 h-5 bg-white rounded-full transition-transform ${
                prefs.autoRefreshDashboard ? 'translate-x-5' : 'translate-x-0'
              }`}
            />
          </button>
        </div>

        {/* Notifications Preference */}
        <div className="flex items-center justify-between p-3.5 bg-slate-900/60 border border-slate-800 rounded-xl">
          <div>
            <label className="text-xs font-bold text-slate-200 block">Alert Toast Density</label>
            <p className="text-[11px] text-slate-500 mt-0.5">Control popup notifications for live security events</p>
          </div>
          <select
            value={prefs.notificationPreference}
            onChange={(e) => handleChange('notificationPreference', e.target.value as AppPreferences['notificationPreference'])}
            className="bg-slate-800 border border-slate-700 text-slate-200 text-xs rounded-lg px-3 py-1.5 focus:outline-none focus:border-blue-500"
          >
            <option value="all">All Alerts</option>
            <option value="critical">Critical &amp; High Only</option>
            <option value="muted">Muted</option>
          </select>
        </div>
      </div>

      <div className="flex items-center justify-between pt-2 border-t border-slate-800">
        <button
          onClick={handleReset}
          className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs text-slate-400 hover:text-slate-200 transition-colors"
        >
          <RotateCcw className="w-3.5 h-3.5" />
          <span>Reset to defaults</span>
        </button>

        <div className="flex items-center gap-3">
          {saved && (
            <span className="text-xs text-green-400 flex items-center gap-1 animate-fade-in">
              <Check className="w-3.5 h-3.5" /> Saved to browser storage
            </span>
          )}
          <button
            onClick={onClose}
            className="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-xs font-semibold transition-colors shadow-lg shadow-blue-600/20"
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
      title="About LogSentry"
      subtitle="Platform metadata and attribution"
      icon={<Shield className="w-5 h-5 text-blue-400" />}
      maxWidth="max-w-md"
    >
      <div className="flex flex-col items-center text-center py-4 space-y-4">
        {/* Logo Icon */}
        <div className="w-16 h-16 rounded-2xl bg-blue-600/15 border border-blue-500/30 flex items-center justify-center p-3 shadow-xl">
          <img src="/branding/logo.svg" alt="LogSentry Logo" className="w-10 h-10" />
        </div>

        <div>
          <h3 className="text-lg font-bold text-slate-100 tracking-tight">LogSentry</h3>
          <p className="text-xs text-blue-400 font-semibold uppercase tracking-widest mt-0.5">Enterprise SIEM</p>
          <span className="inline-block mt-2 px-2.5 py-0.5 rounded-full text-[10px] font-bold bg-slate-800 text-slate-300 border border-slate-700">
            Version 1.0.0
          </span>
        </div>

        <p className="text-xs text-slate-400 max-w-xs leading-relaxed">
          AI-assisted security monitoring, threat detection, investigation and incident reporting.
        </p>

        {/* Creator Attribution Box */}
        <div className="w-full p-4 bg-slate-900/60 border border-slate-800 rounded-xl space-y-2">
          <div className="flex items-center justify-between text-xs">
            <span className="text-slate-400">Creator</span>
            <span className="text-slate-200 font-semibold">Built by Martial</span>
          </div>
          <div className="flex items-center justify-between text-xs">
            <span className="text-slate-400">License</span>
            <span className="text-slate-200 font-mono">MIT License</span>
          </div>
          <div className="flex items-center justify-between text-xs pt-2 border-t border-slate-800">
            <span className="text-slate-400">Source Code</span>
            <a
              href={REPO_URL}
              target="_blank"
              rel="noopener noreferrer"
              className="text-blue-400 hover:text-blue-300 font-semibold inline-flex items-center gap-1 transition-colors"
            >
              <span>GitHub</span>
              <ExternalLink className="w-3.5 h-3.5" />
            </a>
          </div>
        </div>
      </div>

      <div className="flex justify-end pt-2 border-t border-slate-800">
        <button
          onClick={onClose}
          className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-xs font-semibold transition-colors"
        >
          Close
        </button>
      </div>
    </ModalWrapper>
  );
}
