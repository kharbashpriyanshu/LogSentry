import { useState, useEffect, useCallback } from 'react';
import { Settings as SettingsIcon, Save, AlertTriangle, ShieldCheck, BrainCircuit, Bell, Palette, Lock, Cpu } from 'lucide-react';
import { Toast } from '../components/ui';

type Tab = 'general' | 'detection' | 'ai' | 'threat' | 'security' | 'notifications' | 'appearance';

interface SettingsState {
  // General
  orgName: string;
  timezone: string;
  // Detection
  bruteForceThreshold: string;
  bruteForceWindow: string;
  sqliThreshold: string;
  enableXSS: boolean;
  enablePathTraversal: boolean;
  enableCmdInjection: boolean;
  // AI
  aiProvider: string;
  openaiKey: string;
  geminiKey: string;
  ollamaUrl: string;
  maxTokens: string;
  // Threat Intel
  abuseipdbKey: string;
  otxKey: string;
  enableAutoEnrich: boolean;
  // Security
  sessionTimeout: string;
  maxUploadMb: string;
  enableCors: boolean;
  // Notifications
  notifyOnCritical: boolean;
  notifyOnHigh: boolean;
  notifyEmail: string;
  // Appearance
  theme: 'dark' | 'darker' | 'light';
  accentColor: string;
  dateFormat: string;
  // Data Management
  dataRetention: string;
}

const DEFAULTS: SettingsState = {
  orgName: 'SOC Operations Center', timezone: 'UTC',
  bruteForceThreshold: '5', bruteForceWindow: '60', sqliThreshold: '1', enableXSS: true, enablePathTraversal: true, enableCmdInjection: true,
  aiProvider: 'openai', openaiKey: '', geminiKey: '', ollamaUrl: 'http://localhost:11434', maxTokens: '2048',
  abuseipdbKey: '', otxKey: '', enableAutoEnrich: true,
  sessionTimeout: '3600', maxUploadMb: '10', enableCors: true,
  notifyOnCritical: true, notifyOnHigh: false, notifyEmail: '',
  theme: 'dark', accentColor: '#3b82f6', dateFormat: 'yyyy-MM-dd',
  dataRetention: '90',
};

const TABS: Array<{ id: Tab; label: string; icon: any }> = [
  { id: 'general',       label: 'General',       icon: SettingsIcon },
  { id: 'detection',     label: 'Detection',     icon: ShieldCheck },
  { id: 'ai',            label: 'AI Engine',     icon: BrainCircuit },
  { id: 'threat',        label: 'Threat Intel',  icon: Cpu },
  { id: 'security',      label: 'Security',      icon: Lock },
  { id: 'notifications', label: 'Notifications', icon: Bell },
  { id: 'appearance',    label: 'Appearance',    icon: Palette },
];

function Field({ label, desc, children }: { label: string; desc?: string; children: React.ReactNode }) {
  return (
    <div className="flex items-start justify-between gap-4 py-4 border-b border-slate-800/60 last:border-0">
      <div className="min-w-0 flex-1">
        <p className="text-sm font-medium text-slate-200">{label}</p>
        {desc && <p className="text-xs text-slate-500 mt-0.5 leading-relaxed">{desc}</p>}
      </div>
      <div className="shrink-0">{children}</div>
    </div>
  );
}

function TextInput({ value, onChange, placeholder, type = 'text', mono = false }: any) {
  return (
    <input type={type} value={value} onChange={e => onChange(e.target.value)} placeholder={placeholder}
      className={`w-56 bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-200 placeholder-slate-600 focus:outline-none focus:border-blue-500/60 transition-colors ${mono ? 'font-mono text-xs' : ''}`} />
  );
}

function Toggle({ value, onChange }: { value: boolean; onChange: (v: boolean) => void }) {
  return (
    <button onClick={() => onChange(!value)} role="switch" aria-checked={value}
      className={`relative inline-flex w-10 h-5.5 rounded-full transition-colors focus:outline-none ${value ? 'bg-blue-600' : 'bg-slate-700'}`}
      style={{ height: '22px', minWidth: '40px' }}>
      <span className={`inline-block w-4 h-4 bg-white rounded-full shadow-sm transition-transform mt-[3px] ml-[3px] ${value ? 'translate-x-[18px]' : 'translate-x-0'}`} />
    </button>
  );
}

export default function Settings() {
  const [activeTab, setActiveTab] = useState<Tab>('general');
  const [settings, setSettings] = useState<SettingsState>(DEFAULTS);
  const [hasChanges, setHasChanges] = useState(false);
  const [errors, setErrors] = useState<string[]>([]);
  const [toast, setToast] = useState<{ msg: string; type: 'success' | 'error' } | null>(null);

  useEffect(() => {
    const stored = localStorage.getItem('logsentry_settings_v2');
    if (stored) {
      const parsed = JSON.parse(stored);
      setSettings(s => ({ ...s, ...parsed }));
    }
  }, []);

  const set = useCallback(<K extends keyof SettingsState>(key: K, val: SettingsState[K]) => {
    setSettings(s => ({ ...s, [key]: val }));
    setHasChanges(true);
  }, []);

  const validate = () => {
    const errs: string[] = [];
    const bf = parseInt(settings.bruteForceThreshold);
    const bw = parseInt(settings.bruteForceWindow);
    if (isNaN(bf) || bf < 1) errs.push('Brute force threshold must be a positive integer.');
    if (isNaN(bw) || bw < 10) errs.push('Analysis window must be at least 10 seconds.');
    if (settings.notifyEmail && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(settings.notifyEmail)) errs.push('Invalid notification email address.');
    return errs;
  };

  const handleSave = (e: React.FormEvent) => {
    e.preventDefault();
    const errs = validate();
    if (errs.length) { setErrors(errs); return; }
    setErrors([]);
    localStorage.setItem('logsentry_settings_v2', JSON.stringify(settings));
    setHasChanges(false);
    setToast({ msg: 'Settings saved and applied', type: 'success' });
  };

  const handleReset = () => {
    setSettings(DEFAULTS);
    setHasChanges(true);
    setToast({ msg: 'Settings reset to defaults', type: 'success' });
  };

  return (
    <div className="space-y-5 animate-fade-in max-w-5xl">
      {toast && <Toast message={toast.msg} type={toast.type} onClose={() => setToast(null)} />}

      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <SettingsIcon className="w-5 h-5 text-slate-400" /> SIEM Configuration
          </h1>
          <p className="text-xs text-slate-500 mt-0.5">
            {hasChanges ? <span className="text-yellow-400 font-semibold">● Unsaved changes</span> : 'All changes saved'}
          </p>
        </div>
      </div>

      {errors.length > 0 && (
        <div className="bg-red-500/8 border border-red-500/20 rounded-xl p-4">
          <div className="flex items-center gap-2 text-red-400 font-semibold text-sm mb-2"><AlertTriangle className="w-4 h-4" /> Validation Errors</div>
          <ul className="space-y-1 text-xs text-red-300 list-disc pl-5">{errors.map((e,i) => <li key={i}>{e}</li>)}</ul>
        </div>
      )}

      <div className="flex gap-5">
        {/* Vertical tab bar */}
        <div className="w-44 shrink-0">
          <div className="bg-[#1e293b] border border-slate-700/80 rounded-xl overflow-hidden">
            {TABS.map(t => {
              const Icon = t.icon;
              return (
                <button key={t.id} onClick={() => setActiveTab(t.id)}
                  className={`w-full flex items-center gap-2.5 px-4 py-3 text-sm transition-colors border-l-2 ${activeTab === t.id ? 'bg-blue-600/10 border-l-blue-500 text-blue-400 font-semibold' : 'border-l-transparent text-slate-400 hover:text-slate-200 hover:bg-slate-800/40'}`}>
                  <Icon className="w-4 h-4 shrink-0" />
                  {t.label}
                </button>
              );
            })}
          </div>
        </div>

        {/* Panel */}
        <form onSubmit={handleSave} className="flex-1 space-y-4">
          <div className="bg-[#1e293b] border border-slate-700/80 rounded-xl p-6">
            {activeTab === 'general' && (
              <div className="animate-fade-in">
                <h2 className="text-sm font-bold text-slate-300 mb-1">General Settings</h2>
                <p className="text-xs text-slate-500 mb-5">Organization profile and system preferences.</p>
                <Field label="Organization Name" desc="Appears in reports and notifications">
                  <TextInput value={settings.orgName} onChange={(v: string) => set('orgName', v)} placeholder="My SOC" />
                </Field>
                <Field label="Timezone" desc="Used for log display and report timestamps">
                  <select value={settings.timezone} onChange={e => set('timezone', e.target.value)}
                    className="bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-blue-500/60">
                    {['UTC', 'America/New_York', 'America/Los_Angeles', 'Europe/London', 'Asia/Kolkata', 'Asia/Tokyo'].map(tz => (
                      <option key={tz} value={tz}>{tz}</option>
                    ))}
                  </select>
                </Field>
                <Field label="Data Retention Policy" desc="Number of days to keep logs and incidents">
                  <select value={settings.dataRetention} onChange={e => set('dataRetention', e.target.value)}
                    className="bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-blue-500/60">
                    <option value="30">30 Days</option>
                    <option value="90">90 Days</option>
                    <option value="180">180 Days</option>
                    <option value="365">1 Year</option>
                    <option value="99999">Indefinite (Not Recommended)</option>
                  </select>
                </Field>
              </div>
            )}

            {activeTab === 'detection' && (
              <div className="animate-fade-in">
                <h2 className="text-sm font-bold text-slate-300 mb-1">Detection Engine</h2>
                <p className="text-xs text-slate-500 mb-5">Tune rule thresholds and enabled detectors.</p>
                <Field label="Brute Force Threshold" desc="Failed attempts before generating an alert">
                  <TextInput type="number" value={settings.bruteForceThreshold} onChange={(v: string) => set('bruteForceThreshold', v)} />
                </Field>
                <Field label="Brute Force Window (sec)" desc="Time window for counting failures">
                  <TextInput type="number" value={settings.bruteForceWindow} onChange={(v: string) => set('bruteForceWindow', v)} />
                </Field>
                <Field label="SQL Injection Threshold" desc="Minimum matches to trigger alert (0 = any)">
                  <TextInput type="number" value={settings.sqliThreshold} onChange={(v: string) => set('sqliThreshold', v)} />
                </Field>
                <Field label="Enable XSS Detection"><Toggle value={settings.enableXSS} onChange={v => set('enableXSS', v)} /></Field>
                <Field label="Enable Path Traversal"><Toggle value={settings.enablePathTraversal} onChange={v => set('enablePathTraversal', v)} /></Field>
                <Field label="Enable Command Injection"><Toggle value={settings.enableCmdInjection} onChange={v => set('enableCmdInjection', v)} /></Field>
              </div>
            )}

            {activeTab === 'ai' && (
              <div className="animate-fade-in">
                <h2 className="text-sm font-bold text-slate-300 mb-1">AI Engine Configuration</h2>
                <p className="text-xs text-slate-500 mb-5">Configure the LLM provider for AI-powered analysis.</p>
                <Field label="Active Provider" desc="LLM used for forensic analysis">
                  <select value={settings.aiProvider} onChange={e => set('aiProvider', e.target.value)}
                    className="bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-blue-500/60">
                    <option value="openai">OpenAI (GPT-4o)</option>
                    <option value="gemini">Google Gemini 1.5 Flash</option>
                    <option value="ollama">Ollama (Local)</option>
                  </select>
                </Field>
                {settings.aiProvider === 'openai' && (
                  <Field label="OpenAI API Key" desc="Starts with sk-...">
                    <TextInput type="password" value={settings.openaiKey} onChange={(v: string) => set('openaiKey', v)} placeholder="sk-…" mono />
                  </Field>
                )}
                {settings.aiProvider === 'gemini' && (
                  <Field label="Gemini API Key" desc="From Google AI Studio">
                    <TextInput type="password" value={settings.geminiKey} onChange={(v: string) => set('geminiKey', v)} placeholder="AIzaSy…" mono />
                  </Field>
                )}
                {settings.aiProvider === 'ollama' && (
                  <Field label="Ollama URL" desc="Local Ollama server endpoint">
                    <TextInput value={settings.ollamaUrl} onChange={(v: string) => set('ollamaUrl', v)} placeholder="http://localhost:11434" mono />
                  </Field>
                )}
                <Field label="Max Tokens" desc="Maximum response length per analysis">
                  <TextInput type="number" value={settings.maxTokens} onChange={(v: string) => set('maxTokens', v)} />
                </Field>
              </div>
            )}

            {activeTab === 'threat' && (
              <div className="animate-fade-in">
                <h2 className="text-sm font-bold text-slate-300 mb-1">Threat Intelligence Feeds</h2>
                <p className="text-xs text-slate-500 mb-5">API keys for external threat data providers.</p>
                <div className="mb-6 p-4 bg-slate-800/40 rounded-xl border border-slate-700/60 flex items-center justify-between">
                  <div>
                    <p className="text-sm font-semibold text-slate-200">Integration Status</p>
                    <p className="text-[10px] text-slate-500 mt-1">Real-time connection checks</p>
                  </div>
                  <div className="flex gap-4">
                    <span className="flex items-center gap-1.5 text-xs text-slate-400 font-medium"><div className={`w-2 h-2 rounded-full ${settings.abuseipdbKey ? 'bg-green-500 shadow-[0_0_8px_rgba(34,197,94,0.5)]' : 'bg-slate-600'}`} /> AbuseIPDB</span>
                    <span className="flex items-center gap-1.5 text-xs text-slate-400 font-medium"><div className={`w-2 h-2 rounded-full ${settings.otxKey ? 'bg-green-500 shadow-[0_0_8px_rgba(34,197,94,0.5)]' : 'bg-slate-600'}`} /> OTX</span>
                  </div>
                </div>
                <Field label="AbuseIPDB API Key" desc="abuseipdb.com — IP abuse reports">
                  <TextInput type="password" value={settings.abuseipdbKey} onChange={(v: string) => set('abuseipdbKey', v)} placeholder="Your key" mono />
                </Field>
                <Field label="AlienVault OTX Key" desc="otx.alienvault.com — threat pulses">
                  <TextInput type="password" value={settings.otxKey} onChange={(v: string) => set('otxKey', v)} placeholder="Your key" mono />
                </Field>
                <Field label="Auto-Enrich Alerts" desc="Automatically query threat feeds for every new alert">
                  <Toggle value={settings.enableAutoEnrich} onChange={v => set('enableAutoEnrich', v)} />
                </Field>
              </div>
            )}

            {activeTab === 'security' && (
              <div className="animate-fade-in">
                <h2 className="text-sm font-bold text-slate-300 mb-1">Security Settings</h2>
                <p className="text-xs text-slate-500 mb-5">Platform security and access controls.</p>
                <Field label="Session Timeout (sec)" desc="Idle time before auto-logout">
                  <TextInput type="number" value={settings.sessionTimeout} onChange={(v: string) => set('sessionTimeout', v)} />
                </Field>
                <Field label="Max Upload Size (MB)" desc="Maximum allowed log file size">
                  <TextInput type="number" value={settings.maxUploadMb} onChange={(v: string) => set('maxUploadMb', v)} />
                </Field>
                <Field label="Enable CORS" desc="Allow browser cross-origin requests to API">
                  <Toggle value={settings.enableCors} onChange={v => set('enableCors', v)} />
                </Field>
              </div>
            )}

            {activeTab === 'notifications' && (
              <div className="animate-fade-in">
                <h2 className="text-sm font-bold text-slate-300 mb-1">Notification Preferences</h2>
                <p className="text-xs text-slate-500 mb-5">Configure alerting for SOC events.</p>
                <Field label="Notify on Critical" desc="Immediate notification for CRITICAL severity alerts">
                  <Toggle value={settings.notifyOnCritical} onChange={v => set('notifyOnCritical', v)} />
                </Field>
                <Field label="Notify on High" desc="Notifications for HIGH severity alerts">
                  <Toggle value={settings.notifyOnHigh} onChange={v => set('notifyOnHigh', v)} />
                </Field>
                <Field label="Notification Email" desc="Destination for email alerts">
                  <TextInput type="email" value={settings.notifyEmail} onChange={(v: string) => set('notifyEmail', v)} placeholder="analyst@org.com" />
                </Field>
              </div>
            )}

            {activeTab === 'appearance' && (
              <div className="animate-fade-in">
                <h2 className="text-sm font-bold text-slate-300 mb-1">Appearance</h2>
                <p className="text-xs text-slate-500 mb-5">Visual preferences for the dashboard.</p>
                <Field label="Theme" desc="Interface color scheme">
                  <select value={settings.theme} onChange={e => set('theme', e.target.value as any)}
                    className="bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-blue-500/60">
                    <option value="dark">Dark (Slate)</option>
                    <option value="darker">Darker (Midnight)</option>
                    <option value="light">Light Mode</option>
                  </select>
                </Field>
                <Field label="Accent Color" desc="Primary UI highlight color">
                  <div className="flex items-center gap-2">
                    <input type="color" value={settings.accentColor} onChange={e => set('accentColor', e.target.value)}
                      className="w-9 h-9 rounded-lg border border-slate-700 bg-slate-800 cursor-pointer" />
                    <span className="font-mono text-xs text-slate-400">{settings.accentColor}</span>
                  </div>
                </Field>
                <Field label="Date Format" desc="Format for timestamps in reports">
                  <select value={settings.dateFormat} onChange={e => set('dateFormat', e.target.value)}
                    className="bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-blue-500/60">
                    <option value="yyyy-MM-dd">ISO 8601 (2024-06-15)</option>
                    <option value="MM/dd/yyyy">US (06/15/2024)</option>
                    <option value="dd/MM/yyyy">EU (15/06/2024)</option>
                  </select>
                </Field>
              </div>
            )}
          </div>

          {/* Footer actions */}
          <div className="flex items-center justify-between">
            <button type="button" onClick={handleReset} className="px-4 py-2 text-xs font-semibold text-slate-400 hover:text-slate-200 border border-slate-700 hover:border-slate-600 rounded-lg transition-colors">
              Reset to Defaults
            </button>
            <button type="submit" className="flex items-center gap-2 px-5 py-2.5 bg-blue-600 hover:bg-blue-700 text-white text-sm font-semibold rounded-lg transition-colors">
              <Save className="w-4 h-4" /> Save Changes
              {hasChanges && <span className="w-1.5 h-1.5 rounded-full bg-yellow-400 ml-0.5" />}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
