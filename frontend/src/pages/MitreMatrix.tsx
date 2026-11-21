import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import {
  ShieldAlert, Target, Sparkles, Filter, AlertTriangle,
  RefreshCw, CheckCircle2,
} from 'lucide-react';
import { alertService } from '../services/alertService';
import { StatCard } from '../components/ui';

interface MitreTechnique {
  id: string;
  name: string;
  tactic: string;
  ruleName?: string;
  description: string;
}

const MITRE_TACTICS: Array<{ id: string; name: string; techniques: MitreTechnique[] }> = [
  {
    id: 'initial-access',
    name: 'Initial Access',
    techniques: [
      { id: 'T1190', name: 'Exploit Public-Facing Application', tactic: 'Initial Access', ruleName: 'Log4Shell / Spring4Shell / SQLi', description: 'Exploiting internet-exposed web servers and API gateways.' },
      { id: 'T1078', name: 'Valid Accounts', tactic: 'Initial Access', ruleName: 'Linux Auth / Sudo', description: 'Adversaries obtaining and abusing existing credentials.' },
      { id: 'T1133', name: 'External Remote Services', tactic: 'Initial Access', ruleName: 'SSH Brute Force', description: 'Attacking exposed RDP or SSH bastion gateways.' },
    ],
  },
  {
    id: 'execution',
    name: 'Execution',
    techniques: [
      { id: 'T1059.001', name: 'PowerShell Execution', tactic: 'Execution', ruleName: 'Sigma: PowerShell Cradle', description: 'Execution of encoded or download cradle PowerShell scripts.' },
      { id: 'T1059', name: 'Command & Scripting Interpreter', tactic: 'Execution', ruleName: 'OS Command Injection', description: 'Abusing command shells (sh, bash, cmd.exe) to execute commands.' },
      { id: 'T1204', name: 'User Execution', tactic: 'Execution', ruleName: 'Web Probe & Clickjack', description: 'Tricking victims into executing malicious payloads.' },
    ],
  },
  {
    id: 'persistence',
    name: 'Persistence',
    techniques: [
      { id: 'T1505', name: 'Server Software Component', tactic: 'Persistence', ruleName: 'Webshell / File Upload', description: 'Backdoors planted on application servers or web roots.' },
      { id: 'T1136', name: 'Create Account', tactic: 'Persistence', ruleName: 'Win Event 4720', description: 'Creating rogue admin accounts for persistent access.' },
      { id: 'T1078.001', name: 'Default Accounts', tactic: 'Persistence', ruleName: 'Admin Probe', description: 'Exploiting default application credentials.' },
    ],
  },
  {
    id: 'privilege-escalation',
    name: 'Privilege Escalation',
    techniques: [
      { id: 'T1548', name: 'Abuse Elevation Control', tactic: 'Privilege Escalation', ruleName: 'Sudo Abuse', description: 'Circumventing mechanisms designed to control elevated privileges.' },
      { id: 'T1068', name: 'Exploitation for Privilege Escalation', tactic: 'Privilege Escalation', ruleName: 'Kernel / Service Exploit', description: 'Leveraging software vulnerabilities to elevate to SYSTEM or root.' },
    ],
  },
  {
    id: 'defense-evasion',
    name: 'Defense Evasion',
    techniques: [
      { id: 'T1070', name: 'Indicator Removal on Host', tactic: 'Defense Evasion', ruleName: 'Win Event 1102 / Log Clearing', description: 'Clearing security audit trails or tampering with log daemons.' },
      { id: 'T1027', name: 'Obfuscated Files or Information', tactic: 'Defense Evasion', ruleName: 'Encoded Commands', description: 'Encoding payloads in Base64 or XOR to evade signature filters.' },
      { id: 'T1036', name: 'Masquerading', tactic: 'Defense Evasion', ruleName: 'Process Rename', description: 'Disguising malicious binaries as legitimate system files.' },
    ],
  },
  {
    id: 'credential-access',
    name: 'Credential Access',
    techniques: [
      { id: 'T1110', name: 'Brute Force', tactic: 'Credential Access', ruleName: 'SSH / HTTP Auth Brute Force', description: 'Repeatedly guessing passwords against exposed authentication endpoints.' },
      { id: 'T1552', name: 'Unsecured Credentials', tactic: 'Credential Access', ruleName: 'Config Exposure / .git / .env', description: 'Scanning public directories for hardcoded API keys or passwords.' },
      { id: 'T1003', name: 'OS Credential Dumping', tactic: 'Credential Access', ruleName: 'LSASS / Shadow File', description: 'Dumping password hashes or Kerberos tickets from memory.' },
    ],
  },
  {
    id: 'discovery',
    name: 'Discovery',
    techniques: [
      { id: 'T1595', name: 'Active Scanning', tactic: 'Discovery', ruleName: 'Sigma: WordPress Admin Probe', description: 'Probing web servers for administrative endpoints and exposed files.' },
      { id: 'T1087', name: 'Account Discovery', tactic: 'Discovery', ruleName: 'User Enumeration', description: 'Surveying user lists to discover privileged identity targets.' },
    ],
  },
  {
    id: 'command-and-control',
    name: 'Command & Control',
    techniques: [
      { id: 'T1071', name: 'Application Layer Protocol', tactic: 'Command & Control', ruleName: 'C2 HTTP Beaconing', description: 'Blended beaconing traffic over HTTP/HTTPS to external controllers.' },
      { id: 'T1105', name: 'Ingress Tool Transfer', tactic: 'Command & Control', ruleName: 'Net.WebClient Download', description: 'Downloading second-stage malicious payloads from the internet.' },
    ],
  },
];

export default function MitreMatrix() {
  const [selectedTechnique, setSelectedTechnique] = useState<MitreTechnique | null>(null);
  const [filterQuery, setFilterQuery] = useState('');

  // Fetch live alerts to map triggers to techniques
  const { data: alerts = [], isLoading, refetch } = useQuery({
    queryKey: ['alerts_mitre'],
    queryFn: () => alertService.getAlerts(),
    refetchInterval: 10000,
  });

  // Count alerts per technique ID safely
  const techniqueHits: Record<string, number> = {};
  const alertList = Array.isArray(alerts) ? alerts : [];
  alertList.forEach((a: any) => {
    const tech = a?.mitre_technique;
    if (tech && typeof tech === 'string') {
      techniqueHits[tech] = (techniqueHits[tech] || 0) + 1;
      // also match base tech (e.g. T1059.001 -> T1059)
      const base = tech.split('.')[0];
      if (base && base !== tech) {
        techniqueHits[base] = (techniqueHits[base] || 0) + 1;
      }
    }
  });

  const totalTechniques = MITRE_TACTICS.reduce((acc, t) => acc + t.techniques.length, 0);
  const triggeredTechniquesCount = Object.keys(techniqueHits).length;

  return (
    <div className="space-y-6 max-w-7xl mx-auto pb-12">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-[var(--border-subtle)]">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="p-1.5 rounded-lg bg-orange-500/10 text-orange-800 dark:text-orange-300 border border-orange-500/20">
              <Target className="w-5 h-5" />
            </span>
            <h1 className="text-2xl font-black tracking-tight text-[var(--text-primary)]">
              MITRE ATT&CK Matrix Navigator
            </h1>
            <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[11px] font-semibold bg-emerald-500/10 text-emerald-800 dark:text-emerald-300 border border-emerald-500/20">
              <CheckCircle2 className="w-3.5 h-3.5 text-emerald-800 dark:text-emerald-300" />
              Enterprise v15 Matrix
            </span>
          </div>
          <p className="text-xs text-[var(--text-muted)]">
            Visual kill-chain mapping adversary tactics, detection rule coverage, and live triggered telemetry.
          </p>
        </div>

        <button
          onClick={() => refetch()}
          className="inline-flex items-center gap-2 px-3 py-1.5 rounded-lg border border-[var(--border-default)] bg-[var(--bg-card)] text-xs font-semibold text-[var(--text-secondary)] hover:bg-[var(--bg-card-hover)] transition-all shadow-xs shrink-0 cursor-pointer"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin' : ''}`} />
          Refresh Coverage
        </button>
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          title="TACTICS COVERED"
          value="8 Tactics"
          subtitle="Enterprise Kill-Chain"
          icon={<Target className="w-4 h-4 text-blue-800 dark:text-blue-300" />}
        />
        <StatCard
          title="ACTIVE TECHNIQUES"
          value={totalTechniques}
          subtitle="Enforced by SIEM rules"
          icon={<CheckCircle2 className="w-4 h-4 text-emerald-800 dark:text-emerald-300" />}
        />
        <StatCard
          title="TRIGGERED IN REAL-TIME"
          value={triggeredTechniquesCount}
          subtitle="Active adversaries flagged"
          icon={<ShieldAlert className="w-4 h-4 text-red-800 dark:text-red-300" />}
        />
        <StatCard
          title="DETECTION RATIO"
          value="100% Coverage"
          subtitle="Sigma + Native heuristics"
          icon={<Sparkles className="w-4 h-4 text-purple-800 dark:text-purple-300" />}
        />
      </div>

      {/* Search / Filter Bar */}
      <div className="flex items-center gap-3 bg-[var(--bg-card)] p-3 rounded-xl border border-[var(--border-default)] shadow-xs">
        <Filter className="w-4 h-4 text-[var(--text-muted)] ml-2" />
        <input
          type="text"
          value={filterQuery}
          onChange={(e) => setFilterQuery(e.target.value)}
          placeholder="Filter matrix techniques by ID, name, or attack type (e.g. T1059, PowerShell, Brute Force)..."
          className="w-full bg-transparent text-xs text-[var(--text-primary)] placeholder-[var(--text-muted)] focus:outline-hidden"
        />
        {filterQuery && (
          <button onClick={() => setFilterQuery('')} className="text-xs text-[var(--text-muted)] hover:text-[var(--text-primary)] mr-2 cursor-pointer">
            Clear
          </button>
        )}
      </div>

      {/* Interactive MITRE ATT&CK Grid */}
      <div className="bg-[var(--bg-card)] border border-[var(--border-default)] rounded-xl p-6 shadow-xs overflow-x-auto">
        <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-8 gap-3 min-w-[1000px]">
          {MITRE_TACTICS.map((tactic) => {
            const filteredTechniques = tactic.techniques.filter((t) =>
              t.name.toLowerCase().includes(filterQuery.toLowerCase()) ||
              t.id.toLowerCase().includes(filterQuery.toLowerCase())
            );

            return (
              <div key={tactic.id} className="flex flex-col gap-2">
                <div className="p-2.5 rounded-lg bg-[var(--bg-card-subtle)] border border-[var(--border-subtle)] text-center">
                  <h3 className="text-[11px] font-black uppercase tracking-tight text-[var(--text-primary)] truncate">
                    {tactic.name}
                  </h3>
                  <span className="text-[10px] text-[var(--text-muted)] font-mono">
                    {filteredTechniques.length} rules
                  </span>
                </div>

                <div className="space-y-2">
                  {filteredTechniques.map((tech) => {
                    const hits = techniqueHits[tech.id] || 0;
                    const isSelected = selectedTechnique?.id === tech.id;
                    const isHot = hits > 0;

                    return (
                      <button
                        key={tech.id}
                        onClick={() => setSelectedTechnique(tech)}
                        className={`w-full text-left p-2.5 rounded-lg border transition-all cursor-pointer relative group ${
                          isSelected
                            ? 'ring-2 ring-blue-500 bg-blue-500/10 border-blue-500/30'
                            : isHot
                            ? 'bg-red-500/10 border-red-500/30 hover:bg-red-500/15'
                            : 'bg-[var(--bg-card)] border-[var(--border-default)] hover:border-emerald-500/50 hover:bg-[var(--bg-card-hover)]'
                        }`}
                      >
                        <div className="flex items-center justify-between gap-1 mb-1">
                          <span className="font-mono text-[10px] font-bold text-[var(--text-muted)] group-hover:text-blue-500">
                            {tech.id}
                          </span>
                          {isHot ? (
                            <span className="px-1.5 py-0.2 rounded-full text-[9px] font-black bg-red-600 text-white animate-pulse">
                              {hits} alerts
                            </span>
                          ) : (
                            <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" title="Active Rule Coverage" />
                          )}
                        </div>
                        <p className="text-[11px] font-semibold text-[var(--text-primary)] line-clamp-2 leading-snug">
                          {tech.name}
                        </p>
                      </button>
                    );
                  })}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Detail Drawer / Modal for Selected Technique */}
      {selectedTechnique && (
        <div className="bg-[var(--bg-card)] border border-blue-500/30 rounded-xl p-6 shadow-sm">
          <div className="flex items-start justify-between gap-4">
            <div>
              <div className="flex items-center gap-2 mb-1">
                <span className="px-2 py-0.5 rounded text-xs font-mono font-bold bg-blue-500/15 text-blue-800 dark:text-blue-300 border border-blue-500/30">
                  {selectedTechnique.id}
                </span>
                <span className="text-xs font-semibold text-[var(--text-muted)]">
                  Tactic: {selectedTechnique.tactic}
                </span>
              </div>
              <h2 className="text-lg font-black text-[var(--text-primary)]">
                {selectedTechnique.name}
              </h2>
              <p className="text-xs text-[var(--text-secondary)] mt-1 max-w-3xl">
                {selectedTechnique.description}
              </p>
            </div>

            <button
              onClick={() => setSelectedTechnique(null)}
              className="text-xs text-[var(--text-muted)] hover:text-[var(--text-primary)] p-1 cursor-pointer"
            >
              ✕ Close
            </button>
          </div>

          <div className="grid md:grid-cols-2 gap-4 mt-5 pt-4 border-t border-[var(--border-subtle)]">
            <div className="p-3.5 rounded-xl bg-[var(--bg-card-subtle)] border border-[var(--border-subtle)]">
              <h4 className="text-xs font-bold text-[var(--text-primary)] mb-1 flex items-center gap-1.5">
                <ShieldAlert className="w-3.5 h-3.5 text-blue-500" />
                Active SIEM Rule Enforcement
              </h4>
              <p className="text-xs font-mono text-[var(--text-secondary)]">
                Rule: {selectedTechnique.ruleName || 'Heuristic & Regex Rule'}
              </p>
              <p className="text-[11px] text-[var(--text-muted)] mt-1">
                Standard: Sigma Universal YAML + Regex Heuristics
              </p>
            </div>

            <div className="p-3.5 rounded-xl bg-[var(--bg-card-subtle)] border border-[var(--border-subtle)]">
              <h4 className="text-xs font-bold text-[var(--text-primary)] mb-1 flex items-center gap-1.5">
                <AlertTriangle className="w-3.5 h-3.5 text-amber-500" />
                Live Detections in Environment
              </h4>
              <p className="text-xs font-mono font-bold text-red-500">
                {techniqueHits[selectedTechnique.id] || 0} Detections Triggered
              </p>
              <p className="text-[11px] text-[var(--text-muted)] mt-1">
                Captured by telemetry ingestion pipeline
              </p>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
