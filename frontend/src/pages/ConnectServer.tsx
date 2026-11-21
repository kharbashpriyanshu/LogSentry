import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Server, Shield, Terminal, Copy, Check, Radio,
  Send, RefreshCw, Cpu, Flame, HardDrive, Laptop,
  Network,
} from 'lucide-react';
import { integrationService, type ConnectedServer } from '../services/integrationService';
import { StatCard } from '../components/ui';

export default function ConnectServer() {
  const queryClient = useQueryClient();
  const [activeTab, setActiveTab] = useState<'linux' | 'windows' | 'network' | 'cloud' | 'k8s'>('linux');
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  // Connection tester state
  const [testForm, setTestForm] = useState({
    server_name: 'corp-web-01.internal',
    server_ip: '192.168.10.45',
    platform: 'linux',
    parser: 'nginx',
  });
  const [testFeedback, setTestFeedback] = useState<any>(null);

  // Queries
  const { data: servers = [], isLoading: loadingServers, refetch } = useQuery<ConnectedServer[]>({
    queryKey: ['connected_servers'],
    queryFn: () => integrationService.getServers(),
    refetchInterval: 8000,
  });

  const { data: ingestionInfo } = useQuery({
    queryKey: ['ingestion_info'],
    queryFn: () => integrationService.getIngestionInfo(),
  });

  // Ping test mutation
  const pingMutation = useMutation({
    mutationFn: (payload: typeof testForm) => integrationService.testPing(payload),
    onSuccess: (data) => {
      setTestFeedback(data);
      queryClient.invalidateQueries({ queryKey: ['connected_servers'] });
      queryClient.invalidateQueries({ queryKey: ['dashboard_summary'] });
    },
    onError: (err: any) => {
      setTestFeedback({ status: 'error', message: err?.response?.data?.details || err.message });
    },
  });

  const handleCopy = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const streamingCount = servers.filter((s) => s.status === 'streaming').length;
  const totalEvents = servers.reduce((acc, s) => acc + s.total_events, 0);

  return (
    <div className="space-y-6 max-w-7xl mx-auto pb-12">
      {/* Page Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-[var(--border-subtle)]">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="p-1.5 rounded-lg bg-blue-500/10 text-blue-800 dark:text-blue-300 border border-blue-500/20">
              <Server className="w-5 h-5" />
            </span>
            <h1 className="text-2xl font-black tracking-tight text-[var(--text-primary)]">
              Enterprise Server Connectors
            </h1>
            <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[11px] font-semibold bg-emerald-500/10 text-emerald-800 dark:text-emerald-300 border border-emerald-500/20">
              <Radio className="w-3 h-3 animate-pulse text-emerald-800 dark:text-emerald-300" />
              Ingestion Gateway Live
            </span>
          </div>
          <p className="text-xs text-[var(--text-muted)]">
            Deploy shippers or stream agentless Syslog from any corporate Linux, Windows, Firewall, or Cloud server.
          </p>
        </div>

        <button
          onClick={() => refetch()}
          className="inline-flex items-center gap-2 px-3 py-1.5 rounded-lg border border-[var(--border-default)] bg-[var(--bg-card)] text-xs font-semibold text-[var(--text-secondary)] hover:bg-[var(--bg-card-hover)] transition-all shadow-xs shrink-0 cursor-pointer"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loadingServers ? 'animate-spin' : ''}`} />
          Refresh Nodes
        </button>
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          title="CONNECTED NODES"
          value={servers.length}
          subtitle="Corporate hosts registered"
          icon={<Server className="w-4 h-4 text-blue-800 dark:text-blue-300" />}
        />
        <StatCard
          title="ACTIVE STREAMING"
          value={streamingCount}
          subtitle="Real-time telemetry feeds"
          icon={<Radio className="w-4 h-4 text-emerald-800 dark:text-emerald-300" />}
        />
        <StatCard
          title="INGESTED EVENTS"
          value={totalEvents.toLocaleString()}
          subtitle="Raw logs parsed & analyzed"
          icon={<HardDrive className="w-4 h-4 text-purple-800 dark:text-purple-300" />}
        />
        <StatCard
          title="GATEWAY PROTOCOLS"
          value="4 Ingestion Modes"
          subtitle="Syslog, REST, Winlogbeat, SQS"
          icon={<Network className="w-4 h-4 text-amber-800 dark:text-amber-300" />}
        />
      </div>

      {/* Main Connection Guide & Instructions Tabs */}
      <div className="bg-[var(--bg-card)] border border-[var(--border-default)] rounded-xl overflow-hidden shadow-xs">
        <div className="p-5 border-b border-[var(--border-subtle)] bg-[var(--bg-card-subtle)]/50">
          <h2 className="text-sm font-bold text-[var(--text-primary)]">
            Select Company Infrastructure Type to Connect
          </h2>
          <p className="text-xs text-[var(--text-muted)] mt-0.5">
            Choose your corporate asset below to view 1-click installation commands, configuration files, and network ports.
          </p>

          {/* Platform Tabs */}
          <div className="flex flex-wrap gap-2 mt-4">
            {[
              { id: 'linux', label: 'Linux Servers (Ubuntu/RHEL)', icon: Terminal },
              { id: 'windows', label: 'Windows & Active Directory', icon: Laptop },
              { id: 'network', label: 'Firewalls & Network (Syslog)', icon: Flame },
              { id: 'cloud', label: 'AWS / Azure / GCP Cloud', icon: Shield },
              { id: 'k8s', label: 'Kubernetes & Docker', icon: Cpu },
            ].map((tab) => {
              const Icon = tab.icon;
              const isActive = activeTab === tab.id;
              return (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id as any)}
                  className={`inline-flex items-center gap-2 px-3.5 py-2 rounded-lg text-xs font-bold transition-all cursor-pointer ${
                    isActive
                      ? 'bg-blue-600 text-white shadow-xs'
                      : 'bg-[var(--bg-card)] border border-[var(--border-default)] text-[var(--text-secondary)] hover:bg-[var(--bg-card-hover)]'
                  }`}
                >
                  <Icon className="w-3.5 h-3.5" />
                  {tab.label}
                </button>
              );
            })}
          </div>
        </div>

        <div className="p-6">
          {/* TAB 1: LINUX */}
          {activeTab === 'linux' && (
            <div className="space-y-6">
              <div>
                <h3 className="text-sm font-extrabold text-[var(--text-primary)] mb-1 flex items-center gap-2">
                  <Terminal className="w-4 h-4 text-blue-800 dark:text-blue-300" />
                  Method 1: Native Rsyslog Remote Forwarding (Zero Software Install)
                </h3>
                <p className="text-xs text-[var(--text-muted)] mb-3">
                  Supported on Ubuntu, Debian, RHEL, CentOS, Fedora, SUSE. Drops into your existing system logging service.
                </p>
                <div className="relative">
                  <pre className="p-4 rounded-xl bg-slate-950 text-slate-100 text-xs font-mono overflow-x-auto border border-slate-800">
{`# 1. Create LogSentry remote forwarder rule:
cat << 'EOF' | sudo tee /etc/rsyslog.d/99-logsentry.conf
auth,authpriv.* action(type="omfwd" target="${window.location.hostname}" port="1514" protocol="tcp" template="RSYSLOG_SyslogProtocol23Format")
local6.* action(type="omfwd" target="${window.location.hostname}" port="1514" protocol="tcp" template="RSYSLOG_SyslogProtocol23Format")
EOF

# 2. Restart rsyslog to begin streaming
sudo systemctl restart rsyslog`}
                  </pre>
                  <button
                    onClick={() => handleCopy(`cat << 'EOF' | sudo tee /etc/rsyslog.d/99-logsentry.conf\nauth,authpriv.* action(type="omfwd" target="${window.location.hostname}" port="1514" protocol="tcp" template="RSYSLOG_SyslogProtocol23Format")\nlocal6.* action(type="omfwd" target="${window.location.hostname}" port="1514" protocol="tcp" template="RSYSLOG_SyslogProtocol23Format")\nEOF\nsudo systemctl restart rsyslog`, 'linux-rsyslog')}
                    className="absolute top-3 right-3 px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 text-[11px] font-semibold flex items-center gap-1.5 transition-colors cursor-pointer"
                  >
                    {copiedKey === 'linux-rsyslog' ? <Check className="w-3.5 h-3.5 text-emerald-800 dark:text-emerald-300" /> : <Copy className="w-3.5 h-3.5" />}
                    {copiedKey === 'linux-rsyslog' ? 'Copied' : 'Copy Command'}
                  </button>
                </div>
              </div>

              <div className="pt-4 border-t border-[var(--border-subtle)]">
                <h3 className="text-sm font-extrabold text-[var(--text-primary)] mb-1 flex items-center gap-2">
                  <Server className="w-4 h-4 text-emerald-800 dark:text-emerald-300" />
                  Method 2: Standalone LogSentry Universal Python Shipper
                </h3>
                <p className="text-xs text-[var(--text-muted)] mb-3">
                  Tails any file (`/var/log/nginx/access.log`, `/var/log/auth.log`) and streams JSON over HTTPS directly to the SIEM:
                </p>
                <div className="relative">
                  <pre className="p-4 rounded-xl bg-slate-950 text-slate-100 text-xs font-mono overflow-x-auto border border-slate-800">
{`# Run shipper in background as a daemon
python3 scripts/logsentry_shipper.py \\
  --file /var/log/nginx/access.log \\
  --parser nginx \\
  --server http://${window.location.hostname}:8000 \\
  --tenant-id corp-prod`}
                  </pre>
                  <button
                    onClick={() => handleCopy(`python3 scripts/logsentry_shipper.py --file /var/log/nginx/access.log --parser nginx --server http://${window.location.hostname}:8000 --tenant-id corp-prod`, 'linux-shipper')}
                    className="absolute top-3 right-3 px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 text-[11px] font-semibold flex items-center gap-1.5 transition-colors cursor-pointer"
                  >
                    {copiedKey === 'linux-shipper' ? <Check className="w-3.5 h-3.5 text-emerald-800 dark:text-emerald-300" /> : <Copy className="w-3.5 h-3.5" />}
                    {copiedKey === 'linux-shipper' ? 'Copied' : 'Copy Command'}
                  </button>
                </div>
              </div>
            </div>
          )}

          {/* TAB 2: WINDOWS */}
          {activeTab === 'windows' && (
            <div className="space-y-6">
              <div>
                <h3 className="text-sm font-extrabold text-[var(--text-primary)] mb-1 flex items-center gap-2">
                  <Laptop className="w-4 h-4 text-blue-800 dark:text-blue-300" />
                  Method 1: LogSentry Windows Host Agent (PowerShell Operational & EVTX)
                </h3>
                <p className="text-xs text-[var(--text-muted)] mb-3">
                  Run this on any Windows Server or workstation to stream Event ID 4104 (PowerShell) and 4624/4625 (Logons):
                </p>
                <div className="relative">
                  <pre className="p-4 rounded-xl bg-slate-950 text-slate-100 text-xs font-mono overflow-x-auto border border-slate-800">
{`# Start live host listener on your Windows server:
.\\venv\\Scripts\\python.exe scripts/laptop_agent.py --live-powershell`}
                  </pre>
                  <button
                    onClick={() => handleCopy(`.\\venv\\Scripts\\python.exe scripts/laptop_agent.py --live-powershell`, 'win-agent')}
                    className="absolute top-3 right-3 px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 text-[11px] font-semibold flex items-center gap-1.5 transition-colors cursor-pointer"
                  >
                    {copiedKey === 'win-agent' ? <Check className="w-3.5 h-3.5 text-emerald-800 dark:text-emerald-300" /> : <Copy className="w-3.5 h-3.5" />}
                    {copiedKey === 'win-agent' ? 'Copied' : 'Copy'}
                  </button>
                </div>
              </div>

              <div className="pt-4 border-t border-[var(--border-subtle)]">
                <h3 className="text-sm font-extrabold text-[var(--text-primary)] mb-1 flex items-center gap-2">
                  <Shield className="w-4 h-4 text-amber-800 dark:text-amber-300" />
                  Method 2: Elastic Winlogbeat Service (Active Directory Domain Controllers)
                </h3>
                <p className="text-xs text-[var(--text-muted)] mb-3">
                  Deploy `deploy/collectors/winlogbeat_logsentry.yml` via Group Policy to ship security event IDs (4624, 4625, 4688, 4720):
                </p>
                <div className="relative">
                  <pre className="p-4 rounded-xl bg-slate-950 text-slate-100 text-xs font-mono overflow-x-auto border border-slate-800">
{`# In C:\\Program Files\\Winlogbeat\\winlogbeat.yml:
output.http:
  enabled: true
  url: "http://${window.location.hostname}:8000/api/v1/detection/analyze"
  headers:
    Content-Type: "application/json"
    Authorization: "Bearer CORP_AD_INGEST_KEY"`}
                  </pre>
                  <button
                    onClick={() => handleCopy(`output.http:\n  enabled: true\n  url: "http://${window.location.hostname}:8000/api/v1/detection/analyze"\n  headers:\n    Content-Type: "application/json"\n    Authorization: "Bearer CORP_AD_INGEST_KEY"`, 'win-beat')}
                    className="absolute top-3 right-3 px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 text-[11px] font-semibold flex items-center gap-1.5 transition-colors cursor-pointer"
                  >
                    {copiedKey === 'win-beat' ? <Check className="w-3.5 h-3.5 text-emerald-800 dark:text-emerald-300" /> : <Copy className="w-3.5 h-3.5" />}
                    {copiedKey === 'win-beat' ? 'Copied' : 'Copy Config'}
                  </button>
                </div>
              </div>
            </div>
          )}

          {/* TAB 3: NETWORK & FIREWALL */}
          {activeTab === 'network' && (
            <div className="space-y-4">
              <h3 className="text-sm font-extrabold text-[var(--text-primary)] flex items-center gap-2">
                <Flame className="w-4 h-4 text-orange-800 dark:text-orange-300" />
                Agentless Syslog Forwarding (Firewalls, Switches & Routers)
              </h3>
              <p className="text-xs text-[var(--text-muted)]">
                Corporate security appliances transmit events using RFC 5424 / RFC 3164 Syslog over UDP/TCP port 1514.
              </p>

              <div className="grid md:grid-cols-2 gap-4 mt-2">
                <div className="p-4 rounded-xl bg-[var(--bg-card-subtle)] border border-[var(--border-subtle)]">
                  <h4 className="text-xs font-bold text-[var(--text-primary)] mb-1">Palo Alto Networks (PAN-OS)</h4>
                  <ol className="text-xs text-[var(--text-secondary)] space-y-1 list-decimal list-inside">
                    <li>Log in to PAN-OS Web Interface</li>
                    <li>Go to <strong>Device</strong> &gt; <strong>Server Profiles</strong> &gt; <strong>Syslog</strong></li>
                    <li>Add LogSentry IP: <code>{window.location.hostname}</code>, Port: <code>1514</code> (UDP/TCP)</li>
                    <li>Attach profile to <strong>Objects</strong> &gt; <strong>Log Forwarding</strong></li>
                  </ol>
                </div>

                <div className="p-4 rounded-xl bg-[var(--bg-card-subtle)] border border-[var(--border-subtle)]">
                  <h4 className="text-xs font-bold text-[var(--text-primary)] mb-1">Fortinet (FortiGate)</h4>
                  <pre className="p-2.5 rounded bg-slate-950 text-slate-200 text-[11px] font-mono mt-1">
{`config log syslogd setting
    set status enable
    set server "${window.location.hostname}"
    set port 1514
    set mode udp
end`}
                  </pre>
                </div>
              </div>
            </div>
          )}

          {/* TAB 4: CLOUD */}
          {activeTab === 'cloud' && (
            <div className="space-y-4">
              <h3 className="text-sm font-extrabold text-[var(--text-primary)] flex items-center gap-2">
                <Shield className="w-4 h-4 text-purple-800 dark:text-purple-300" />
                AWS CloudTrail & Multi-Cloud Ingestion
              </h3>
              <p className="text-xs text-[var(--text-muted)]">
                Stream CloudTrail audit events (unauthorized IAM policy changes, root login alerts) into LogSentry.
              </p>
              <div className="p-4 rounded-xl bg-[var(--bg-card-subtle)] border border-[var(--border-subtle)] space-y-2">
                <p className="text-xs text-[var(--text-secondary)]">
                  1. Configure CloudTrail to deliver logs to an S3 bucket: <code>s3://corp-cloudtrail-audit/</code>
                </p>
                <p className="text-xs text-[var(--text-secondary)]">
                  2. Create an AWS Lambda function triggered on S3 <code>ObjectCreated</code> to POST JSON batches to:
                </p>
                <code className="block p-3 rounded-lg bg-slate-950 text-slate-100 text-xs font-mono">
                  POST http://{window.location.hostname}:8000/api/v1/detection/analyze
                </code>
              </div>
            </div>
          )}

          {/* TAB 5: KUBERNETES */}
          {activeTab === 'k8s' && (
            <div className="space-y-4">
              <h3 className="text-sm font-extrabold text-[var(--text-primary)] flex items-center gap-2">
                <Cpu className="w-4 h-4 text-cyan-800 dark:text-cyan-300" />
                Kubernetes & Container Ingestion (FluentBit DaemonSet)
              </h3>
              <p className="text-xs text-[var(--text-muted)]">
                Deploy FluentBit across all worker nodes to stream pod logs automatically.
              </p>
              <div className="relative">
                <pre className="p-4 rounded-xl bg-slate-950 text-slate-100 text-xs font-mono overflow-x-auto border border-slate-800">
{`[OUTPUT]
    Name          http
    Match         kube.*
    Host          ${window.location.hostname}
    Port          8000
    URI           /api/v1/detection/analyze
    Header        Authorization Bearer K8S_CLUSTER_INGEST_KEY
    Format        json`}
                </pre>
                <button
                  onClick={() => handleCopy(`[OUTPUT]\n    Name          http\n    Match         kube.*\n    Host          ${window.location.hostname}\n    Port          8000\n    URI           /api/v1/detection/analyze\n    Format        json`, 'k8s-fluentbit')}
                  className="absolute top-3 right-3 px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 text-[11px] font-semibold flex items-center gap-1.5 transition-colors cursor-pointer"
                >
                  {copiedKey === 'k8s-fluentbit' ? <Check className="w-3.5 h-3.5 text-emerald-800 dark:text-emerald-300" /> : <Copy className="w-3.5 h-3.5" />}
                  {copiedKey === 'k8s-fluentbit' ? 'Copied' : 'Copy'}
                </button>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Interactive Server Connection Tester */}
      <div className="bg-[var(--bg-card)] border border-[var(--border-default)] rounded-xl p-6 shadow-xs">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h2 className="text-sm font-bold text-[var(--text-primary)] flex items-center gap-2">
              <Send className="w-4 h-4 text-blue-800 dark:text-blue-300" />
              Live Server Connection & Probe Tester
            </h2>
            <p className="text-xs text-[var(--text-muted)] mt-0.5">
              Simulate or verify an initial handshake from a corporate server to confirm pipeline ingestion.
            </p>
          </div>
          <span className="text-[11px] font-mono text-[var(--text-muted)]">
            Endpoint: {ingestionInfo?.api_endpoint || 'http://localhost:8000/api/v1/detection/analyze'}
          </span>
        </div>

        <div className="grid md:grid-cols-4 gap-3">
          <div>
            <label className="block text-[11px] font-bold text-[var(--text-secondary)] mb-1">Company Server Name</label>
            <input
              type="text"
              value={testForm.server_name}
              onChange={(e) => setTestForm({ ...testForm, server_name: e.target.value })}
              className="w-full px-3 py-2 rounded-lg bg-[var(--bg-input)] border border-[var(--border-default)] text-xs text-[var(--text-primary)] font-mono focus:outline-hidden focus:ring-1 focus:ring-blue-500"
              placeholder="e.g. prod-auth-01.corp"
            />
          </div>

          <div>
            <label className="block text-[11px] font-bold text-[var(--text-secondary)] mb-1">Server IPv4/IPv6</label>
            <input
              type="text"
              value={testForm.server_ip}
              onChange={(e) => setTestForm({ ...testForm, server_ip: e.target.value })}
              className="w-full px-3 py-2 rounded-lg bg-[var(--bg-input)] border border-[var(--border-default)] text-xs text-[var(--text-primary)] font-mono focus:outline-hidden focus:ring-1 focus:ring-blue-500"
              placeholder="e.g. 10.0.5.21"
            />
          </div>

          <div>
            <label className="block text-[11px] font-bold text-[var(--text-secondary)] mb-1">Operating System</label>
            <select
              value={testForm.platform}
              onChange={(e) => setTestForm({ ...testForm, platform: e.target.value })}
              className="w-full px-3 py-2 rounded-lg bg-[var(--bg-input)] border border-[var(--border-default)] text-xs text-[var(--text-primary)] focus:outline-hidden"
            >
              <option value="linux">Linux Server (Ubuntu / RHEL)</option>
              <option value="windows">Windows Server / Active Directory</option>
              <option value="network">Firewall / Router (Palo Alto, Cisco)</option>
              <option value="cloud">Cloud (AWS / Azure / GCP)</option>
              <option value="k8s">Kubernetes / Containers</option>
            </select>
          </div>

          <div>
            <label className="block text-[11px] font-bold text-[var(--text-secondary)] mb-1">Parser Format</label>
            <select
              value={testForm.parser}
              onChange={(e) => setTestForm({ ...testForm, parser: e.target.value })}
              className="w-full px-3 py-2 rounded-lg bg-[var(--bg-input)] border border-[var(--border-default)] text-xs text-[var(--text-primary)] focus:outline-hidden"
            >
              <option value="nginx">Nginx Access Log</option>
              <option value="apache">Apache Web Log</option>
              <option value="linux_auth">Linux Auth (SSH / Sudo)</option>
              <option value="windows_event">Windows Event Log (EVTX)</option>
              <option value="cloudtrail">AWS CloudTrail</option>
            </select>
          </div>
        </div>

        <div className="mt-4 flex items-center justify-between">
          <p className="text-[11px] text-[var(--text-muted)]">
            Clicking verify injects a handshake probe and tests detection engine compatibility.
          </p>
          <button
            onClick={() => pingMutation.mutate(testForm)}
            disabled={pingMutation.isPending}
            className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-700 text-white text-xs font-bold transition-all shadow-xs disabled:opacity-50 cursor-pointer"
          >
            <Send className={`w-3.5 h-3.5 ${pingMutation.isPending ? 'animate-bounce' : ''}`} />
            {pingMutation.isPending ? 'Sending Handshake...' : 'Send Verification Probe'}
          </button>
        </div>

        {/* Feedback Alert */}
        {testFeedback && (
          <div className={`mt-4 p-3.5 rounded-xl border text-xs flex items-center justify-between ${
            testFeedback.status === 'connected'
              ? 'bg-emerald-500/10 border-emerald-500/20 text-emerald-800 dark:text-emerald-300'
              : 'bg-red-500/10 border-red-500/20 text-red-800 dark:text-red-300'
          }`}>
            <div className="flex items-center gap-2">
              <Check className="w-4 h-4 shrink-0" />
              <span>{testFeedback.message}</span>
            </div>
            <span className="font-mono text-[11px] opacity-80">{testFeedback.timestamp}</span>
          </div>
        )}
      </div>

      {/* Live Connected Enterprise Servers Inventory */}
      <div className="bg-[var(--bg-card)] border border-[var(--border-default)] rounded-xl overflow-hidden shadow-xs">
        <div className="p-5 border-b border-[var(--border-subtle)] flex items-center justify-between">
          <div>
            <h2 className="text-sm font-bold text-[var(--text-primary)] flex items-center gap-2">
              <Server className="w-4 h-4 text-blue-800 dark:text-blue-300" />
              Connected Enterprise Server Inventory
            </h2>
            <p className="text-xs text-[var(--text-muted)] mt-0.5">
              Live inventory of all corporate nodes streaming into this LogSentry SIEM cluster.
            </p>
          </div>
          <span className="text-xs font-bold text-[var(--text-secondary)] px-2.5 py-1 rounded-lg bg-[var(--bg-card-subtle)] border border-[var(--border-subtle)]">
            {servers.length} Registered Nodes
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="border-b border-[var(--border-subtle)] bg-[var(--bg-card-subtle)]/50 text-[11px] font-bold text-[var(--text-muted)] uppercase tracking-wider">
                <th className="py-3 px-4">Hostname / Node</th>
                <th className="py-3 px-4">IPv4 Address</th>
                <th className="py-3 px-4">Platform</th>
                <th className="py-3 px-4">Parser Engine</th>
                <th className="py-3 px-4 text-right">Events Ingested</th>
                <th className="py-3 px-4">Last Telemetry</th>
                <th className="py-3 px-4 text-center">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[var(--border-subtle)]">
              {servers.slice(0, 15).map((srv) => (
                <tr key={srv.id} className="hover:bg-[var(--bg-card-hover)] transition-colors">
                  <td className="py-3 px-4 font-mono font-bold text-[var(--text-primary)] flex items-center gap-2">
                    <Server className="w-3.5 h-3.5 text-[var(--text-muted)]" />
                    {srv.hostname}
                  </td>
                  <td className="py-3 px-4 font-mono text-[var(--text-secondary)]">{srv.ip}</td>
                  <td className="py-3 px-4">
                    <span className="capitalize px-2 py-0.5 rounded text-[10px] font-semibold bg-[var(--bg-card-subtle)] border border-[var(--border-subtle)] text-[var(--text-secondary)]">
                      {srv.platform}
                    </span>
                  </td>
                  <td className="py-3 px-4 font-mono text-[11px] text-[var(--text-muted)]">{srv.parser}</td>
                  <td className="py-3 px-4 text-right font-mono font-bold text-[var(--text-primary)]">
                    {srv.total_events.toLocaleString()}
                  </td>
                  <td className="py-3 px-4 text-[11px] text-[var(--text-muted)]">
                    {new Date(srv.last_seen).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                  </td>
                  <td className="py-3 px-4 text-center">
                    {srv.status === 'streaming' ? (
                      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-bold bg-emerald-500/10 text-emerald-800 dark:text-emerald-300 border border-emerald-500/20">
                        <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-ping" />
                        Streaming
                      </span>
                    ) : (
                      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-medium bg-slate-500/10 text-slate-800 dark:text-slate-300 border border-slate-500/20">
                        Idle
                      </span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
