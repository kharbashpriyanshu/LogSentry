import { useState, useEffect } from 'react';
import { useQuery } from '@tanstack/react-query';
import { healthService } from '../services/healthService';
import { aiService } from '../services/aiService';
import { threatIntelService } from '../services/threatIntelService';
import { HealthCard, MetricBar, ChartCard, AnimatedCounter } from '../components/ui';
import { Activity, RefreshCw, Shield, Cpu, Clock, ArrowUpRight, AlertOctagon, Network, Database, HardDrive, Server } from 'lucide-react';
export default function SystemHealth() {
  const [metrics] = useState({
    cpu: null as number | null,
    memory: null as number | null,
    disk: null as number | null,
    network: null as number | null,
    latency: null as number | null,
    requestCount: null as number | null,
    errorRate: null as number | null,
  });

  const { data: coreHealth, isLoading: coreLoading, refetch: refetchCore } = useQuery({
    queryKey: ['health-core'], queryFn: healthService.getBackendHealth, refetchInterval: 30_000,
  });
  const { data: aiHealth, isLoading: aiLoading } = useQuery({
    queryKey: ['health-ai'], queryFn: aiService.checkHealth, refetchInterval: 30_000,
  });
  const { data: threatHealth, isLoading: threatLoading } = useQuery({
    queryKey: ['health-threat'], queryFn: threatIntelService.getHealth, refetchInterval: 30_000,
  });
  const { data: backendMetrics } = useQuery({
    queryKey: ['metrics'], queryFn: healthService.getMetrics, refetchInterval: 10_000,
  });

  const isHealthy = (v: any) => v && (v.healthy === true || v.status === 'healthy');

  const getStatus = (loading: boolean, data: any): 'healthy' | 'degraded' | 'down' | 'unknown' => {
    if (loading) return 'unknown';
    if (!data) return 'down';
    return isHealthy(data) ? 'healthy' : 'degraded';
  };

  const coreStatus = getStatus(coreLoading, coreHealth);
  const aiStatus = getStatus(aiLoading, aiHealth);
  const threatStatus = getStatus(threatLoading, threatHealth);

  // Sub-system cards derived from health data
  const subsystems = [
    { name: 'API Gateway', status: coreStatus, metric: backendMetrics ? `${Math.round(backendMetrics.average_latency_seconds * 1000)}ms` : 'Unavailable', detail: 'Avg response latency', uptime: null },
    { name: 'Detection Engine', status: coreHealth?.subsystems?.detection_rules ? 'healthy' as const : 'degraded' as const, metric: `${coreHealth?.detection_rules_available ?? '–'} rules`, detail: 'Active detection rules', uptime: null },
    { name: 'Log Parsers', status: coreHealth?.subsystems?.parsers ? 'healthy' as const : 'degraded' as const, metric: `${coreHealth?.parsers_available ?? '–'} parsers`, detail: 'Registered log parsers', uptime: null },
    { name: 'AI SOC Analyst', status: aiStatus, metric: (aiHealth as any)?.provider || 'N/A', detail: aiStatus === 'healthy' ? 'Provider online' : 'Configure API key', uptime: null },
    { name: 'Threat Intelligence', status: threatStatus, metric: threatStatus === 'healthy' ? 'All feeds active' : 'Feeds degraded', detail: 'AbuseIPDB · OTX · MITRE', uptime: null },
    { name: 'Reporting Engine', status: coreStatus, metric: coreStatus === 'healthy' ? 'Ready' : 'Unavailable', detail: 'PDF · CSV · JSON export', uptime: null },
    { name: 'Cache Layer', status: coreStatus, metric: 'Unavailable', detail: 'In-process query cache', uptime: null },
    { name: 'Enrichment Service', status: coreStatus, metric: '3 providers', detail: 'IP and domain enrichment', uptime: null },
  ];

  const allHealthy = subsystems.every(s => s.status === 'healthy');
  const degraded   = subsystems.filter(s => s.status === 'degraded').length;
  const down       = subsystems.filter(s => s.status === 'down').length;

  return (
    <div className="space-y-5 animate-fade-in">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <Activity className="w-5 h-5 text-green-400" /> System Health Monitor
          </h1>
          <p className="text-xs text-slate-500 mt-0.5">
            Status: <span className={coreStatus === 'healthy' ? 'text-green-400 font-semibold' : 'text-yellow-400 font-semibold'}>{coreStatus === 'healthy' ? 'Operational' : 'Checking…'}</span> · Auto-refreshing every 30s
          </p>
        </div>
        <button onClick={() => refetchCore()} className="flex items-center gap-1.5 px-3 py-2 bg-slate-800 border border-slate-700 text-slate-400 hover:text-slate-200 hover:bg-slate-700 rounded-lg text-xs font-semibold transition-colors">
          <RefreshCw className="w-3.5 h-3.5" /> Refresh
        </button>
      </div>

      {/* Overall status banner */}
      <div className={`p-4 rounded-xl border flex items-center gap-3 ${allHealthy ? 'bg-green-500/8 border-green-500/20' : down > 0 ? 'bg-red-500/8 border-red-500/20' : 'bg-yellow-500/8 border-yellow-500/20'}`}>
        <Shield className={`w-5 h-5 shrink-0 ${allHealthy ? 'text-green-400' : down > 0 ? 'text-red-400' : 'text-yellow-400'}`} />
        <div>
          <p className={`text-sm font-bold ${allHealthy ? 'text-green-300' : down > 0 ? 'text-red-300' : 'text-yellow-300'}`}>
            {allHealthy ? 'All Systems Operational' : down > 0 ? `${down} System${down > 1 ? 's' : ''} Down` : `${degraded} System${degraded > 1 ? 's' : ''} Degraded`}
          </p>
          <p className="text-xs text-slate-500 mt-0.5">
            {subsystems.filter(s => s.status === 'healthy').length}/{subsystems.length} subsystems healthy
          </p>
        </div>
        <div className="ml-auto flex items-center gap-4">
          <div className="text-center">
            <p className="text-lg font-extrabold text-slate-300">Unavailable</p>
            <p className="text-[10px] text-slate-500 uppercase tracking-widest font-bold">Uptime %</p>
          </div>
          <div className="text-center">
            <p className="text-lg font-extrabold text-blue-400">{backendMetrics ? <AnimatedCounter value={backendMetrics.requests_total} /> : <span className="text-sm text-slate-500">Unavailable</span>}</p>
            <p className="text-[10px] text-slate-500 uppercase tracking-widest font-bold">Requests</p>
          </div>
          <div className="text-center">
            <p className="text-lg font-extrabold text-slate-500 text-sm">Unavailable</p>
            <p className="text-[10px] text-slate-500 uppercase tracking-widest font-bold">Error Rate</p>
          </div>
        </div>
      </div>

      {/* System metrics */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <ChartCard title="System Resources" subtitle="Real-time infrastructure metrics">
          <div className="space-y-5">
            <MetricBar label="CPU Usage" value={metrics.cpu ?? 0} unit="%" color="bg-slate-600" />
            <MetricBar label="Memory" value={metrics.memory ?? 0} unit="%" color="bg-slate-600" />
            <MetricBar label="Disk I/O" value={metrics.disk ?? 0} unit="%" color="bg-slate-600" />
            <MetricBar label="Network Traffic" value={metrics.network ?? 0} unit="%" color="bg-slate-600" />
          </div>
        </ChartCard>

        <ChartCard title="API Performance" subtitle="Request and response metrics">
          <div className="space-y-4">
            {[
              { icon: <Clock className="w-4 h-4 text-blue-400" />, label: 'Avg Latency', value: backendMetrics ? Math.round(backendMetrics.average_latency_seconds * 1000) : null, unit: 'ms', sub: 'Per request' },
              { icon: <ArrowUpRight className="w-4 h-4 text-green-400" />, label: 'Request Rate', value: null, unit: '/s', sub: 'Last 24 hours' },
              { icon: <AlertOctagon className="w-4 h-4 text-red-400" />, label: 'Error Rate', value: null, unit: '%', sub: '5xx responses' },
              { icon: <Cpu className="w-4 h-4 text-purple-400" />, label: 'Total Requests', value: backendMetrics ? backendMetrics.requests_total : null, unit: '', sub: 'Since restart' },
            ].map(item => (
              <div key={item.label} className="flex items-center gap-3 p-3 bg-slate-800/40 rounded-xl border border-slate-700/40">
                <div className="p-2 bg-slate-900/60 rounded-lg shrink-0">{item.icon}</div>
                <div className="flex-1">
                  <p className="text-[10px] text-slate-500 uppercase font-bold">{item.label}</p>
                  <p className="text-sm text-slate-500">{item.sub}</p>
                </div>
                <p className="text-xl font-extrabold text-slate-100 flex items-baseline gap-0.5">
                  {item.value !== null ? <AnimatedCounter value={item.value} /> : <span className="text-sm text-slate-500">Unavailable</span>}
                  {item.value !== null && <span className="text-sm text-slate-500 font-bold">{item.unit}</span>}
                </p>
              </div>
            ))}
          </div>
        </ChartCard>
      </div>

      {/* Subsystem grid */}
      <div>
        <h2 className="text-xs font-bold text-slate-500 uppercase tracking-widest mb-3">Subsystem Status</h2>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
          {subsystems.map(s => (
            <HealthCard key={s.name} name={s.name} status={s.status} metric={s.metric} detail={s.detail} uptime={s.uptime} />
          ))}
        </div>
      </div>

      {/* Version info */}
      <div className="bg-[#1e293b] border border-slate-700/80 rounded-xl p-5">
        <h2 className="text-xs font-bold text-slate-500 uppercase tracking-widest mb-4">Environment Information</h2>
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          {[
            { label: 'Version', val: coreHealth?.version || '1.0.0' },
            { label: 'Environment', val: coreHealth?.environment || 'development' },
            { label: 'Parsers', val: `${coreHealth?.parsers_available ?? '–'} loaded` },
            { label: 'Detection Rules', val: `${coreHealth?.detection_rules_available ?? '–'} active` },
          ].map(item => (
            <div key={item.label} className="p-3 bg-slate-800/40 rounded-xl border border-slate-700/40">
              <p className="text-[10px] text-slate-500 uppercase font-bold">{item.label}</p>
              <p className="text-sm font-semibold text-slate-200 mt-1 capitalize">{item.val}</p>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
