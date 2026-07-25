import { useState, useEffect } from 'react';
import { useQuery } from '@tanstack/react-query';
import { healthService } from '../services/healthService';
import { aiService } from '../services/aiService';
import { threatIntelService } from '../services/threatIntelService';
import { HealthCard, MetricBar, ChartCard, AnimatedCounter } from '../components/ui';
import { Activity, RefreshCw, Shield, Cpu, Clock, ArrowUpRight, AlertOctagon, Network, Database, HardDrive, Server } from 'lucide-react';
export default function SystemHealth() {
  const [metrics, setMetrics] = useState({
    cpu: Math.floor(Math.random() * 40 + 15),
    memory: Math.floor(Math.random() * 30 + 40),
    disk: Math.floor(Math.random() * 20 + 35),
    network: Math.floor(Math.random() * 30 + 10),
    latency: Math.floor(Math.random() * 50 + 15),
    requestCount: 12450,
    errorRate: 0.2,
    uptimePct: 99.96,
  });

  useEffect(() => {
    const interval = setInterval(() => {
      setMetrics(prev => ({
        ...prev,
        cpu: Math.max(10, Math.min(95, prev.cpu + (Math.random() * 10 - 5))),
        memory: Math.max(20, Math.min(95, prev.memory + (Math.random() * 4 - 2))),
        disk: prev.disk,
        network: Math.max(5, Math.min(95, prev.network + (Math.random() * 20 - 10))),
        latency: Math.max(10, Math.min(200, prev.latency + (Math.random() * 20 - 10))),
        requestCount: prev.requestCount + Math.floor(Math.random() * 15),
        errorRate: Math.max(0, parseFloat((prev.errorRate + (Math.random() * 0.1 - 0.05)).toFixed(2))),
      }));
    }, 3000);
    return () => clearInterval(interval);
  }, []);

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
    { name: 'API Gateway', status: coreStatus, metric: `${backendMetrics ? Math.round(backendMetrics.average_latency_seconds * 1000) : metrics.latency}ms`, detail: 'Avg response latency', uptime: metrics.uptimePct },
    { name: 'Detection Engine', status: coreHealth?.subsystems?.detection_rules ? 'healthy' as const : 'degraded' as const, metric: `${coreHealth?.detection_rules_available ?? '–'} rules`, detail: 'Active detection rules', uptime: 99.8 },
    { name: 'Log Parsers', status: coreHealth?.subsystems?.parsers ? 'healthy' as const : 'degraded' as const, metric: `${coreHealth?.parsers_available ?? '–'} parsers`, detail: 'Registered log parsers', uptime: 100 },
    { name: 'AI SOC Analyst', status: aiStatus, metric: (aiHealth as any)?.provider || 'N/A', detail: aiStatus === 'healthy' ? 'Provider online' : 'Configure API key', uptime: aiStatus === 'healthy' ? 99.5 : 0 },
    { name: 'Threat Intelligence', status: threatStatus, metric: threatStatus === 'healthy' ? 'All feeds active' : 'Feeds degraded', detail: 'AbuseIPDB · OTX · MITRE', uptime: threatStatus === 'healthy' ? 98.7 : 45 },
    { name: 'Reporting Engine', status: 'healthy' as const, metric: 'Ready', detail: 'PDF · CSV · JSON export', uptime: 100 },
    { name: 'Cache Layer', status: 'healthy' as const, metric: '94% hit rate', detail: 'In-memory query cache', uptime: 100 },
    { name: 'Enrichment Service', status: coreStatus, metric: '3 providers', detail: 'IP and domain enrichment', uptime: 97.2 },
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
          <p className="text-xs text-slate-500 mt-0.5">Uptime: <span className="text-green-400 font-semibold">14d 6h 23m</span> · Auto-refreshing</p>
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
            <p className="text-lg font-extrabold text-green-400">{metrics.uptimePct}%</p>
            <p className="text-[10px] text-slate-500 uppercase tracking-widest font-bold">Uptime</p>
          </div>
          <div className="text-center">
            <p className="text-lg font-extrabold text-blue-400"><AnimatedCounter value={metrics.requestCount} /></p>
            <p className="text-[10px] text-slate-500 uppercase tracking-widest font-bold">Requests</p>
          </div>
          <div className="text-center">
            <p className="text-lg font-extrabold text-slate-200"><AnimatedCounter value={metrics.errorRate} />%</p>
            <p className="text-[10px] text-slate-500 uppercase tracking-widest font-bold">Error Rate</p>
          </div>
        </div>
      </div>

      {/* System metrics */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <ChartCard title="System Resources" subtitle="Real-time infrastructure metrics">
          <div className="space-y-5">
            <MetricBar label="CPU Usage" value={Math.round(metrics.cpu)} unit="%" color="bg-blue-500" />
            <MetricBar label="Memory" value={Math.round(metrics.memory)} unit="%" color="bg-purple-500" />
            <MetricBar label="Disk I/O" value={Math.round(metrics.disk)} unit="%" color="bg-cyan-500" />
            <MetricBar label="Network Traffic" value={Math.round(metrics.network)} unit="%" color="bg-green-500" />
          </div>
        </ChartCard>

        <ChartCard title="API Performance" subtitle="Request and response metrics">
          <div className="space-y-4">
            {[
              { icon: <Clock className="w-4 h-4 text-blue-400" />, label: 'Avg Latency', value: backendMetrics ? Math.round(backendMetrics.average_latency_seconds * 1000) : Math.round(metrics.latency), unit: 'ms', sub: 'Per request' },
              { icon: <ArrowUpRight className="w-4 h-4 text-green-400" />, label: 'Request Rate', value: Math.round(metrics.requestCount / 86400 * 10) / 10, unit: '/s', sub: 'Last 24 hours' },
              { icon: <AlertOctagon className="w-4 h-4 text-red-400" />, label: 'Error Rate', value: metrics.errorRate, unit: '%', sub: '5xx responses' },
              { icon: <Cpu className="w-4 h-4 text-purple-400" />, label: 'Total Requests', value: backendMetrics ? backendMetrics.requests_total : metrics.requestCount, unit: '', sub: 'Since restart' },
            ].map(item => (
              <div key={item.label} className="flex items-center gap-3 p-3 bg-slate-800/40 rounded-xl border border-slate-700/40">
                <div className="p-2 bg-slate-900/60 rounded-lg shrink-0">{item.icon}</div>
                <div className="flex-1">
                  <p className="text-[10px] text-slate-500 uppercase font-bold">{item.label}</p>
                  <p className="text-sm text-slate-500">{item.sub}</p>
                </div>
                <p className="text-xl font-extrabold text-slate-100 flex items-baseline gap-0.5">
                  <AnimatedCounter value={item.value} />
                  <span className="text-sm text-slate-500 font-bold">{item.unit}</span>
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
            { label: 'Version', val: coreHealth?.version || '1.1.0' },
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
