import { useMemo, useState, useEffect } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import {
  Chart as ChartJS, CategoryScale, LinearScale, BarElement, LineElement,
  PointElement, ArcElement, Tooltip as CJTooltip, Legend, Filler,
} from 'chart.js';
import { Bar, Doughnut, Line } from 'react-chartjs-2';
import { Link, useNavigate } from 'react-router-dom';
import {
  AlertOctagon, ShieldAlert, AlertTriangle, Info, ArrowUpRight,
  Shield, Clock, Target, Activity, RefreshCw, Cpu, Eye, Globe,
  ActivitySquare, CheckCircle2
} from 'lucide-react';
import { dashboardService } from '../services/dashboardService';
import { alertService } from '../services/alertService';
import { healthService } from '../services/healthService';
import { wsService } from '../services/websocketService';
import { StatCard, ChartCard, Tooltip, AnimatedCounter } from '../components/ui';
import { format } from 'date-fns';

ChartJS.register(CategoryScale, LinearScale, BarElement, LineElement, PointElement, ArcElement, CJTooltip, Legend, Filler);

const CHART_DEFAULTS = {
  plugins: { legend: { display: false }, tooltip: { backgroundColor: '#0f172a', titleColor: '#e2e8f0', bodyColor: '#94a3b8', borderColor: '#1e293b', borderWidth: 1 } },
  scales: { x: { grid: { color: '#1e293b' }, ticks: { color: '#475569', font: { size: 10 } } }, y: { grid: { color: '#1e293b' }, ticks: { color: '#475569', font: { size: 10 } } } },
};

export default function Dashboard() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  
  const [liveEvents, setLiveEvents] = useState<any[]>([]);

  useEffect(() => {
    wsService.connect();
    
    const handleWsEvent = (event: any) => {
      // Add event to live feed
      setLiveEvents(prev => {
        let icon = <Info className="w-3.5 h-3.5 text-blue-400" />;
        let text = event.type;
        
        if (event.type === 'alert.created') {
           icon = <AlertTriangle className="w-3.5 h-3.5 text-orange-400" />;
           text = `Alert Created: ${event.data.title}`;
        } else if (event.type === 'alert.updated') {
           icon = <Activity className="w-3.5 h-3.5 text-yellow-400" />;
           text = `Alert Updated (Status: ${event.data.status})`;
        } else if (event.type === 'incident.created') {
           icon = <ShieldAlert className="w-3.5 h-3.5 text-red-400" />;
           text = `Incident Escalated: ${event.data.title}`;
        }
        
        const newEv = {
          id: Date.now() + Math.random(), // just for list key
          time: format(new Date(event.timestamp), 'HH:mm:ss'),
          text,
          icon
        };
        return [newEv, ...prev].slice(0, 50); // Keep last 50
      });

      // Invalidate relevant queries to fetch fresh data
      queryClient.invalidateQueries({ queryKey: ['dashboard_summary'] });
      queryClient.invalidateQueries({ queryKey: ['dashboard_severity'] });
      queryClient.invalidateQueries({ queryKey: ['dashboard_trend'] });
      queryClient.invalidateQueries({ queryKey: ['alerts'] });
    };

    wsService.addListener(handleWsEvent);
    
    return () => {
      wsService.removeListener(handleWsEvent);
      wsService.disconnect();
    };
  }, [queryClient]);

  const { data: summary, isLoading: loadingSummary, refetch: refetchSummary } = useQuery({ queryKey: ['dashboard_summary'], queryFn: dashboardService.getSummary });
  const { data: severityDataRaw, isLoading: loadingSeverity } = useQuery({ queryKey: ['dashboard_severity'], queryFn: dashboardService.getSeverityDistribution });
  const { data: trendDataRaw, isLoading: loadingTrend } = useQuery({ queryKey: ['dashboard_trend'], queryFn: dashboardService.getAlertTrend });
  const { data: topSourcesRaw, isLoading: loadingSources } = useQuery({ queryKey: ['dashboard_sources'], queryFn: dashboardService.getTopSources });
  const { data: health } = useQuery({ queryKey: ['health'], queryFn: healthService.getBackendHealth, refetchInterval: 30000 });
  const { data: recentAlerts = [] } = useQuery({ queryKey: ['alerts'], queryFn: alertService.getAlerts });

  const refetchAll = () => {
    refetchSummary();
    queryClient.invalidateQueries({ queryKey: ['dashboard_severity'] });
    queryClient.invalidateQueries({ queryKey: ['dashboard_trend'] });
    queryClient.invalidateQueries({ queryKey: ['dashboard_sources'] });
    queryClient.invalidateQueries({ queryKey: ['alerts'] });
  };

  const isLoading = loadingSummary || loadingSeverity || loadingTrend || loadingSources;

  const severityData = useMemo(() => {
    if (!severityDataRaw) return { labels: [], datasets: [] };
    
    const mapping: any = { 'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0 };
    severityDataRaw.forEach((item: any) => {
      if (item.severity) mapping[item.severity.toUpperCase()] = item.count;
    });
    
    return {
      labels: ['Critical', 'High', 'Medium', 'Low'],
      datasets: [{ data: [mapping['CRITICAL'], mapping['HIGH'], mapping['MEDIUM'], mapping['LOW']], backgroundColor: ['#ef4444','#f97316','#eab308','#3b82f6'], borderWidth: 0, hoverOffset: 8 }],
    };
  }, [severityDataRaw]);

  const alertsOverTime = useMemo(() => {
    if (!trendDataRaw) return { labels: [], datasets: [] };
    const dates = trendDataRaw.map((t: any) => t.date);
    const counts = trendDataRaw.map((t: any) => t.count);
    
    return {
      labels: dates.length ? dates : ['No Data'],
      datasets: [{
        label: 'Alerts',
        data: counts.length ? counts : [0],
        borderColor: '#3b82f6',
        backgroundColor: 'rgba(59,130,246,0.08)',
        borderWidth: 2,
        pointBackgroundColor: '#3b82f6',
        pointRadius: 4,
        pointHoverRadius: 6,
        tension: 0.4,
        fill: true,
      }],
    };
  }, [trendDataRaw]);

  const topIPs = topSourcesRaw || [];

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Activity className="w-6 h-6 text-blue-400 animate-spin mr-3" />
        <span className="text-slate-400">Loading Dashboard Metrics…</span>
      </div>
    );
  }

  // Handle empty database case gracefully
  if (summary && summary.total_alerts === 0 && summary.events_processed === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-24 text-center px-4 animate-fade-in">
        <div className="p-5 bg-slate-800/60 rounded-2xl border border-slate-700 text-slate-500 mb-4">
          <ActivitySquare className="w-10 h-10 text-slate-400" />
        </div>
        <h3 className="text-xl font-semibold text-slate-200">No Security Telemetry Detected</h3>
        <p className="text-sm text-slate-500 mt-2 max-w-md leading-relaxed">
          The LogSentry database is currently empty. Ingest logs via the API or upload a log file in the Alerts view to begin populating the dashboard.
        </p>
        <button onClick={() => navigate('/alerts')} className="mt-6 px-5 py-2.5 bg-blue-600 hover:bg-blue-700 text-white font-semibold rounded-lg shadow-lg">
          Go to Alerts
        </button>
      </div>
    );
  }

  return (
    <div className="space-y-6 animate-fade-in pb-12">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <Cpu className="w-5 h-5 text-blue-400" /> SOC Command Dashboard
          </h1>
          <p className="text-xs text-slate-500 mt-0.5">Real-time telemetry and metrics</p>
        </div>
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2 px-3 py-1.5 bg-green-500/10 border border-green-500/20 rounded-lg text-xs text-green-400 font-semibold shadow-[0_0_15px_rgba(34,197,94,0.1)]">
            <span className="w-1.5 h-1.5 rounded-full bg-green-500 animate-pulse" />
            {health?.status === 'healthy' ? 'System Operational' : 'System Connecting...'}
          </div>
          <button onClick={refetchAll} className="p-2 rounded-lg bg-slate-800 border border-slate-700 text-slate-400 hover:text-slate-200 hover:bg-slate-700 transition-colors" title="Refresh">
            <RefreshCw className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* KPI Row */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <Tooltip text="Requires immediate triage (< 15 min SLA)">
          <StatCard title="Critical" value={summary?.critical_alerts || 0} subtitle="Critical severity" colorClass="bg-red-500/15 text-red-400" icon={<AlertOctagon className="w-5 h-5" />} onClick={() => navigate('/alerts')} />
        </Tooltip>
        <Tooltip text="Priority investigation (< 4h SLA)">
          <StatCard title="High" value={summary?.high_alerts || 0} subtitle="High severity" colorClass="bg-orange-500/15 text-orange-400" icon={<ShieldAlert className="w-5 h-5" />} onClick={() => navigate('/alerts')} />
        </Tooltip>
        <Tooltip text="Currently assigned and investigating">
          <StatCard title="Active Investigations" value={summary?.investigating_alerts || 0} subtitle="Alerts under review" colorClass="bg-yellow-500/15 text-yellow-400" icon={<AlertTriangle className="w-5 h-5" />} onClick={() => navigate('/alerts')} />
        </Tooltip>
        <Tooltip text="Open escalated incidents">
          <StatCard title="Open Incidents" value={summary?.open_incidents || 0} subtitle="Escalated cases" colorClass="bg-red-500/15 text-red-400" icon={<Shield className="w-5 h-5" />} onClick={() => navigate('/incidents')} />
        </Tooltip>
      </div>

      {/* Secondary KPI Row */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard title="Total Alerts" value={summary?.total_alerts || 0} subtitle="All time" colorClass="bg-slate-700 text-slate-300" icon={<Shield className="w-5 h-5" />} />
        <StatCard title="Resolved Alerts" value={summary?.resolved_alerts || 0} subtitle="Successfully remediated" colorClass="bg-green-500/15 text-green-400" icon={<CheckCircle2 className="w-5 h-5" />} />
        <StatCard title="Total Incidents" value={summary?.total_incidents || 0} subtitle="Total historical incidents" colorClass="bg-purple-500/15 text-purple-400" icon={<Eye className="w-5 h-5" />} onClick={() => navigate('/incidents')} />
        <StatCard title="Events Processed" value={summary?.events_processed || 0} subtitle="Total logs ingested" colorClass="bg-cyan-500/15 text-cyan-400" icon={<Target className="w-5 h-5" />} />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-4">
        {/* Main Chart Area */}
        <div className="lg:col-span-3 space-y-4">
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            <div className="lg:col-span-2">
              <ChartCard title="Alerts Over Time" subtitle="Last 7 days · Backend Database">
                <Line data={alertsOverTime} options={{ ...CHART_DEFAULTS, responsive: true, maintainAspectRatio: false, interaction: { mode: 'index', intersect: false } } as any} height={180} />
              </ChartCard>
            </div>
            <ChartCard title="Severity Distribution">
              <div className="flex items-center justify-center">
                <Doughnut data={severityData} options={{ responsive: true, maintainAspectRatio: false, cutout: '75%', plugins: { legend: { display: true, position: 'bottom', labels: { color: '#64748b', font: { size: 10 }, padding: 12, boxWidth: 10 } }, tooltip: CHART_DEFAULTS.plugins.tooltip } } as any} height={200} />
              </div>
            </ChartCard>
          </div>
          
          {/* Recent Alerts (Replaces Top Attack Types to use actual Alert data properly) */}
          <div className="bg-[#1e293b] rounded-xl border border-slate-700/80">
            <div className="flex items-center justify-between px-5 py-3.5 border-b border-slate-700/60">
              <h3 className="text-sm font-semibold text-slate-200">Recent Alerts</h3>
              <Link to="/alerts" className="text-[11px] text-blue-400 hover:underline flex items-center font-semibold">View All <ArrowUpRight className="w-3 h-3 ml-0.5" /></Link>
            </div>
            <div className="divide-y divide-slate-800/60">
              {recentAlerts.slice(0, 5).map((a: any) => (
                 <div key={a.alert_id} onClick={() => navigate('/alerts')} className="flex items-center px-5 py-2.5 hover:bg-slate-800/30 transition-colors cursor-pointer">
                    <div className="w-24 shrink-0"><span className={`text-[10px] px-1.5 py-0.5 rounded font-bold uppercase ${a.severity==='CRITICAL'?'bg-red-500/20 text-red-400':a.severity==='HIGH'?'bg-orange-500/20 text-orange-400':'bg-yellow-500/20 text-yellow-400'}`}>{a.severity}</span></div>
                    <div className="flex-1 truncate"><p className="text-xs text-slate-300 font-medium truncate">{a.title}</p></div>
                    <div className="w-24 shrink-0 text-right"><span className="text-[11px] text-slate-500">{format(new Date(a.timestamp), 'MM-dd HH:mm')}</span></div>
                 </div>
              ))}
            </div>
          </div>
        </div>

        {/* Live Feed Sidebar */}
        <div className="bg-[#1e293b] rounded-xl border border-slate-700/80 flex flex-col overflow-hidden">
          <div className="px-5 py-4 border-b border-slate-700/60 bg-slate-800/20">
            <h3 className="text-sm font-semibold text-slate-200 flex items-center gap-2">
              <ActivitySquare className="w-4 h-4 text-green-400" /> Live WebSocket Feed
            </h3>
            <p className="text-[10px] text-slate-500 mt-0.5">Real-time system events</p>
          </div>
          <div className="flex-1 overflow-y-auto p-4 space-y-3 min-h-[400px]">
            {liveEvents.length === 0 ? (
              <p className="text-xs text-slate-500 text-center py-4">Waiting for incoming events...</p>
            ) : (
              liveEvents.map((ev, i) => (
                <div key={ev.id} className="flex gap-3 animate-fade-in">
                  <div className="mt-0.5 p-1.5 bg-slate-800 rounded-lg border border-slate-700 shrink-0">
                    {ev.icon}
                  </div>
                  <div>
                    <p className="text-xs font-medium text-slate-300 leading-tight">{ev.text}</p>
                    <p className="text-[10px] text-slate-500 mt-0.5 font-mono">{ev.time}</p>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Top Source IPs */}
        <div className="bg-[#1e293b] rounded-xl border border-slate-700/80">
          <div className="flex items-center justify-between px-5 py-3.5 border-b border-slate-700/60">
            <h3 className="text-sm font-semibold text-slate-200 flex items-center gap-2"><Globe className="w-4 h-4 text-blue-400" /> Top Source IPs</h3>
          </div>
          <div className="divide-y divide-slate-800/60">
            {topIPs.length === 0 ? <p className="text-xs text-slate-500 text-center py-4">No data</p> : null}
            {topIPs.map((item: any, i: number) => (
              <div key={item.source_ip} className="flex items-center px-5 py-2.5 hover:bg-slate-800/30 transition-colors">
                <span className="text-[11px] text-slate-600 w-5 font-mono">{i+1}</span>
                <span className="font-mono text-xs text-slate-200 flex-1">{item.source_ip}</span>
                <div className="flex items-center gap-2">
                  <div className="w-20 h-1.5 bg-slate-700 rounded-full overflow-hidden">
                    <div className="h-full bg-orange-500/60 rounded-full" style={{ width: `${(item.count / topIPs[0].count) * 100}%` }} />
                  </div>
                  <span className="text-[11px] font-bold text-orange-400 w-6 text-right">{item.count}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
