import { useMemo, useEffect } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import {
  Chart as ChartJS, CategoryScale, LinearScale, BarElement, LineElement,
  PointElement, ArcElement, Tooltip as CJTooltip, Legend, Filler,
} from 'chart.js';
import { Line, Doughnut } from 'react-chartjs-2';
import { Link, useNavigate } from 'react-router-dom';
import {
  AlertOctagon, ShieldAlert, AlertTriangle, Info, ArrowUpRight,
  Shield, Clock, Target, Activity, RefreshCw, Cpu, Eye, Globe,
  ActivitySquare, CheckCircle2, Search, User, Network, FileText,
} from 'lucide-react';
import { dashboardService } from '../services/dashboardService';
import { alertService } from '../services/alertService';
import { healthService } from '../services/healthService';
import { wsService } from '../services/websocketService';
import { StatCard, ChartCard, Tooltip, SeverityBadge, StatusBadge } from '../components/ui';
import { format } from 'date-fns';

ChartJS.register(CategoryScale, LinearScale, BarElement, LineElement, PointElement, ArcElement, CJTooltip, Legend, Filler);

const CHART_DEFAULTS = {
  plugins: {
    legend: { display: false },
    tooltip: { backgroundColor: '#0f172a', titleColor: '#e2e8f0', bodyColor: '#94a3b8', borderColor: '#334155', borderWidth: 1, padding: 10 },
  },
  scales: {
    x: { grid: { color: '#1e293b' }, ticks: { color: '#475569', font: { size: 10 } } },
    y: { grid: { color: '#1e293b' }, ticks: { color: '#475569', font: { size: 10 }, stepSize: 1 } },
  },
};

// ── Ranked list widget ────────────────────────────────────────────────────────
function RankedList({ items, labelKey, countKey, color }: { items: any[]; labelKey: string; countKey: string; color: string }) {
  const max = items[0]?.[countKey] || 1;
  if (!items.length) return <p className="text-xs text-slate-500 text-center py-4">No data</p>;
  return (
    <div className="space-y-2.5">
      {items.map((item, i) => (
        <div key={item[labelKey] || i} className="flex items-center gap-3">
          <span className="text-[10px] text-slate-600 w-4 font-mono shrink-0">{i + 1}</span>
          <div className="flex-1 min-w-0">
            <p className="text-xs text-slate-300 font-medium truncate">{item[labelKey] || '—'}</p>
            <div className="mt-1 h-1 bg-slate-700/60 rounded-full overflow-hidden">
              <div
                className="h-full rounded-full transition-all duration-700"
                style={{ width: `${(item[countKey] / max) * 100}%`, background: color }}
              />
            </div>
          </div>
          <span className={`text-[11px] font-bold w-6 text-right shrink-0`} style={{ color }}>{item[countKey]}</span>
        </div>
      ))}
    </div>
  );
}

// ── Activity message formatter ────────────────────────────────────────────────
function formatActivityMessage(ev: any): { text: string; icon: React.ReactNode } {
  const actor = ev.actor && ev.actor !== 'System' ? ev.actor : 'System';
  const eid = ev.short_id ? `#${ev.short_id}` : '';
  const entityLabel = ev.entity_type === 'alert' ? `Alert ${eid}` : ev.entity_type === 'incident' ? `Incident ${eid}` : ev.entity_type;

  switch (ev.action) {
    case 'assigned':
      return { text: `${actor} assigned ${entityLabel} → ${ev.new_value || '?'}`, icon: <User className="w-3.5 h-3.5 text-blue-400" /> };
    case 'resolved':
      return { text: `${actor} resolved ${entityLabel}`, icon: <CheckCircle2 className="w-3.5 h-3.5 text-green-400" /> };
    case 'marked_false_positive':
      return { text: `${actor} marked ${entityLabel} as False Positive`, icon: <CheckCircle2 className="w-3.5 h-3.5 text-slate-400" /> };
    case 'status_changed':
      return { text: `${entityLabel} status → ${ev.new_value || '?'}`, icon: <Activity className="w-3.5 h-3.5 text-yellow-400" /> };
    case 'investigation_started':
      return { text: `${actor} started investigation on ${entityLabel}`, icon: <Search className="w-3.5 h-3.5 text-purple-400" /> };
    case 'created':
      return { text: `${entityLabel} created`, icon: <ShieldAlert className="w-3.5 h-3.5 text-red-400" /> };
    case 'commented':
      return { text: `${actor} added comment on ${entityLabel}`, icon: <FileText className="w-3.5 h-3.5 text-cyan-400" /> };
    default:
      return { text: `${entityLabel}: ${ev.action}`, icon: <Info className="w-3.5 h-3.5 text-blue-400" /> };
  }
}

export default function Dashboard() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();

  useEffect(() => {
    wsService.connect();
    const handleWsEvent = () => {
      queryClient.invalidateQueries({ queryKey: ['dashboard_summary'] });
      queryClient.invalidateQueries({ queryKey: ['dashboard_severity'] });
      queryClient.invalidateQueries({ queryKey: ['dashboard_trend'] });
      queryClient.invalidateQueries({ queryKey: ['dashboard_activity'] });
      queryClient.invalidateQueries({ queryKey: ['dashboard_attack_types'] });
      queryClient.invalidateQueries({ queryKey: ['dashboard_mitre'] });
      queryClient.invalidateQueries({ queryKey: ['dashboard_incidents'] });
      queryClient.invalidateQueries({ queryKey: ['alerts'] });
    };
    wsService.addListener(handleWsEvent);
    return () => { wsService.removeListener(handleWsEvent); wsService.disconnect(); };
  }, [queryClient]);

  const { data: summary, isLoading: loadingSummary, refetch: refetchSummary } = useQuery({
    queryKey: ['dashboard_summary'], queryFn: dashboardService.getSummary, refetchInterval: 15000,
  });
  const { data: severityDataRaw, isLoading: loadingSeverity } = useQuery({
    queryKey: ['dashboard_severity'], queryFn: dashboardService.getSeverityDistribution,
  });
  const { data: trendDataRaw, isLoading: loadingTrend } = useQuery({
    queryKey: ['dashboard_trend'], queryFn: dashboardService.getAlertTrend,
  });
  const { data: topSourcesRaw = [] } = useQuery({
    queryKey: ['dashboard_sources'], queryFn: dashboardService.getTopSources,
  });
  const { data: recentActivity = [] } = useQuery({
    queryKey: ['dashboard_activity'], queryFn: dashboardService.getActivity, refetchInterval: 8000,
  });
  const { data: topAttackTypes = [] } = useQuery({
    queryKey: ['dashboard_attack_types'], queryFn: dashboardService.getTopAttackTypes,
  });
  const { data: topMitre = [] } = useQuery({
    queryKey: ['dashboard_mitre'], queryFn: dashboardService.getTopMitre,
  });
  const { data: recentIncidents = [] } = useQuery({
    queryKey: ['dashboard_incidents'], queryFn: dashboardService.getRecentIncidents,
  });
  const { data: recentAlerts = [] } = useQuery({
    queryKey: ['alerts'], queryFn: alertService.getAlerts,
  });
  const { data: health } = useQuery({
    queryKey: ['health'], queryFn: healthService.getBackendHealth, refetchInterval: 30000,
  });

  const refetchAll = () => {
    refetchSummary();
    ['dashboard_severity','dashboard_trend','dashboard_sources','dashboard_activity',
      'dashboard_attack_types','dashboard_mitre','dashboard_incidents','alerts'].forEach(k =>
      queryClient.invalidateQueries({ queryKey: [k] })
    );
  };

  const isLoading = loadingSummary || loadingSeverity || loadingTrend;

  // Build severity doughnut
  const severityData = useMemo(() => {
    if (!severityDataRaw) return { labels: [], datasets: [] };
    const m: any = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
    severityDataRaw.forEach((item: any) => { if (item.severity) m[item.severity.toUpperCase()] = item.count; });
    return {
      labels: ['Critical', 'High', 'Medium', 'Low'],
      datasets: [{ data: [m.CRITICAL, m.HIGH, m.MEDIUM, m.LOW], backgroundColor: ['#ef4444','#f97316','#eab308','#3b82f6'], borderWidth: 0, hoverOffset: 8 }],
    };
  }, [severityDataRaw]);

  // Build 7-day trend line (fill missing dates with 0)
  const alertsOverTime = useMemo(() => {
    const days = 7;
    const dates: string[] = [];
    for (let i = days - 1; i >= 0; i--) {
      const d = new Date(); d.setDate(d.getDate() - i);
      dates.push(d.toISOString().slice(0, 10));
    }
    const trendMap: Record<string, number> = {};
    (trendDataRaw || []).forEach((t: any) => { trendMap[t.date] = t.count; });
    const counts = dates.map(d => trendMap[d] || 0);
    const todayCount = counts[counts.length - 1];

    return {
      dates, counts, todayCount,
      chart: {
        labels: dates.map(d => format(new Date(d + 'T12:00:00'), 'MMM d')),
        datasets: [{
          label: 'Alerts',
          data: counts,
          borderColor: '#3b82f6',
          backgroundColor: 'rgba(59,130,246,0.08)',
          borderWidth: 2,
          pointBackgroundColor: dates.map((_, i) => i === days - 1 ? '#60a5fa' : '#3b82f6'),
          pointRadius: dates.map((_, i) => i === days - 1 ? 6 : 3),
          pointHoverRadius: 7,
          tension: 0.4,
          fill: true,
        }],
      },
    };
  }, [trendDataRaw]);

  const topIPs: any[] = Array.isArray(topSourcesRaw) ? topSourcesRaw : [];

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Activity className="w-6 h-6 text-blue-400 animate-spin mr-3" />
        <span className="text-slate-400">Loading Dashboard Metrics…</span>
      </div>
    );
  }

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
          <p className="text-xs text-slate-500 mt-0.5">Real-time telemetry · All values from database</p>
        </div>
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2 px-3 py-1.5 bg-green-500/10 border border-green-500/20 rounded-lg text-xs text-green-400 font-semibold">
            <span className="w-1.5 h-1.5 rounded-full bg-green-500 animate-pulse" />
            {health?.status === 'healthy' ? 'System Operational' : 'System Connecting...'}
          </div>
          <button onClick={refetchAll} className="p-2 rounded-lg bg-slate-800 border border-slate-700 text-slate-400 hover:text-slate-200 hover:bg-slate-700 transition-colors" title="Refresh all">
            <RefreshCw className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* KPI Row 1 — Severity */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <Tooltip text="Requires immediate triage (< 15 min SLA)">
          <StatCard title="Critical" value={summary?.critical_alerts || 0} subtitle="Critical severity" colorClass="bg-red-500/15 text-red-400" icon={<AlertOctagon className="w-5 h-5" />} onClick={() => navigate('/alerts')} />
        </Tooltip>
        <Tooltip text="Priority investigation (< 4h SLA)">
          <StatCard title="High" value={summary?.high_alerts || 0} subtitle="High severity" colorClass="bg-orange-500/15 text-orange-400" icon={<ShieldAlert className="w-5 h-5" />} onClick={() => navigate('/alerts')} />
        </Tooltip>
        <Tooltip text="Currently under active investigation">
          <StatCard title="Investigating" value={summary?.investigating_alerts || 0} subtitle="Alerts under review" colorClass="bg-amber-500/15 text-amber-400" icon={<AlertTriangle className="w-5 h-5" />} onClick={() => navigate('/alerts')} />
        </Tooltip>
        <Tooltip text="Open escalated incidents">
          <StatCard title="Open Incidents" value={summary?.open_incidents || 0} subtitle="Escalated cases" colorClass="bg-red-500/15 text-red-400" icon={<Shield className="w-5 h-5" />} onClick={() => navigate('/incidents')} />
        </Tooltip>
      </div>

      {/* KPI Row 2 — Status counts */}
      <div className="grid grid-cols-2 lg:grid-cols-6 gap-4">
        <StatCard title="Total Alerts" value={summary?.total_alerts || 0} subtitle="All time" colorClass="bg-slate-700 text-slate-300" icon={<Shield className="w-5 h-5" />} />
        <StatCard title="Open" value={summary?.open_alerts || 0} subtitle="Needs triage" colorClass="bg-red-500/15 text-red-400" icon={<Clock className="w-5 h-5" />} onClick={() => navigate('/alerts')} />
        <StatCard title="Resolved" value={summary?.resolved_alerts || 0} subtitle="Remediated" colorClass="bg-green-500/15 text-green-400" icon={<CheckCircle2 className="w-5 h-5" />} />
        <StatCard title="False Positives" value={summary?.false_positive_alerts || 0} subtitle="Marked FP" colorClass="bg-slate-500/15 text-slate-400" icon={<Info className="w-5 h-5" />} />
        <StatCard title="Total Incidents" value={summary?.total_incidents || 0} subtitle="Historical" colorClass="bg-purple-500/15 text-purple-400" icon={<Eye className="w-5 h-5" />} onClick={() => navigate('/incidents')} />
        <StatCard title="Events Ingested" value={summary?.events_processed || 0} subtitle="Log events" colorClass="bg-cyan-500/15 text-cyan-400" icon={<Target className="w-5 h-5" />} />
      </div>

      {/* Charts row */}
      <div className="grid grid-cols-1 lg:grid-cols-4 gap-4">
        <div className="lg:col-span-3">
          <ChartCard
            title="Alerts Over Time"
            subtitle={`Last 7 days · Today: ${alertsOverTime.todayCount} alert${alertsOverTime.todayCount !== 1 ? 's' : ''}`}
          >
            <Line
              data={alertsOverTime.chart}
              options={{
                ...CHART_DEFAULTS,
                responsive: true,
                maintainAspectRatio: false,
                interaction: { mode: 'index', intersect: false },
              } as any}
              height={180}
            />
          </ChartCard>
        </div>
        <ChartCard title="Severity Distribution">
          <div className="flex items-center justify-center">
            <Doughnut
              data={severityData}
              options={{
                responsive: true,
                maintainAspectRatio: false,
                cutout: '72%',
                plugins: {
                  legend: { display: true, position: 'bottom', labels: { color: '#64748b', font: { size: 10 }, padding: 10, boxWidth: 10 } },
                  tooltip: CHART_DEFAULTS.plugins.tooltip,
                },
              } as any}
              height={200}
            />
          </div>
        </ChartCard>
      </div>

      {/* Intelligence widgets row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Top Attack Types */}
        <div className="bg-[#1e293b] rounded-xl border border-slate-700/80 overflow-hidden">
          <div className="px-5 py-3.5 border-b border-slate-700/60 flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-orange-400" />
            <h3 className="text-sm font-semibold text-slate-200">Top Attack Types</h3>
          </div>
          <div className="p-4">
            <RankedList items={Array.isArray(topAttackTypes) ? topAttackTypes : []} labelKey="attack_type" countKey="count" color="#f97316" />
          </div>
        </div>

        {/* Top MITRE Techniques */}
        <div className="bg-[#1e293b] rounded-xl border border-slate-700/80 overflow-hidden">
          <div className="px-5 py-3.5 border-b border-slate-700/60 flex items-center gap-2">
            <Network className="w-4 h-4 text-purple-400" />
            <h3 className="text-sm font-semibold text-slate-200">Top MITRE ATT&CK</h3>
          </div>
          <div className="p-4">
            <RankedList items={Array.isArray(topMitre) ? topMitre : []} labelKey="technique" countKey="count" color="#a855f7" />
          </div>
        </div>

        {/* Top Source IPs */}
        <div className="bg-[#1e293b] rounded-xl border border-slate-700/80 overflow-hidden">
          <div className="px-5 py-3.5 border-b border-slate-700/60 flex items-center gap-2">
            <Globe className="w-4 h-4 text-blue-400" />
            <h3 className="text-sm font-semibold text-slate-200">Top Source IPs</h3>
          </div>
          <div className="p-4">
            <RankedList items={topIPs} labelKey="source_ip" countKey="count" color="#3b82f6" />
          </div>
        </div>
      </div>

      {/* Recent Alerts + Recent Incidents */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Recent Alerts */}
        <div className="bg-[#1e293b] rounded-xl border border-slate-700/80 overflow-hidden">
          <div className="flex items-center justify-between px-5 py-3.5 border-b border-slate-700/60">
            <h3 className="text-sm font-semibold text-slate-200 flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-red-400" /> Latest Alerts
            </h3>
            <Link to="/alerts" className="text-[11px] text-blue-400 hover:underline flex items-center gap-0.5 font-semibold">
              View All <ArrowUpRight className="w-3 h-3" />
            </Link>
          </div>
          <div className="divide-y divide-slate-800/40">
            {Array.isArray(recentAlerts) && recentAlerts.slice(0, 5).map((a: any) => (
              <div key={a.alert_id} onClick={() => navigate('/alerts')} className="flex items-center px-5 py-2.5 hover:bg-slate-800/30 transition-colors cursor-pointer gap-3">
                <span className={`text-[10px] px-1.5 py-0.5 rounded font-bold uppercase shrink-0 ${
                  a.severity === 'CRITICAL' ? 'bg-red-500/20 text-red-400' :
                  a.severity === 'HIGH'     ? 'bg-orange-500/20 text-orange-400' :
                  a.severity === 'MEDIUM'   ? 'bg-yellow-500/20 text-yellow-400' :
                                              'bg-blue-500/20 text-blue-400'
                }`}>{a.severity}</span>
                <p className="text-xs text-slate-300 font-medium truncate flex-1">{a.title}</p>
                <span className="text-[11px] text-slate-500 font-mono shrink-0">{format(new Date(a.timestamp), 'MM-dd HH:mm')}</span>
              </div>
            ))}
            {(!Array.isArray(recentAlerts) || recentAlerts.length === 0) && (
              <p className="text-xs text-slate-500 text-center py-6">No alerts found</p>
            )}
          </div>
        </div>

        {/* Recent Incidents */}
        <div className="bg-[#1e293b] rounded-xl border border-slate-700/80 overflow-hidden">
          <div className="flex items-center justify-between px-5 py-3.5 border-b border-slate-700/60">
            <h3 className="text-sm font-semibold text-slate-200 flex items-center gap-2">
              <Eye className="w-4 h-4 text-purple-400" /> Recent Incidents
            </h3>
            <Link to="/incidents" className="text-[11px] text-blue-400 hover:underline flex items-center gap-0.5 font-semibold">
              View All <ArrowUpRight className="w-3 h-3" />
            </Link>
          </div>
          <div className="divide-y divide-slate-800/40">
            {Array.isArray(recentIncidents) && recentIncidents.slice(0, 5).map((inc: any) => (
              <div key={inc.id} onClick={() => navigate('/incidents')} className="flex items-center px-5 py-2.5 hover:bg-slate-800/30 transition-colors cursor-pointer gap-3">
                <SeverityBadge severity={inc.severity} size="sm" />
                <p className="text-xs text-slate-300 font-medium truncate flex-1">{inc.title}</p>
                <StatusBadge status={inc.status} />
              </div>
            ))}
            {(!Array.isArray(recentIncidents) || recentIncidents.length === 0) && (
              <p className="text-xs text-slate-500 text-center py-6">No incidents yet</p>
            )}
          </div>
        </div>
      </div>

      {/* Activity Feed */}
      <div className="bg-[#1e293b] rounded-xl border border-slate-700/80 overflow-hidden">
        <div className="px-5 py-4 border-b border-slate-700/60 bg-slate-800/20 flex items-center gap-2">
          <ActivitySquare className="w-4 h-4 text-green-400" />
          <div>
            <h3 className="text-sm font-semibold text-slate-200">Recent Analyst Activity</h3>
            <p className="text-[10px] text-slate-500 mt-0.5">Live from database timeline · auto-refreshes every 8s</p>
          </div>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-px bg-slate-800/40 max-h-64 overflow-y-auto">
          {!Array.isArray(recentActivity) || recentActivity.length === 0 ? (
            <div className="col-span-3 text-center py-8">
              <p className="text-xs text-slate-500">No analyst activity recorded yet.</p>
            </div>
          ) : (
            recentActivity.slice(0, 12).map((ev: any) => {
              const { text, icon } = formatActivityMessage(ev);
              return (
                <div key={ev.id} className="flex gap-3 p-4 bg-[#1e293b] hover:bg-slate-800/30 transition-colors">
                  <div className="mt-0.5 p-1.5 bg-slate-800 rounded-lg border border-slate-700/60 shrink-0">{icon}</div>
                  <div className="min-w-0">
                    <p className="text-xs font-medium text-slate-300 leading-snug">{text}</p>
                    <p className="text-[10px] text-slate-500 mt-0.5 font-mono">{format(new Date(ev.created_at), 'MM-dd HH:mm:ss')}</p>
                  </div>
                </div>
              );
            })
          )}
        </div>
      </div>
    </div>
  );
}
