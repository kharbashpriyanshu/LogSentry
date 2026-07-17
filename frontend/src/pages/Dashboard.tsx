import { useQuery } from '@tanstack/react-query';
import { alertService } from '../services/alertService';
import { healthService } from '../services/healthService';
import { ShieldAlert, AlertOctagon, AlertTriangle, Info, Activity } from 'lucide-react';

const StatCard = ({ title, value, icon: Icon, colorClass }: any) => (
  <div className="bg-surface rounded-xl p-6 border border-slate-700 flex items-center justify-between">
    <div>
      <p className="text-sm text-slate-400 font-medium mb-1">{title}</p>
      <h3 className="text-3xl font-bold text-slate-100">{value}</h3>
    </div>
    <div className={`p-4 rounded-lg ${colorClass}`}>
      <Icon className="w-6 h-6" />
    </div>
  </div>
);

export default function Dashboard() {
  const { data: alerts = [], isLoading: alertsLoading } = useQuery({
    queryKey: ['alerts'],
    queryFn: alertService.getAlerts,
  });

  const { data: health, isLoading: healthLoading } = useQuery({
    queryKey: ['health'],
    queryFn: healthService.getBackendHealth,
  });

  if (alertsLoading || healthLoading) {
    return <div className="flex items-center justify-center h-full text-slate-400">Loading dashboard...</div>;
  }

  const critical = alerts.filter(a => a.severity === 'CRITICAL').length;
  const high = alerts.filter(a => a.severity === 'HIGH').length;
  const medium = alerts.filter(a => a.severity === 'MEDIUM').length;
  const low = alerts.filter(a => a.severity === 'LOW').length;

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold text-slate-100">SOC Overview</h1>
      
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <StatCard 
          title="Critical Alerts" 
          value={critical} 
          icon={AlertOctagon} 
          colorClass="bg-red-500/20 text-red-500" 
        />
        <StatCard 
          title="High Alerts" 
          value={high} 
          icon={ShieldAlert} 
          colorClass="bg-orange-500/20 text-orange-500" 
        />
        <StatCard 
          title="Medium Alerts" 
          value={medium} 
          icon={AlertTriangle} 
          colorClass="bg-yellow-500/20 text-yellow-500" 
        />
        <StatCard 
          title="Low Alerts" 
          value={low} 
          icon={Info} 
          colorClass="bg-blue-500/20 text-blue-500" 
        />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-surface rounded-xl p-6 border border-slate-700">
          <h2 className="text-lg font-bold text-slate-100 mb-4 flex items-center">
            <Activity className="w-5 h-5 mr-2 text-primary" />
            System Status
          </h2>
          <div className="space-y-4">
            <div className="flex justify-between items-center py-2 border-b border-slate-700/50">
              <span className="text-slate-400">Backend API</span>
              <span className={`px-2 py-1 rounded text-xs font-medium ${health?.status === 'ok' ? 'bg-green-500/20 text-green-400' : 'bg-red-500/20 text-red-400'}`}>
                {health?.status === 'ok' ? 'Operational' : 'Down'}
              </span>
            </div>
            {/* Additional health statuses can be populated from AI/Enrichment services */}
          </div>
        </div>
      </div>
    </div>
  );
}
