import { useQuery } from '@tanstack/react-query';
import { alertService } from '../services/alertService';
import { format } from 'date-fns';

const SeverityBadge = ({ severity }: { severity: string }) => {
  const colors: any = {
    CRITICAL: 'bg-red-500/20 text-red-400 border border-red-500/30',
    HIGH: 'bg-orange-500/20 text-orange-400 border border-orange-500/30',
    MEDIUM: 'bg-yellow-500/20 text-yellow-400 border border-yellow-500/30',
    LOW: 'bg-blue-500/20 text-blue-400 border border-blue-500/30',
  };
  return (
    <span className={`px-2.5 py-1 rounded-full text-xs font-semibold ${colors[severity] || 'bg-slate-700 text-slate-300'}`}>
      {severity}
    </span>
  );
};

export default function Alerts() {
  const { data: alerts = [], isLoading } = useQuery({
    queryKey: ['alerts'],
    queryFn: alertService.getAlerts,
  });

  if (isLoading) return <div className="text-slate-400 flex justify-center mt-10">Loading alerts...</div>;

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold text-slate-100">Detection Alerts</h1>
      
      <div className="bg-surface border border-slate-700 rounded-xl overflow-hidden">
        <table className="w-full text-left text-sm text-slate-400">
          <thead className="text-xs text-slate-300 uppercase bg-slate-800 border-b border-slate-700">
            <tr>
              <th className="px-6 py-4 font-medium">Timestamp</th>
              <th className="px-6 py-4 font-medium">Severity</th>
              <th className="px-6 py-4 font-medium">Rule</th>
              <th className="px-6 py-4 font-medium">Attack Type</th>
              <th className="px-6 py-4 font-medium">Source IP</th>
            </tr>
          </thead>
          <tbody>
            {alerts.length === 0 && (
              <tr>
                <td colSpan={5} className="px-6 py-8 text-center text-slate-500">
                  No alerts found.
                </td>
              </tr>
            )}
            {alerts.map((alert) => (
              <tr key={alert.alert_id} className="border-b border-slate-700/50 hover:bg-slate-800/50 transition-colors cursor-pointer">
                <td className="px-6 py-4">{format(new Date(alert.timestamp), 'yyyy-MM-dd HH:mm:ss')}</td>
                <td className="px-6 py-4"><SeverityBadge severity={alert.severity} /></td>
                <td className="px-6 py-4 text-slate-300 font-medium">{alert.rule_name}</td>
                <td className="px-6 py-4">{alert.attack_type}</td>
                <td className="px-6 py-4 font-mono text-xs">{alert.source_ip || '-'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
