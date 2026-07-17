import { useQuery } from '@tanstack/react-query';
import { healthService } from '../services/healthService';
import { aiService } from '../services/aiService';
import { threatIntelService } from '../services/threatIntelService';
import { Activity, CheckCircle2, XCircle } from 'lucide-react';

const StatusRow = ({ name, status, details }: { name: string, status: boolean, details?: string }) => (
  <div className="flex items-center justify-between p-4 border-b border-slate-700/50 last:border-0">
    <div>
      <h3 className="font-medium text-slate-200">{name}</h3>
      {details && <p className="text-xs text-slate-500 mt-1">{details}</p>}
    </div>
    <div className="flex items-center">
      {status ? (
        <span className="flex items-center text-green-400 text-sm font-medium">
          <CheckCircle2 className="w-4 h-4 mr-1.5" /> Operational
        </span>
      ) : (
        <span className="flex items-center text-red-400 text-sm font-medium">
          <XCircle className="w-4 h-4 mr-1.5" /> Degraded
        </span>
      )}
    </div>
  </div>
);

export default function SystemHealth() {
  const { data: coreHealth } = useQuery({ queryKey: ['health-core'], queryFn: healthService.getBackendHealth });
  const { data: aiHealth } = useQuery({ queryKey: ['health-ai'], queryFn: aiService.getHealth });
  const { data: threatHealth } = useQuery({ queryKey: ['health-threat'], queryFn: threatIntelService.getHealth });

  return (
    <div className="space-y-6 max-w-4xl">
      <h1 className="text-2xl font-bold text-slate-100 flex items-center">
        <Activity className="w-6 h-6 mr-2 text-primary" />
        System Health Diagnostics
      </h1>
      
      <div className="bg-surface border border-slate-700 rounded-xl overflow-hidden">
        <StatusRow 
          name="Core API Services" 
          status={coreHealth?.status === 'ok'} 
          details={`Latency: ${coreHealth?.latency_ms || 0}ms`}
        />
        <StatusRow 
          name="AI SOC Analyst Engine" 
          status={aiHealth?.healthy} 
          details={`Provider: ${aiHealth?.provider || 'Unknown'}`}
        />
        <StatusRow 
          name="Threat Intelligence Pipeline" 
          status={threatHealth?.healthy} 
          details="AbuseIPDB, OTX, MITRE"
        />
      </div>
    </div>
  );
}
