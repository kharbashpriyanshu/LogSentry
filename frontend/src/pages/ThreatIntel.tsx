import { useState } from 'react';
import { useQuery, useMutation } from '@tanstack/react-query';
import { threatIntelService } from '../services/threatIntelService';
import { EmptyState, ProgressRing, Toast, AnimatedCounter } from '../components/ui';
import type { NormalizedThreatIntel, ProviderStatus } from '../types';
import {
  ShieldAlert, Search, Globe, Shield, Server, CheckCircle2, XCircle,
  Clock, AlertTriangle, ExternalLink, Target, Cpu, Activity,
  MapPin, Hash, Building2, Bookmark, History, FileText, Network
} from 'lucide-react';

function ProviderCard({ p }: { p: ProviderStatus }) {
  return (
    <div className={`flex items-center justify-between p-3 rounded-xl border ${p.status === 'active' ? 'bg-green-500/5 border-green-500/15' : 'bg-slate-800/40 border-slate-700/40'}`}>
      <div className="flex items-center gap-2">
        {p.status === 'active' ? <CheckCircle2 className="w-4 h-4 text-green-400" /> : <XCircle className="w-4 h-4 text-slate-600" />}
        <div>
          <p className="text-xs font-semibold text-slate-200">{p.name}</p>
          {p.latency !== undefined && <p className="text-[10px] text-slate-500">{Math.round(p.latency)}ms</p>}
        </div>
      </div>
      {p.score !== undefined && p.score !== null && (
        <span className={`text-xs font-bold px-2 py-0.5 rounded border ${p.score > 70 ? 'text-red-400 bg-red-500/10 border-red-500/20' : p.score > 40 ? 'text-yellow-400 bg-yellow-500/10 border-yellow-500/20' : 'text-green-400 bg-green-500/10 border-green-500/20'}`}>
          <AnimatedCounter value={p.score} />/100
        </span>
      )}
    </div>
  );
}

export default function ThreatIntel() {
  const [ipInput, setIpInput] = useState('');
  const [result, setResult] = useState<NormalizedThreatIntel | null>(null);
  const [toast, setToast] = useState<{ msg: string; type: 'success' | 'error' } | null>(null);

  const { data: providersHealth } = useQuery({ queryKey: ['enrichment-providers'], queryFn: threatIntelService.getProviders });
  const { data: history, refetch: refetchHistory } = useQuery({ queryKey: ['enrichment-history'], queryFn: threatIntelService.getHistory });

  const lookupMutation = useMutation({
    mutationFn: (observable: string) => threatIntelService.lookupIoc(observable),
    onSuccess: (data) => {
      setResult(data);
      refetchHistory();
      setToast({ msg: `Reputation lookup completed for ${data.observable}`, type: 'success' });
    },
    onError: (err: any) => {
      setToast({ msg: err?.response?.data?.detail || 'Failed to lookup observable', type: 'error' });
    }
  });

  const handleLookup = (e: React.FormEvent) => {
    e.preventDefault();
    if (!ipInput.trim()) return;
    lookupMutation.mutate(ipInput.trim());
  };

  const setAndLookup = (obs: string) => {
    setIpInput(obs);
    lookupMutation.mutate(obs);
  };

  return (
    <div className="space-y-5 animate-fade-in pb-12">
      {toast && <Toast message={toast.msg} type={toast.type} onClose={() => setToast(null)} />}

      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <ShieldAlert className="w-5 h-5 text-purple-400" /> Threat Intelligence Portal
          </h1>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-5">
        {/* Left Sidebar */}
        <div className="lg:col-span-1 space-y-4">
          <div className="bg-[#1e293b] border border-slate-700/80 rounded-xl p-5 shadow-lg">
            <h2 className="text-sm font-semibold text-slate-200 mb-3 flex items-center gap-2"><Search className="w-4 h-4 text-blue-400" /> Indicator Search</h2>
            <form onSubmit={handleLookup} className="space-y-3">
              <input type="text" value={ipInput} onChange={e => setIpInput(e.target.value)}
                placeholder="IP, Domain, Hash..."
                className="w-full bg-slate-800/60 border border-slate-700/60 rounded-lg px-3 py-2.5 text-sm text-slate-200 placeholder-slate-600 focus:outline-none focus:border-blue-500/60 font-mono" />
              <button type="submit" disabled={lookupMutation.isPending}
                className="w-full flex items-center justify-center gap-2 py-2.5 bg-blue-600 hover:bg-blue-700 disabled:bg-slate-700 text-white text-xs font-semibold rounded-lg transition-colors">
                {lookupMutation.isPending ? <><Cpu className="w-3.5 h-3.5 animate-spin" /> Querying…</> : <><Search className="w-3.5 h-3.5" /> Check Reputation</>}
              </button>
            </form>
          </div>

          <div className="bg-[#1e293b] border border-slate-700/80 rounded-xl overflow-hidden">
            <div className="px-4 py-3 border-b border-slate-700/60 bg-slate-800/40">
              <p className="text-xs font-bold text-slate-400 flex items-center gap-1.5"><History className="w-3.5 h-3.5" /> Recent Searches</p>
            </div>
            <div className="divide-y divide-slate-800/60 max-h-64 overflow-y-auto">
              {history && history.length > 0 ? history.map((item: any, i: number) => (
                <button key={i} onClick={() => setAndLookup(item.observable)} className="w-full text-left px-4 py-2 hover:bg-slate-800/30 transition-colors flex items-center justify-between">
                  <span className="text-xs font-mono text-slate-300 truncate">{item.observable}</span>
                </button>
              )) : (
                <div className="p-4 text-center text-xs text-slate-500">No recent searches</div>
              )}
            </div>
          </div>
        </div>

        {/* Right – lookup result */}
        <div className="lg:col-span-3 space-y-4">
          {lookupMutation.isPending && (
            <div className="bg-[#1e293b] border border-slate-700/80 rounded-xl p-16 flex flex-col items-center">
              <Cpu className="w-10 h-10 text-purple-400 animate-spin mb-4" />
              <p className="text-sm font-semibold text-slate-200">Querying Global Threat Feeds…</p>
              <p className="text-xs text-slate-500 mt-2">Checking AbuseIPDB, OTX, and GeoIP</p>
            </div>
          )}

          {!lookupMutation.isPending && !result && (
            <div className="bg-[#1e293b] border border-slate-700/80 rounded-xl h-full flex flex-col justify-center min-h-[400px]">
              <EmptyState icon={<Globe className="w-10 h-10" />} title="Enter an Indicator to Investigate" desc="Query real-time threat feeds for IP reputation, geo-location, historical records, and known IOC associations." />
            </div>
          )}

          {!lookupMutation.isPending && result && (
            <div className="space-y-4 animate-fade-in">
              {/* Summary header */}
              <div className={`bg-[#1e293b] border rounded-xl p-6 shadow-xl ${result.risk.level === 'critical' || result.risk.level === 'high' ? 'border-red-500/40 shadow-red-500/10' : 'border-green-500/30 shadow-green-500/5'}`}>
                <div className="flex items-start justify-between">
                  <div className="flex-1">
                    <div className="flex items-center gap-3 mb-2">
                      <p className="text-3xl font-extrabold font-mono text-slate-100">{result.observable}</p>
                      <span className={`px-3 py-1 rounded-md text-xs font-bold border ${result.risk.level === 'critical' || result.risk.level === 'high' ? 'text-red-400 bg-red-500/15 border-red-500/30 shadow-[0_0_10px_rgba(239,68,68,0.2)]' : 'text-green-400 bg-green-500/15 border-green-500/30'}`}>
                        {result.risk.level === 'critical' || result.risk.level === 'high' ? '⚠ MALICIOUS INDICATOR' : '✓ CLEAN INDICATOR'}
                      </span>
                      {result.cached && (
                        <span className="px-2 py-1 rounded text-[10px] font-bold border text-blue-400 bg-blue-500/15 border-blue-500/30">CACHED</span>
                      )}
                    </div>
                    
                    <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mt-6">
                      <div>
                        <p className="text-[10px] text-slate-500 uppercase font-bold flex items-center gap-1.5"><MapPin className="w-3 h-3" /> Location</p>
                        <p className="text-sm font-semibold text-slate-300 mt-1">{result.geo?.country || result.geo?.countryCode || 'Unknown'}</p>
                      </div>
                      <div>
                        <p className="text-[10px] text-slate-500 uppercase font-bold flex items-center gap-1.5"><Building2 className="w-3 h-3" /> ISP / ASN</p>
                        <p className="text-sm font-semibold text-slate-300 mt-1 truncate">{result.geo?.isp || 'Unknown'}</p>
                      </div>
                      <div>
                        <p className="text-[10px] text-slate-500 uppercase font-bold flex items-center gap-1.5"><Activity className="w-3 h-3" /> Type</p>
                        <p className="text-sm font-semibold text-slate-300 mt-1 uppercase">{result.observable_type}</p>
                      </div>
                      <div>
                        <p className="text-[10px] text-slate-500 uppercase font-bold flex items-center gap-1.5"><Clock className="w-3 h-3" /> Last Enriched</p>
                        <p className="text-sm font-semibold text-slate-300 mt-1">{new Date(result.enriched_at).toLocaleTimeString()}</p>
                      </div>
                    </div>
                  </div>
                  
                  {/* Gauge rings */}
                  <div className="flex gap-6 shrink-0 pl-6 border-l border-slate-700/60 ml-6">
                    <div className="text-center">
                      <ProgressRing value={result.risk.score} size={80} stroke={8} color={result.risk.level === 'critical' ? '#ef4444' : result.risk.level === 'high' ? '#f97316' : result.risk.level === 'medium' ? '#f59e0b' : '#10b981'} />
                      <p className="text-[10px] text-slate-500 mt-2 font-bold uppercase">Aggregated Risk</p>
                    </div>
                  </div>
                </div>
              </div>

              {/* Details grid */}
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-2 gap-4">
                {/* IOC Tags */}
                <div className="bg-[#1e293b] border border-slate-700/80 rounded-xl p-5 shadow-lg">
                  <h3 className="text-xs font-bold text-cyan-400 uppercase tracking-widest mb-4 flex items-center gap-2"><Target className="w-3.5 h-3.5" /> Identified Tags</h3>
                  {result.ioc_tags && result.ioc_tags.length > 0 ? (
                    <div className="flex flex-wrap gap-2">
                      {result.ioc_tags.map(t => (
                        <span key={t} className="px-2.5 py-1 bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 text-xs font-semibold rounded-md">{t}</span>
                      ))}
                    </div>
                  ) : <p className="text-xs text-slate-500">No tags associated with this indicator</p>}
                </div>

                {/* MITRE Techniques */}
                <div className="bg-[#1e293b] border border-slate-700/80 rounded-xl p-5 shadow-lg">
                  <h3 className="text-xs font-bold text-orange-400 uppercase tracking-widest mb-4 flex items-center gap-2"><Network className="w-3.5 h-3.5" /> MITRE ATT&CK Mapping</h3>
                  <div className="flex flex-wrap gap-2">
                    {result.mitre && result.mitre.length > 0 ? result.mitre.map(t => (
                      <a key={t} href={`https://attack.mitre.org/techniques/${t.replace('.', '/')}`} target="_blank" rel="noreferrer"
                        className="flex items-center gap-1.5 px-3 py-1.5 bg-orange-500/10 border border-orange-500/20 text-orange-400 text-xs font-mono font-bold rounded-md hover:bg-orange-500/20 transition-colors">
                        {t} <ExternalLink className="w-3 h-3" />
                      </a>
                    )) : <p className="text-xs text-slate-500">No known MITRE mappings from feeds</p>}
                  </div>
                </div>
              </div>

              {/* Provider results */}
              <div className="bg-[#1e293b] border border-slate-700/80 rounded-xl p-5 shadow-lg">
                <div className="flex items-center justify-between mb-4">
                  <h3 className="text-xs font-bold text-slate-400 uppercase tracking-widest">Feed Provider Verification</h3>
                </div>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  {result.providers.map(p => <ProviderCard key={p.name} p={p} />)}
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
      
      {/* IOC Table from History */}
      <div className="bg-[#1e293b] border border-slate-700/80 rounded-xl overflow-hidden shadow-lg mt-8">
        <div className="px-5 py-4 border-b border-slate-800 flex items-center justify-between bg-slate-800/20">
          <h2 className="text-sm font-semibold text-slate-200 flex items-center gap-2"><Hash className="w-4 h-4 text-orange-400" /> Recent Enrichment Database</h2>
        </div>
        <div className="overflow-x-auto max-h-96">
          <table className="w-full text-xs">
            <thead className="bg-[#111827] sticky top-0 z-10 border-b border-slate-800">
              <tr className="text-[10px] text-slate-500 uppercase font-bold tracking-widest">
                <th className="px-5 py-3 text-left">Type</th>
                <th className="px-5 py-3 text-left">Observable</th>
                <th className="px-5 py-3 text-left">Tags</th>
                <th className="px-5 py-3 text-left">Location</th>
                <th className="px-5 py-3 text-right">Risk Score</th>
                <th className="px-5 py-3 text-left">Enriched At</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/40">
              {history && history.length > 0 ? history.map((item: any, i: number) => (
                <tr key={i} className="hover:bg-slate-800/30 transition-colors">
                  <td className="px-5 py-3 text-slate-300 uppercase">{item.observable_type}</td>
                  <td className="px-5 py-3 text-slate-100 font-mono font-medium">{item.observable}</td>
                  <td className="px-5 py-3 text-slate-400">{item.ioc_tags?.slice(0, 3).join(', ') || '-'}</td>
                  <td className="px-5 py-3 text-slate-400">{item.geo?.countryCode || '-'}</td>
                  <td className="px-5 py-3 text-right">
                    <span className={`px-2 py-1 rounded text-[10px] font-bold border ${item.risk.level === 'critical' ? 'text-red-400 bg-red-500/10 border-red-500/20' : item.risk.level === 'high' ? 'text-orange-400 bg-orange-500/10 border-orange-500/20' : 'text-green-400 bg-green-500/10 border-green-500/20'}`}>
                      {item.risk.score}
                    </span>
                  </td>
                  <td className="px-5 py-3 text-slate-400">{new Date(item.enriched_at).toLocaleString()}</td>
                </tr>
              )) : (
                <tr>
                  <td colSpan={6} className="px-5 py-8 text-center text-slate-500">No recent IOCs enriched</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
