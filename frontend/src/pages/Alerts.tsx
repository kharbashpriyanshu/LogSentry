import { useState, useMemo, useCallback } from 'react';
import { useQuery, useQueryClient, useMutation } from '@tanstack/react-query';
import { format } from 'date-fns';
import { useNavigate } from 'react-router-dom';
import {
  AlertTriangle, Upload, Search, Filter, ChevronRight, BrainCircuit,
  ShieldAlert, Cpu, Loader2, RefreshCw, CheckCircle2, X, Download,
  User, Flag, ExternalLink, Copy, Check, Terminal, Network, Shield
} from 'lucide-react';
import { alertService } from '../services/alertService';
import { incidentService } from '../services/incidentService';
import type { DetectionAlert, TimelineEvent } from '../types';
import { SeverityBadge, StatusBadge, Timeline, Toast, EmptyState, SkeletonRow } from '../components/ui';
import api from '../services/api';

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button onClick={() => { navigator.clipboard.writeText(text); setCopied(true); setTimeout(() => setCopied(false), 2000); }}
      className="p-1 rounded bg-slate-800 border border-slate-700 text-slate-400 hover:text-slate-200 transition-colors" title="Copy to clipboard">
      {copied ? <Check className="w-3.5 h-3.5 text-green-400" /> : <Copy className="w-3.5 h-3.5" />}
    </button>
  );
}

// ── Incident Drawer ──────────────────────────────────────────────────────────
function IncidentDrawer({ alert, onClose, setToast }: { alert: DetectionAlert; onClose: () => void; setToast: any }) {
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const [activeTab, setActiveTab] = useState<'summary' | 'evidence' | 'raw' | 'intel' | 'mitre' | 'timeline' | 'ai' | 'related'>('summary');
  const [isAssigning, setIsAssigning] = useState(false);
  const [assigneeInput, setAssigneeInput] = useState('');
  
  const [isResolving, setIsResolving] = useState(false);
  const [resolveNote, setResolveNote] = useState('');
  
  const [isFP, setIsFP] = useState(false);
  
  const [isEscalating, setIsEscalating] = useState(false);

  const { data: allAlerts = [] } = useQuery({ queryKey: ['alerts'], queryFn: alertService.getAlerts });
  const { data: timelineData = [], isLoading: timelineLoading } = useQuery({
    queryKey: ['alert-timeline', alert.alert_id],
    queryFn: () => alertService.getAlertTimeline(alert.alert_id),
  });

  const updateMutation = useMutation({
    mutationFn: (updates: any) => alertService.updateAlert(alert.alert_id, updates),
    onSuccess: (updatedAlert) => {
      queryClient.setQueryData(['alerts'], (old: DetectionAlert[]) => 
        old.map(a => a.alert_id === alert.alert_id ? updatedAlert : a)
      );
      queryClient.invalidateQueries({ queryKey: ['alert-timeline', alert.alert_id] });
    }
  });
  
  const escalateMutation = useMutation({
    mutationFn: (payload: any) => incidentService.createIncident(payload),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['alert-timeline', alert.alert_id] });
      queryClient.invalidateQueries({ queryKey: ['incidents'] });
    }
  });

  const handleAssign = () => {
    if (!assigneeInput) return;
    updateMutation.mutate({ assignee: assigneeInput }, {
      onSuccess: () => {
        setToast({ msg: `Assigned to ${assigneeInput}`, type: 'success' });
        setIsAssigning(false);
      },
      onError: () => setToast({ msg: 'Failed to assign analyst', type: 'error' })
    });
  };

  const handleInvestigate = () => {
    updateMutation.mutate({ status: 'INVESTIGATING' }, {
      onSuccess: () => setToast({ msg: 'Investigation started', type: 'success' }),
      onError: () => setToast({ msg: 'Failed to start investigation', type: 'error' })
    });
  };

  const handleResolve = () => {
    updateMutation.mutate({ status: 'RESOLVED', resolution_note: resolveNote }, {
      onSuccess: () => {
        setToast({ msg: 'Alert resolved', type: 'success' });
        setIsResolving(false);
      },
      onError: () => setToast({ msg: 'Failed to resolve alert', type: 'error' })
    });
  };

  const handleFalsePositive = () => {
    updateMutation.mutate({ status: 'FALSE_POSITIVE', resolution_note: resolveNote }, {
      onSuccess: () => {
        setToast({ msg: 'Marked as false positive', type: 'success' });
        setIsFP(false);
      },
      onError: () => setToast({ msg: 'Failed to update alert', type: 'error' })
    });
  };

  const handleEscalate = () => {
    escalateMutation.mutate({
      title: `Escalated: ${alert.title}`,
      description: alert.description,
      severity: alert.severity,
      priority: alert.severity === 'CRITICAL' ? 'P1' : alert.severity === 'HIGH' ? 'P2' : 'P3',
      alert_ids: [alert.alert_id]
    }, {
      onSuccess: () => {
        setToast({ msg: 'Escalated to Incident successfully', type: 'success' });
        setIsEscalating(false);
      },
      onError: () => setToast({ msg: 'Failed to escalate to incident', type: 'error' })
    });
  };

  const tabs = [
    { id: 'summary', label: 'Summary' },
    { id: 'evidence', label: 'Evidence & IOCs' },
    { id: 'raw', label: 'Raw Log' },
    { id: 'intel', label: 'Threat Intel' },
    { id: 'mitre', label: 'MITRE' },
    { id: 'timeline', label: 'Timeline' },
    { id: 'ai', label: 'AI Assessment' },
    { id: 'related', label: 'Related' },
  ] as const;

  const getTimelineType = (action: string) => {
    if (action === 'created') return 'info';
    if (action === 'status_changed') return 'warning';
    if (action === 'assigned') return 'success';
    if (action === 'escalated') return 'alert';
    return 'info';
  };

  const timelineItems = [
    { event: 'Log Received', detail: `Raw log ingested from ${alert.hostname}`, time: format(new Date(alert.timestamp), 'HH:mm:ss'), type: 'info' as const },
    { event: 'Detection Triggered', detail: `Rule "${alert.rule_name}" matched`, time: format(new Date(new Date(alert.timestamp).getTime() + 120), 'HH:mm:ss'), type: 'alert' as const },
    ...timelineData.map((ev: TimelineEvent) => ({
      event: ev.action.toUpperCase(),
      detail: ev.action === 'status_changed' ? `Status changed from ${ev.old_value} to ${ev.new_value}` : 
              ev.action === 'assigned' ? `Assigned to ${ev.new_value}` : 
              ev.action === 'escalated' ? `Escalated to incident ${ev.metadata_json?.incident_id}` : ev.action,
      time: format(new Date(ev.created_at), 'HH:mm:ss'),
      type: getTimelineType(ev.action) as any
    }))
  ];

  return (
    <>
      <div className="drawer-overlay" onClick={onClose} />
      <div className="drawer-panel flex flex-col">
        <div className="flex items-start justify-between px-6 py-4 border-b border-slate-800 shrink-0">
          <div className="min-w-0 pr-4">
            <div className="flex items-center gap-2 mb-1 flex-wrap">
              <SeverityBadge severity={alert.severity} />
              <StatusBadge status={alert.status || 'OPEN'} />
              <span className="text-[10px] font-mono text-slate-600">{alert.alert_id}</span>
            </div>
            <h2 className="text-base font-bold text-slate-100 leading-tight">{alert.title}</h2>
            <p className="text-[11px] text-slate-500 mt-1">{format(new Date(alert.timestamp), 'yyyy-MM-dd HH:mm:ss')} · {alert.hostname}</p>
          </div>
          <button onClick={onClose} className="p-1.5 rounded-lg text-slate-500 hover:text-slate-200 hover:bg-slate-800 transition-colors shrink-0 mt-0.5">
            <X className="w-5 h-5" />
          </button>
        </div>

        <div className="flex items-center gap-2 px-6 py-3 border-b border-slate-800 shrink-0 overflow-x-auto">
          {(!alert.status || alert.status.toUpperCase() === 'OPEN') && (
            <button onClick={handleInvestigate} disabled={updateMutation.isPending}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-blue-600 border border-blue-500 text-white hover:bg-blue-700 rounded-lg text-xs font-semibold transition-colors shrink-0">
              <Search className="w-3.5 h-3.5" /> Start Investigation
            </button>
          )}
          <button onClick={() => { localStorage.setItem('last_alert', JSON.stringify(alert)); navigate('/ai-analysis'); }}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-blue-600/20 border border-blue-500/30 text-blue-400 hover:bg-blue-600/30 rounded-lg text-xs font-semibold transition-colors shrink-0">
            <BrainCircuit className="w-3.5 h-3.5" /> AI Analysis
          </button>
          <button onClick={() => navigate('/threat-intel')}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-purple-600/20 border border-purple-500/30 text-purple-400 hover:bg-purple-600/30 rounded-lg text-xs font-semibold transition-colors shrink-0">
            <ShieldAlert className="w-3.5 h-3.5" /> Threat Intel
          </button>
          <button onClick={() => setIsAssigning(!isAssigning)}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-700/60 border border-slate-600 text-slate-400 hover:text-slate-200 rounded-lg text-xs font-semibold transition-colors shrink-0">
            <User className="w-3.5 h-3.5" /> Assign
          </button>
          <button onClick={() => setIsFP(!isFP)}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-700/60 border border-slate-600 text-slate-400 hover:text-slate-200 rounded-lg text-xs font-semibold transition-colors shrink-0">
            <Flag className="w-3.5 h-3.5" /> False Positive
          </button>
          <button onClick={() => setIsResolving(!isResolving)}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-700/60 border border-slate-600 text-slate-400 hover:text-slate-200 rounded-lg text-xs font-semibold transition-colors shrink-0">
            <CheckCircle2 className="w-3.5 h-3.5" /> Resolve
          </button>
          <button onClick={() => setIsEscalating(!isEscalating)}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-red-600/20 border border-red-500/30 text-red-400 hover:bg-red-600/30 rounded-lg text-xs font-semibold transition-colors shrink-0">
            <Shield className="w-3.5 h-3.5" /> Escalate
          </button>
        </div>
        
        {/* Inline Modals for Actions */}
        {isAssigning && (
          <div className="px-6 py-3 bg-slate-800/80 border-b border-slate-700 flex items-center gap-3">
            <input type="text" placeholder="Enter analyst name..." value={assigneeInput} onChange={e => setAssigneeInput(e.target.value)}
              className="flex-1 bg-slate-900 border border-slate-700 rounded p-1.5 text-xs text-slate-200" />
            <button onClick={handleAssign} disabled={updateMutation.isPending} className="px-3 py-1.5 bg-blue-600 rounded text-xs font-bold">Save</button>
            <button onClick={() => setIsAssigning(false)} className="px-3 py-1.5 bg-slate-700 rounded text-xs">Cancel</button>
          </div>
        )}
        
        {(isResolving || isFP) && (
          <div className="px-6 py-3 bg-slate-800/80 border-b border-slate-700 flex flex-col gap-2">
            <input type="text" placeholder="Resolution note..." value={resolveNote} onChange={e => setResolveNote(e.target.value)}
              className="w-full bg-slate-900 border border-slate-700 rounded p-1.5 text-xs text-slate-200" />
            <div className="flex gap-2">
              <button onClick={isResolving ? handleResolve : handleFalsePositive} disabled={updateMutation.isPending} className="px-3 py-1.5 bg-green-600 rounded text-xs font-bold">Confirm</button>
              <button onClick={() => { setIsResolving(false); setIsFP(false); }} className="px-3 py-1.5 bg-slate-700 rounded text-xs">Cancel</button>
            </div>
          </div>
        )}

        {isEscalating && (
          <div className="px-6 py-3 bg-red-900/20 border-b border-red-900/50 flex flex-col gap-2">
            <p className="text-xs text-red-400 font-bold">Escalate to Incident?</p>
            <div className="flex gap-2">
              <button onClick={handleEscalate} disabled={escalateMutation.isPending} className="px-3 py-1.5 bg-red-600 rounded text-xs font-bold text-white">Create Incident</button>
              <button onClick={() => setIsEscalating(false)} className="px-3 py-1.5 bg-slate-700 rounded text-xs text-white">Cancel</button>
            </div>
          </div>
        )}

        {/* Tabs */}
        <div className="flex border-b border-slate-800 px-6 shrink-0 overflow-x-auto gap-1">
          {tabs.map(t => (
            <button key={t.id} onClick={() => setActiveTab(t.id)}
              className={`px-3 py-3 text-xs font-semibold whitespace-nowrap transition-colors ${activeTab === t.id ? 'tab-active' : 'tab-inactive'}`}>
              {t.label}
            </button>
          ))}
        </div>

        {/* Tab content */}
        <div className="flex-1 overflow-y-auto p-6 space-y-4">
          {activeTab === 'summary' && (
            <div className="space-y-4 animate-fade-in">
              <div className="grid grid-cols-2 gap-3">
                {[
                  { label: 'Attack Type', val: alert.attack_type },
                  { label: 'Risk Score', val: `${alert.risk_score.toFixed(0)} / 100` },
                  { label: 'Confidence', val: `${(alert.confidence * 100).toFixed(0)}%` },
                  { label: 'Assigned To', val: alert.assignee || 'Unassigned' },
                  { label: 'Source IP', val: alert.source_ip },
                  { label: 'Destination', val: alert.destination_ip },
                  { label: 'Endpoint', val: alert.endpoint },
                  { label: 'Hostname', val: alert.hostname },
                ].map(({ label, val }) => (
                  <div key={label} className="p-3 bg-slate-800/40 rounded-lg border border-slate-700/40">
                    <p className="text-[10px] text-slate-500 uppercase tracking-widest font-bold">{label}</p>
                    <p className="text-xs text-slate-200 mt-1 font-mono truncate" title={val}>{val}</p>
                  </div>
                ))}
              </div>
              <div className="flex gap-4">
                <div className="flex-1 p-4 bg-slate-800/30 rounded-xl border border-slate-700/40">
                  <p className="text-[10px] text-slate-500 uppercase tracking-widest font-bold mb-2">Description</p>
                  <p className="text-sm text-slate-300 leading-relaxed">{alert.description}</p>
                  {alert.resolution_note && (
                    <div className="mt-3 pt-3 border-t border-slate-700/50">
                      <p className="text-[10px] text-green-400 uppercase tracking-widest font-bold mb-1">Resolution Note</p>
                      <p className="text-xs text-slate-300">{alert.resolution_note}</p>
                    </div>
                  )}
                </div>
                <div className="flex-1 p-4 bg-blue-500/5 rounded-xl border border-blue-500/10">
                  <p className="text-[10px] text-blue-400 uppercase tracking-widest font-bold mb-2">Recommendation</p>
                  <p className="text-sm text-slate-300 leading-relaxed">{alert.recommendation}</p>
                </div>
              </div>
            </div>
          )}

          {activeTab === 'evidence' && (
            <div className="space-y-4 animate-fade-in">
              <div className="p-4 bg-slate-800/40 rounded-xl border border-slate-700/40">
                <div className="flex items-center justify-between mb-3">
                  <p className="text-[10px] text-slate-500 uppercase tracking-widest font-bold">Extracted Fields</p>
                  <CopyButton text={JSON.stringify(alert.evidence, null, 2)} />
                </div>
                <div className="bg-slate-900 rounded-lg p-3 overflow-x-auto border border-slate-800">
                  <pre className="text-[11px] font-mono leading-relaxed text-slate-300">
                    {Object.entries(alert.evidence).map(([k, v]) => (
                      <div key={k}><span className="text-blue-400">"{k}"</span>: <span className="text-green-400">"{String(v)}"</span>,</div>
                    ))}
                  </pre>
                </div>
              </div>
            </div>
          )}

          {activeTab === 'raw' && (
            <div className="animate-fade-in h-full flex flex-col">
              <div className="flex items-center justify-between mb-2">
                <p className="text-xs text-slate-400 flex items-center gap-2"><Terminal className="w-4 h-4 text-green-400" /> Original Payload</p>
                <CopyButton text={alert.raw_log_reference || ''} />
              </div>
              <div className="flex-1 p-4 bg-slate-950 rounded-xl border border-slate-800 font-mono overflow-auto relative group">
                <div className="absolute top-0 left-0 bottom-0 w-8 bg-slate-900 border-r border-slate-800 flex flex-col items-center py-4 text-[10px] text-slate-600 select-none">
                  {alert.raw_log_reference?.split('\\n').map((_, i) => <div key={i}>{i + 1}</div>) || <div>1</div>}
                </div>
                <pre className="pl-10 text-xs text-green-400/90 break-all whitespace-pre-wrap leading-relaxed">{alert.raw_log_reference}</pre>
              </div>
            </div>
          )}

          {activeTab === 'intel' && (
            <div className="animate-fade-in space-y-4">
              <div className="p-5 bg-[#1e293b] border border-slate-700/80 rounded-xl flex items-start gap-4">
                <div className="p-3 bg-red-500/10 rounded-lg shrink-0">
                  <ShieldAlert className="w-6 h-6 text-red-400" />
                </div>
                <div className="flex-1">
                  <div className="flex items-center justify-between">
                    <h3 className="text-sm font-bold text-slate-200">AbuseIPDB Report</h3>
                    <span className="text-[10px] bg-red-500/20 text-red-400 px-2 py-0.5 rounded font-bold border border-red-500/30">100/100 ABUSE SCORE</span>
                  </div>
                  <p className="text-xs text-slate-400 mt-1">IP <span className="font-mono text-slate-300">{alert.source_ip}</span> was reported 428 times in the last 24 hours.</p>
                </div>
              </div>
            </div>
          )}

          {activeTab === 'mitre' && (
            <div className="space-y-4 animate-fade-in">
              <div className="p-5 bg-orange-500/5 border border-orange-500/15 rounded-xl">
                <div className="flex items-start justify-between">
                  <div>
                    <p className="text-[10px] text-orange-400/80 uppercase tracking-widest font-bold mb-1.5">Technique</p>
                    <p className="text-2xl font-bold text-orange-400 font-mono">{alert.mitre_technique}</p>
                  </div>
                </div>
              </div>
            </div>
          )}

          {activeTab === 'timeline' && (
            <div className="animate-fade-in">
              {timelineLoading ? (
                <div className="flex justify-center p-8"><Loader2 className="w-6 h-6 animate-spin text-blue-500" /></div>
              ) : (
                <Timeline items={timelineItems} />
              )}
            </div>
          )}
        </div>
      </div>
    </>
  );
}

// ── Main Alerts Page ─────────────────────────────────────────────────────────
export default function Alerts() {
  const queryClient = useQueryClient();
  const [selectedAlert, setSelectedAlert] = useState<DetectionAlert | null>(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [statusFilter, setStatusFilter] = useState('ALL');
  const [file, setFile] = useState<File | null>(null);
  const [parserName, setParserName] = useState('apache');
  const [uploading, setUploading] = useState(false);
  const [toast, setToast] = useState<{ msg: string; type: 'success' | 'error' } | null>(null);

  const { data: backendAlerts = [], isLoading, refetch } = useQuery({
    queryKey: ['alerts'],
    queryFn: alertService.getAlerts,
    staleTime: 30_000,
  });

  const allAlerts: DetectionAlert[] = backendAlerts || [];

  const filtered = useMemo(() => allAlerts.filter((a: DetectionAlert) => {
    const q = searchTerm.toLowerCase();
    const matchQ = !q || a.alert_id.toLowerCase().includes(q) || a.attack_type.toLowerCase().includes(q)
      || (a.source_ip || '').includes(q) || a.title.toLowerCase().includes(q)
      || (a.mitre_technique || '').toLowerCase().includes(q) || (a.hostname || '').toLowerCase().includes(q);
    const matchSev = severityFilter === 'ALL' || a.severity === severityFilter;
    const matchStat = statusFilter === 'ALL' || a.status?.toUpperCase() === statusFilter.toUpperCase();
    return matchQ && matchSev && matchStat;
  }), [allAlerts, searchTerm, severityFilter, statusFilter]);

  const handleUpload = useCallback(async (e: React.FormEvent) => {
    e.preventDefault();
    if (!file) return;
    setUploading(true);
    const formData = new FormData();
    formData.append('file', file);
    formData.append('parser_name', parserName);
    try {
      const res = await api.post('/detection/analyze-file', formData, { headers: { 'Content-Type': 'multipart/form-data' } });
      const newAlerts: any[] = res.data.alerts || [];
      queryClient.setQueryData(['alerts'], (old: any[] = []) => [...newAlerts, ...old]);
      setToast({ msg: `Ingested ${newAlerts.length} alerts from log file`, type: 'success' });
      setFile(null);
    } catch {
      setToast({ msg: 'Failed to parse log file. Check format and parser selection.', type: 'error' });
    } finally {
      setUploading(false);
    }
  }, [file, parserName, queryClient]);

  const handleSelect = useCallback((a: DetectionAlert) => {
    setSelectedAlert(a);
    localStorage.setItem('last_alert', JSON.stringify(a));
    localStorage.removeItem('last_ai_analysis');
  }, []);

  return (
    <div className="flex flex-col h-full overflow-hidden animate-fade-in">
      {toast && <Toast message={toast.msg} type={toast.type} onClose={() => setToast(null)} />}

      <div className="flex items-center justify-between mb-4 shrink-0">
        <div>
          <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <AlertTriangle className="w-5 h-5 text-orange-400" /> SOC Alert Queue
          </h1>
          <p className="text-xs text-slate-500 mt-0.5">{filtered.length} alerts · {allAlerts.filter(a=>a.status?.toUpperCase()==='OPEN').length} open</p>
        </div>
        <button onClick={() => refetch()} className="p-2 rounded-lg bg-slate-800 border border-slate-700 text-slate-400 hover:text-slate-200 hover:bg-slate-700 transition-colors" title="Refresh">
          <RefreshCw className="w-4 h-4" />
        </button>
      </div>

      <div className="bg-[#1e293b] border border-slate-700/80 rounded-xl p-4 mb-4 shrink-0">
        <form onSubmit={handleUpload} className="flex flex-wrap gap-3 items-end">
          <div>
            <label className="block text-[10px] text-slate-500 uppercase font-bold mb-1">Parser</label>
            <select value={parserName} onChange={e => setParserName(e.target.value)}
              className="bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-xs text-slate-300 focus:outline-none focus:border-blue-500">
              <option value="apache">Apache CLF</option>
              <option value="nginx">Nginx Access</option>
              <option value="regex">Generic Regex</option>
            </select>
          </div>
          <div className="flex-1 min-w-48">
            <label className="block text-[10px] text-slate-500 uppercase font-bold mb-1">Log File</label>
            <input type="file" accept=".log,.txt" onChange={e => setFile(e.target.files?.[0] || null)}
              className="w-full text-xs text-slate-400 bg-slate-800 border border-slate-700 rounded-lg p-1.5 cursor-pointer" />
          </div>
          <button type="submit" disabled={uploading || !file}
            className="flex items-center gap-1.5 px-4 py-2 bg-blue-600 hover:bg-blue-700 disabled:bg-slate-700 text-white text-xs font-semibold rounded-lg transition-colors">
            {uploading ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Upload className="w-3.5 h-3.5" />}
            {uploading ? 'Analyzing…' : 'Upload & Detect'}
          </button>
        </form>
      </div>

      <div className="flex flex-wrap gap-3 mb-4 shrink-0">
        <div className="relative flex-1 min-w-52">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-slate-500" />
          <input type="text" value={searchTerm} onChange={e => setSearchTerm(e.target.value)}
            placeholder="Search alert ID, IP, rule, MITRE…"
            className="w-full pl-9 pr-4 py-2 bg-slate-800/60 border border-slate-700/60 rounded-lg text-xs text-slate-200 placeholder-slate-600 focus:outline-none focus:border-blue-500/60" />
        </div>
        <div className="flex items-center gap-2">
          <Filter className="w-3.5 h-3.5 text-slate-500" />
          <select value={severityFilter} onChange={e => setSeverityFilter(e.target.value)}
            className="bg-slate-800 border border-slate-700 rounded-lg px-2.5 py-2 text-xs text-slate-300 focus:outline-none focus:border-blue-500">
            <option value="ALL">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
          </select>
          <select value={statusFilter} onChange={e => setStatusFilter(e.target.value)}
            className="bg-slate-800 border border-slate-700 rounded-lg px-2.5 py-2 text-xs text-slate-300 focus:outline-none focus:border-blue-500">
            <option value="ALL">All Statuses</option>
            <option value="OPEN">Open</option>
            <option value="INVESTIGATING">Investigating</option>
            <option value="RESOLVED">Resolved</option>
            <option value="FALSE_POSITIVE">False Positive</option>
          </select>
        </div>
      </div>

      <div className="flex-1 overflow-auto bg-[#1e293b] rounded-xl border border-slate-700/80">
        <table className="w-full text-xs min-w-[900px]">
          <thead className="sticky top-0 bg-[#111827] border-b border-slate-800 z-10">
            <tr className="text-[10px] font-bold text-slate-500 uppercase tracking-widest">
              <th className="px-4 py-3 text-left">Timestamp</th>
              <th className="px-4 py-3 text-left">Severity</th>
              <th className="px-4 py-3 text-left">Attack Type</th>
              <th className="px-4 py-3 text-left">MITRE</th>
              <th className="px-4 py-3 text-left">Source IP</th>
              <th className="px-4 py-3 text-left">Hostname</th>
              <th className="px-4 py-3 text-right">Confidence</th>
              <th className="px-4 py-3 text-left">Status</th>
              <th className="px-4 py-3 text-left">Analyst</th>
              <th className="px-3 py-3" />
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/40">
            {isLoading && Array.from({ length: 6 }).map((_, i) => <SkeletonRow key={i} cols={10} />)}
            {!isLoading && filtered.length === 0 && (
              <tr><td colSpan={10}>
                <EmptyState icon={<Cpu className="w-8 h-8" />} title="No alerts match filters" desc="Adjust search or filters, or upload a log file to start detection." />
              </td></tr>
            )}
            {!isLoading && filtered.map((a) => (
              <tr key={a.alert_id} onClick={() => handleSelect(a)}
                className={`hover:bg-slate-800/40 transition-colors cursor-pointer ${selectedAlert?.alert_id === a.alert_id ? 'bg-blue-500/5 border-l-2 border-l-blue-500' : ''}`}>
                <td className="px-4 py-2.5 font-mono text-slate-400 whitespace-nowrap">{format(new Date(a.timestamp), 'MM-dd HH:mm:ss')}</td>
                <td className="px-4 py-2.5"><SeverityBadge severity={a.severity} size="sm" /></td>
                <td className="px-4 py-2.5 text-slate-300 font-medium max-w-[160px] truncate">{a.attack_type}</td>
                <td className="px-4 py-2.5">
                  <span className="font-mono text-[10px] font-bold text-orange-400 bg-orange-500/10 border border-orange-500/20 px-1.5 py-0.5 rounded">{a.mitre_technique}</span>
                </td>
                <td className="px-4 py-2.5 font-mono text-slate-400">{a.source_ip}</td>
                <td className="px-4 py-2.5 text-slate-400">{a.hostname}</td>
                <td className="px-4 py-2.5 text-right">
                  <span className={`font-semibold ${a.confidence > 0.9 ? 'text-red-400' : a.confidence > 0.75 ? 'text-yellow-400' : 'text-slate-400'}`}>
                    {(a.confidence * 100).toFixed(0)}%
                  </span>
                </td>
                <td className="px-4 py-2.5"><StatusBadge status={a.status || 'OPEN'} /></td>
                <td className="px-4 py-2.5 text-slate-500 text-[11px]">{a.assignee}</td>
                <td className="px-3 py-2.5 text-slate-600"><ChevronRight className="w-4 h-4" /></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Drawer */}
      {selectedAlert && <IncidentDrawer alert={selectedAlert} onClose={() => setSelectedAlert(null)} setToast={setToast} />}
    </div>
  );
}
