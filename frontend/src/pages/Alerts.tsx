import { useState, useMemo, useCallback } from 'react';
import { useQuery, useQueryClient, useMutation } from '@tanstack/react-query';
import { format } from 'date-fns';
import { useNavigate } from 'react-router-dom';
import {
  AlertTriangle, Upload, Search, Filter, ChevronRight, BrainCircuit,
  ShieldAlert, Cpu, Loader2, RefreshCw, CheckCircle2, X, Download,
  User, Flag, ExternalLink, Copy, Check, Terminal, Network, Shield,
  FileText, ArrowUpRight
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
  
  // FP State
  const [fpReason, setFpReason] = useState('Incorrect Detection');
  
  // Resolve State
  const [resolveType, setResolveType] = useState('Blocked Source IP');

  // Assign State
  const [assignPriority, setAssignPriority] = useState('Medium');
  const [assignNotes, setAssignNotes] = useState('');
  
  // Escalate State
  const [escTitle, setEscTitle] = useState(`Incident: ${alert.title}`);
  const [escDesc, setEscDesc] = useState(alert.description || '');
  const [escPriority, setEscPriority] = useState(alert.severity === 'CRITICAL' ? 'P1' : alert.severity === 'HIGH' ? 'P2' : 'P3');
  const [escCategory, setEscCategory] = useState('Intrusion Attempt');

  // Comment state
  const [commentText, setCommentText] = useState('');

  const { data: allAlerts = [] } = useQuery({ queryKey: ['alerts'], queryFn: alertService.getAlerts });
  const { data: timelineData = [], isLoading: timelineLoading } = useQuery({
    queryKey: ['alert-timeline', alert.alert_id],
    queryFn: () => alertService.getAlertTimeline(alert.alert_id),
  });

  const refreshAlerts = () => {
    queryClient.invalidateQueries({ queryKey: ['alerts'] });
    queryClient.invalidateQueries({ queryKey: ['dashboard_summary'] });
    queryClient.invalidateQueries({ queryKey: ['alert-timeline', alert.alert_id] });
  };

  const updateMutation = useMutation({
    mutationFn: (updates: any) => alertService.updateAlert(alert.alert_id, updates),
    onSuccess: () => refreshAlerts()
  });

  const fpMutation = useMutation({
    mutationFn: (payload: any) => alertService.falsePositive(alert.alert_id, payload),
    onSuccess: () => {
      refreshAlerts();
      setToast({ msg: 'Marked as false positive', type: 'success' });
      setIsFP(false);
    }
  });

  const resolveMutation = useMutation({
    mutationFn: (payload: any) => alertService.resolve(alert.alert_id, payload),
    onSuccess: () => {
      refreshAlerts();
      setToast({ msg: 'Alert resolved', type: 'success' });
      setIsResolving(false);
    }
  });

  const assignMutation = useMutation({
    mutationFn: (payload: any) => alertService.assign(alert.alert_id, payload),
    onSuccess: () => {
      refreshAlerts();
      setToast({ msg: `Assigned to ${assigneeInput}`, type: 'success' });
      setIsAssigning(false);
    }
  });

  const escalateMutation = useMutation({
    mutationFn: (payload: any) => alertService.investigate(alert.alert_id, payload),
    onSuccess: (incident) => {
      refreshAlerts();
      queryClient.invalidateQueries({ queryKey: ['incidents'] });
      setToast({ msg: 'Investigation started', type: 'success' });
      setIsEscalating(false);
      navigate('/incidents'); // Optionally navigate, or just stay
    }
  });

  const commentMutation = useMutation({
    mutationFn: (payload: any) => alertService.addComment(alert.alert_id, payload),
    onSuccess: () => {
      refreshAlerts();
      setCommentText('');
    }
  });

  const handleAssign = () => {
    if (!assigneeInput) return;
    assignMutation.mutate({ assignee: assigneeInput, priority: assignPriority, notes: assignNotes, assigned_by: 'Demo User' });
  };

  const handleInvestigate = () => {
    setIsEscalating(true);
  };

  const handleResolve = () => {
    resolveMutation.mutate({ resolution_type: resolveType, notes: resolveNote, resolved_by: 'Demo User' });
  };

  const handleFalsePositive = () => {
    fpMutation.mutate({ reason: fpReason, notes: resolveNote, marked_by: 'Demo User' });
  };

  const handleEscalate = () => {
    escalateMutation.mutate({
      title: escTitle,
      description: escDesc,
      priority: escPriority,
      category: escCategory,
      investigator: 'Demo User'
    });
  };

  const handleAddComment = () => {
    if (!commentText.trim()) return;
    commentMutation.mutate({ content: commentText, author: 'Demo User' });
  };

  const tabs = [
    { id: 'summary', label: 'Summary' },
    { id: 'evidence', label: 'Evidence & IOCs' },
    { id: 'raw', label: 'Raw Log' },
    { id: 'mitre', label: 'MITRE' },
    { id: 'timeline', label: 'Timeline' },
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
    ...timelineData.map((ev: TimelineEvent) => {
      let detail = ev.action;
      if (ev.action === 'status_changed') detail = `Status changed from ${ev.old_value} to ${ev.new_value}`;
      if (ev.action === 'assigned') detail = `Assigned to ${ev.new_value}. Notes: ${ev.metadata_json?.notes || 'None'}`;
      if (ev.action === 'investigation_started') detail = `Investigation started (Incident ${ev.metadata_json?.incident_id})`;
      if (ev.action === 'resolved') detail = `Resolved as ${ev.metadata_json?.type}. Note: ${ev.metadata_json?.notes}`;
      if (ev.action === 'marked_false_positive') detail = `Marked FP (${ev.metadata_json?.reason}). Note: ${ev.metadata_json?.notes}`;
      if (ev.action === 'commented') detail = `Comment: ${ev.new_value}`;
      
      return {
        event: ev.metadata_json?.user ? `${ev.action.toUpperCase()} by ${ev.metadata_json.user}` : ev.action.toUpperCase(),
        detail,
        time: format(new Date(ev.created_at), 'HH:mm:ss'),
        type: getTimelineType(ev.action) as any
      };
    })
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
          {(!alert.status || alert.status.toUpperCase() === 'OPEN') ? (
            <button onClick={() => setIsEscalating(!isEscalating)} disabled={updateMutation.isPending}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-blue-600 border border-blue-500 text-white hover:bg-blue-700 rounded-lg text-xs font-semibold transition-colors shrink-0">
              <Search className="w-3.5 h-3.5" /> Start Investigation
            </button>
          ) : alert.status.toUpperCase() === 'INVESTIGATING' ? (
            <button onClick={() => navigate('/incidents')}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-blue-600/20 border border-blue-500/30 text-blue-400 hover:bg-blue-600/30 rounded-lg text-xs font-semibold transition-colors shrink-0">
              <ArrowUpRight className="w-3.5 h-3.5" /> View Investigation
            </button>
          ) : null}

          <button onClick={() => { localStorage.setItem('last_alert', JSON.stringify(alert)); navigate('/ai-analysis'); }}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-purple-600/20 border border-purple-500/30 text-purple-400 hover:bg-purple-600/30 rounded-lg text-xs font-semibold transition-colors shrink-0">
            <BrainCircuit className="w-3.5 h-3.5" /> AI Analysis
          </button>
          
          <button onClick={() => navigate('/threat-intel')}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-orange-600/20 border border-orange-500/30 text-orange-400 hover:bg-orange-600/30 rounded-lg text-xs font-semibold transition-colors shrink-0">
            <ShieldAlert className="w-3.5 h-3.5" /> Threat Intel
          </button>
          
          <button onClick={() => { localStorage.setItem('last_alert', JSON.stringify(alert)); navigate('/reports'); }}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-green-600/20 border border-green-500/30 text-green-400 hover:bg-green-600/30 rounded-lg text-xs font-semibold transition-colors shrink-0">
            <FileText className="w-3.5 h-3.5" /> Generate Report
          </button>
          
          <button onClick={() => setIsAssigning(!isAssigning)}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition-colors shrink-0 ${alert.assignee ? 'bg-blue-600/20 border border-blue-500/30 text-blue-400' : 'bg-slate-700/60 border border-slate-600 text-slate-400 hover:text-slate-200'}`}>
            <User className="w-3.5 h-3.5" /> {alert.assignee ? `Assigned to ${alert.assignee}` : 'Assign'}
          </button>
          
          {alert.status?.toUpperCase() === 'FALSE_POSITIVE' ? (
            <button disabled title="Already marked as False Positive"
              className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-800/80 border border-slate-700 text-slate-500 rounded-lg text-xs font-semibold cursor-not-allowed shrink-0">
              <Check className="w-3.5 h-3.5" /> False Positive
            </button>
          ) : (
            <button onClick={() => setIsFP(!isFP)}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-700/60 border border-slate-600 text-slate-400 hover:text-slate-200 rounded-lg text-xs font-semibold transition-colors shrink-0">
              <Flag className="w-3.5 h-3.5" /> False Positive
            </button>
          )}

          {alert.status?.toUpperCase() === 'RESOLVED' ? (
            <button disabled title="Already resolved"
              className="flex items-center gap-1.5 px-3 py-1.5 bg-green-900/20 border border-green-900/30 text-green-600 rounded-lg text-xs font-semibold cursor-not-allowed shrink-0">
              <Check className="w-3.5 h-3.5" /> Resolved
            </button>
          ) : (
            <button onClick={() => setIsResolving(!isResolving)}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-700/60 border border-slate-600 text-slate-400 hover:text-slate-200 rounded-lg text-xs font-semibold transition-colors shrink-0">
              <CheckCircle2 className="w-3.5 h-3.5" /> Resolve
            </button>
          )}
        </div>
        
        {/* Inline Modals for Actions */}
        {isAssigning && (
          <div className="px-6 py-4 bg-slate-800/80 border-b border-slate-700 flex flex-col gap-3">
            <h3 className="text-xs font-bold text-slate-200 uppercase tracking-widest">Assign Alert</h3>
            <div className="grid grid-cols-2 gap-3">
              <select value={assigneeInput} onChange={e => setAssigneeInput(e.target.value)} className="bg-slate-900 border border-slate-700 rounded p-2 text-xs text-slate-200">
                <option value="">Select Analyst...</option>
                <option value="Demo User">Demo User</option>
                <option value="Alice Chen">Alice Chen</option>
                <option value="Bob Smith">Bob Smith</option>
              </select>
              <select value={assignPriority} onChange={e => setAssignPriority(e.target.value)} className="bg-slate-900 border border-slate-700 rounded p-2 text-xs text-slate-200">
                <option value="Low">Priority: Low</option>
                <option value="Medium">Priority: Medium</option>
                <option value="High">Priority: High</option>
                <option value="Critical">Priority: Critical</option>
              </select>
            </div>
            <input type="text" placeholder="Assignment notes (optional)..." value={assignNotes} onChange={e => setAssignNotes(e.target.value)} className="bg-slate-900 border border-slate-700 rounded p-2 text-xs text-slate-200" />
            <div className="flex gap-2 justify-end">
              <button onClick={() => setIsAssigning(false)} className="px-4 py-2 bg-slate-700 hover:bg-slate-600 rounded text-xs font-semibold transition-colors">Cancel</button>
              <button onClick={handleAssign} disabled={assignMutation.isPending} className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded text-xs font-bold transition-colors">Assign</button>
            </div>
          </div>
        )}
        
        {isFP && (
          <div className="px-6 py-4 bg-slate-800/80 border-b border-slate-700 flex flex-col gap-3">
            <h3 className="text-xs font-bold text-slate-200 uppercase tracking-widest">Mark as False Positive</h3>
            <select value={fpReason} onChange={e => setFpReason(e.target.value)} className="w-full bg-slate-900 border border-slate-700 rounded p-2 text-xs text-slate-200">
              <option value="Incorrect Detection">Incorrect Detection</option>
              <option value="Expected Behavior">Expected Behavior</option>
              <option value="Authorized Security Testing">Authorized Security Testing</option>
              <option value="Internal Vulnerability Scan">Internal Vulnerability Scan</option>
              <option value="Whitelisted Activity">Whitelisted Activity</option>
              <option value="Duplicate Alert">Duplicate Alert</option>
              <option value="Other">Other</option>
            </select>
            <textarea placeholder="Analyst notes (required)..." value={resolveNote} onChange={e => setResolveNote(e.target.value)} rows={3}
              className="w-full bg-slate-900 border border-slate-700 rounded p-2 text-xs text-slate-200 resize-none" />
            <div className="flex gap-2 justify-end">
              <button onClick={() => setIsFP(false)} className="px-4 py-2 bg-slate-700 hover:bg-slate-600 rounded text-xs font-semibold transition-colors">Cancel</button>
              <button onClick={handleFalsePositive} disabled={fpMutation.isPending || !resolveNote} className="px-4 py-2 bg-green-600 hover:bg-green-700 text-white rounded text-xs font-bold transition-colors disabled:opacity-50">Submit FP</button>
            </div>
          </div>
        )}

        {isResolving && (
          <div className="px-6 py-4 bg-slate-800/80 border-b border-slate-700 flex flex-col gap-3">
            <h3 className="text-xs font-bold text-slate-200 uppercase tracking-widest">Resolve Alert</h3>
            <select value={resolveType} onChange={e => setResolveType(e.target.value)} className="w-full bg-slate-900 border border-slate-700 rounded p-2 text-xs text-slate-200">
              <option value="Blocked Source IP">Blocked Source IP</option>
              <option value="WAF Rule Applied">WAF Rule Applied</option>
              <option value="Firewall Rule Added">Firewall Rule Added</option>
              <option value="User Account Locked">User Account Locked</option>
              <option value="Patch Applied">Patch Applied</option>
              <option value="Configuration Fixed">Configuration Fixed</option>
              <option value="Monitoring Only">Monitoring Only</option>
              <option value="Other">Other</option>
            </select>
            <textarea placeholder="Resolution notes (required)..." value={resolveNote} onChange={e => setResolveNote(e.target.value)} rows={3}
              className="w-full bg-slate-900 border border-slate-700 rounded p-2 text-xs text-slate-200 resize-none" />
            <div className="flex gap-2 justify-end">
              <button onClick={() => setIsResolving(false)} className="px-4 py-2 bg-slate-700 hover:bg-slate-600 rounded text-xs font-semibold transition-colors">Cancel</button>
              <button onClick={handleResolve} disabled={resolveMutation.isPending || !resolveNote} className="px-4 py-2 bg-green-600 hover:bg-green-700 text-white rounded text-xs font-bold transition-colors disabled:opacity-50">Submit Resolution</button>
            </div>
          </div>
        )}

        {isEscalating && (
          <div className="px-6 py-4 bg-red-900/10 border-b border-red-900/30 flex flex-col gap-3">
            <h3 className="text-xs font-bold text-red-400 uppercase tracking-widest">Start Investigation (Create Incident)</h3>
            <input type="text" value={escTitle} onChange={e => setEscTitle(e.target.value)} className="w-full bg-slate-900 border border-slate-700 rounded p-2 text-xs text-slate-200" placeholder="Incident Title" />
            <textarea value={escDesc} onChange={e => setEscDesc(e.target.value)} className="w-full bg-slate-900 border border-slate-700 rounded p-2 text-xs text-slate-200 resize-none" rows={2} placeholder="Incident Description" />
            <div className="grid grid-cols-2 gap-3">
              <select value={escPriority} onChange={e => setEscPriority(e.target.value)} className="bg-slate-900 border border-slate-700 rounded p-2 text-xs text-slate-200">
                <option value="P1">P1 - Critical</option>
                <option value="P2">P2 - High</option>
                <option value="P3">P3 - Medium</option>
                <option value="P4">P4 - Low</option>
              </select>
              <select value={escCategory} onChange={e => setEscCategory(e.target.value)} className="bg-slate-900 border border-slate-700 rounded p-2 text-xs text-slate-200">
                <option value="Intrusion Attempt">Intrusion Attempt</option>
                <option value="Malware">Malware</option>
                <option value="Data Exfiltration">Data Exfiltration</option>
                <option value="Unauthorized Access">Unauthorized Access</option>
              </select>
            </div>
            <div className="flex gap-2 justify-end mt-2">
              <button onClick={() => setIsEscalating(false)} className="px-4 py-2 bg-slate-700 hover:bg-slate-600 rounded text-xs font-semibold text-white transition-colors">Cancel</button>
              <button onClick={handleEscalate} disabled={escalateMutation.isPending} className="px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded text-xs font-bold transition-colors">Start Investigation</button>
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
              <div className="p-4 bg-slate-800/40 rounded-xl border border-slate-700/40">
                <p className="text-[10px] text-slate-500 uppercase tracking-widest font-bold mb-3">Analyst Action Summary</p>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                  <div>
                    <p className="text-[10px] text-slate-500 uppercase font-bold">Status</p>
                    <p className="text-xs text-slate-200 mt-0.5">{alert.status?.replace('_', ' ') || 'OPEN'}</p>
                  </div>
                  <div>
                    <p className="text-[10px] text-slate-500 uppercase font-bold">Assigned To</p>
                    <p className="text-xs text-slate-200 mt-0.5">{alert.assignee || 'Unassigned'}</p>
                  </div>
                  <div>
                    <p className="text-[10px] text-slate-500 uppercase font-bold">Created</p>
                    <p className="text-xs text-slate-200 mt-0.5">{format(new Date(alert.timestamp), 'dd MMM yyyy, HH:mm')}</p>
                  </div>
                  <div>
                    <p className="text-[10px] text-slate-500 uppercase font-bold">Resolved</p>
                    <p className="text-xs text-slate-200 mt-0.5">{alert.resolved_at ? format(new Date(alert.resolved_at), 'dd MMM yyyy, HH:mm') : '—'}</p>
                  </div>
                  {alert.resolution_note && (
                    <div className="col-span-2 md:col-span-4 mt-2">
                      <p className="text-[10px] text-slate-500 uppercase font-bold">Notes</p>
                      <p className="text-xs text-slate-300 mt-0.5">{alert.resolution_note}</p>
                    </div>
                  )}
                </div>
              </div>
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
              {alert.evidence && alert.evidence.unique_paths_probed !== undefined && (
                <div className="p-4 bg-slate-800/40 rounded-xl border border-slate-700/40 space-y-3">
                  <p className="text-[10px] text-blue-400 uppercase tracking-widest font-bold">Reconnaissance Campaign Evidence</p>
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                    <div className="p-2.5 bg-slate-900/60 rounded-lg border border-slate-800">
                      <p className="text-[10px] text-slate-500 uppercase font-bold">Unique Paths Probed</p>
                      <p className="text-sm font-mono font-bold text-slate-200 mt-0.5">{alert.evidence.unique_paths_probed}</p>
                    </div>
                    {alert.evidence.request_count !== undefined && (
                      <div className="p-2.5 bg-slate-900/60 rounded-lg border border-slate-800">
                        <p className="text-[10px] text-slate-500 uppercase font-bold">Request Count</p>
                        <p className="text-sm font-mono font-bold text-slate-200 mt-0.5">{alert.evidence.request_count}</p>
                      </div>
                    )}
                    {alert.evidence.window_seconds !== undefined && (
                      <div className="p-2.5 bg-slate-900/60 rounded-lg border border-slate-800">
                        <p className="text-[10px] text-slate-500 uppercase font-bold">Time Window</p>
                        <p className="text-sm font-mono font-bold text-slate-200 mt-0.5">{alert.evidence.window_seconds}s</p>
                      </div>
                    )}
                    {alert.evidence.source_ip && (
                      <div className="p-2.5 bg-slate-900/60 rounded-lg border border-slate-800">
                        <p className="text-[10px] text-slate-500 uppercase font-bold">Source IP</p>
                        <p className="text-sm font-mono font-bold text-slate-200 mt-0.5">{alert.evidence.source_ip}</p>
                      </div>
                    )}
                  </div>
                  {(alert.evidence.first_seen || alert.evidence.last_seen) && (
                    <div className="grid grid-cols-2 gap-3 text-xs text-slate-400 font-mono">
                      {alert.evidence.first_seen && <div><span className="text-slate-500">First Seen:</span> {String(alert.evidence.first_seen)}</div>}
                      {alert.evidence.last_seen && <div><span className="text-slate-500">Last Seen:</span> {String(alert.evidence.last_seen)}</div>}
                    </div>
                  )}
                  {Array.isArray(alert.evidence.sample_paths) && alert.evidence.sample_paths.length > 0 && (
                    <div>
                      <p className="text-[10px] text-slate-500 uppercase tracking-widest font-bold mb-1.5">Sample Paths Probed</p>
                      <div className="flex flex-wrap gap-1.5">
                        {alert.evidence.sample_paths.map((p: string, idx: number) => (
                          <span key={idx} className="px-2 py-0.5 bg-slate-900 border border-slate-700 rounded text-xs font-mono text-green-400">{p}</span>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}
              <div className="p-4 bg-slate-800/40 rounded-xl border border-slate-700/40">
                <div className="flex items-center justify-between mb-3">
                  <p className="text-[10px] text-slate-500 uppercase tracking-widest font-bold">Extracted Fields</p>
                  <CopyButton text={JSON.stringify(alert.evidence, null, 2)} />
                </div>
                <div className="bg-slate-900 rounded-lg p-3 overflow-x-auto border border-slate-800">
                  <pre className="text-[11px] font-mono leading-relaxed text-slate-300">
                    {Object.entries(alert.evidence).map(([k, v]) => (
                      <div key={k}><span className="text-blue-400">"{k}"</span>: <span className="text-green-400">"{Array.isArray(v) ? v.join(', ') : String(v)}"</span>,</div>
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
            <div className="animate-fade-in space-y-6">
              {timelineLoading ? (
                <div className="flex justify-center p-8"><Loader2 className="w-6 h-6 animate-spin text-blue-500" /></div>
              ) : (
                <Timeline items={timelineItems} />
              )}
              
              <div className="pt-4 border-t border-slate-800">
                <p className="text-xs font-bold text-slate-400 uppercase tracking-widest mb-3">Analyst Comments</p>
                <div className="flex gap-2">
                  <textarea value={commentText} onChange={e => setCommentText(e.target.value)} placeholder="Add a comment to the timeline..."
                    className="flex-1 bg-slate-900 border border-slate-700 rounded p-2 text-xs text-slate-200 resize-none h-16" />
                  <button onClick={handleAddComment} disabled={commentMutation.isPending || !commentText.trim()}
                    className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded text-xs font-bold transition-colors disabled:opacity-50">Post</button>
                </div>
              </div>
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
