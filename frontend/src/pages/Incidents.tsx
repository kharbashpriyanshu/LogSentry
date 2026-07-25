import { useState, useMemo } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { format } from 'date-fns';
import {
  ShieldAlert, Search, Filter, ChevronRight, X, Loader2, CheckCircle2,
  Cpu, Activity, Lock, Unlock, User
} from 'lucide-react';
import { incidentService } from '../services/incidentService';
import type { Incident, TimelineEvent } from '../types';
import { SeverityBadge, StatusBadge, Timeline, Toast, EmptyState, SkeletonRow } from '../components/ui';

function IncidentDetails({ incident, onClose, setToast }: { incident: Incident; onClose: () => void; setToast: any }) {
  const queryClient = useQueryClient();
  const [isAssigning, setIsAssigning] = useState(false);
  const [assigneeInput, setAssigneeInput] = useState('');
  
  const { data: timelineData = [], isLoading: timelineLoading } = useQuery({
    queryKey: ['incident-timeline', incident.id],
    queryFn: () => incidentService.getIncidentTimeline(incident.id),
  });

  const updateMutation = useMutation({
    mutationFn: (updates: any) => incidentService.updateIncident(incident.id, updates),
    onSuccess: (updated) => {
      queryClient.setQueryData(['incidents'], (old: Incident[]) => 
        old.map(i => i.id === incident.id ? updated : i)
      );
      queryClient.invalidateQueries({ queryKey: ['incident-timeline', incident.id] });
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

  const handleStatusUpdate = (status: string) => {
    updateMutation.mutate({ status }, {
      onSuccess: () => setToast({ msg: `Status updated to ${status}`, type: 'success' }),
      onError: () => setToast({ msg: 'Failed to update status', type: 'error' })
    });
  };

  const getTimelineType = (action: string) => {
    if (action === 'created') return 'info';
    if (action === 'status_changed') return 'warning';
    if (action === 'assigned') return 'success';
    return 'info';
  };

  const timelineItems = timelineData.map((ev: TimelineEvent) => ({
    event: ev.action.toUpperCase(),
    detail: ev.action === 'status_changed' ? `Status changed from ${ev.old_value} to ${ev.new_value}` : 
            ev.action === 'assigned' ? `Assigned to ${ev.new_value}` : 
            ev.action === 'created' ? `Incident created: ${ev.metadata_json?.title}` : ev.action,
    time: format(new Date(ev.created_at), 'HH:mm:ss'),
    type: getTimelineType(ev.action) as any
  }));

  return (
    <>
      <div className="drawer-overlay" onClick={onClose} />
      <div className="drawer-panel flex flex-col">
        <div className="flex items-start justify-between px-6 py-4 border-b border-slate-800 shrink-0">
          <div className="min-w-0 pr-4">
            <div className="flex items-center gap-2 mb-1 flex-wrap">
              <SeverityBadge severity={incident.severity} />
              <StatusBadge status={incident.status} />
              <span className="text-[10px] font-bold px-2 py-0.5 bg-slate-800 rounded text-slate-300 border border-slate-700">{incident.priority || 'P3'}</span>
              <span className="text-[10px] font-mono text-slate-600">{incident.id}</span>
            </div>
            <h2 className="text-base font-bold text-slate-100 leading-tight">{incident.title}</h2>
            <p className="text-[11px] text-slate-500 mt-1">{format(new Date(incident.created_at), 'yyyy-MM-dd HH:mm:ss')}</p>
          </div>
          <button onClick={onClose} className="p-1.5 rounded-lg text-slate-500 hover:text-slate-200 hover:bg-slate-800 transition-colors shrink-0 mt-0.5">
            <X className="w-5 h-5" />
          </button>
        </div>

        <div className="flex items-center gap-2 px-6 py-3 border-b border-slate-800 shrink-0 overflow-x-auto">
          {incident.status !== 'investigating' && incident.status !== 'resolved' && incident.status !== 'closed' && (
            <button onClick={() => handleStatusUpdate('investigating')} disabled={updateMutation.isPending}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-blue-600 border border-blue-500 text-white hover:bg-blue-700 rounded-lg text-xs font-semibold transition-colors shrink-0">
              <Search className="w-3.5 h-3.5" /> Start Investigation
            </button>
          )}
          {incident.status === 'investigating' && (
            <button onClick={() => handleStatusUpdate('contained')} disabled={updateMutation.isPending}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-orange-600 border border-orange-500 text-white hover:bg-orange-700 rounded-lg text-xs font-semibold transition-colors shrink-0">
              <Lock className="w-3.5 h-3.5" /> Contain
            </button>
          )}
          {(incident.status === 'investigating' || incident.status === 'contained') && (
            <button onClick={() => handleStatusUpdate('resolved')} disabled={updateMutation.isPending}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-green-600 border border-green-500 text-white hover:bg-green-700 rounded-lg text-xs font-semibold transition-colors shrink-0">
              <CheckCircle2 className="w-3.5 h-3.5" /> Resolve
            </button>
          )}
          {incident.status === 'resolved' && (
            <button onClick={() => handleStatusUpdate('closed')} disabled={updateMutation.isPending}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-700 border border-slate-600 text-slate-300 hover:bg-slate-600 rounded-lg text-xs font-semibold transition-colors shrink-0">
              <CheckCircle2 className="w-3.5 h-3.5" /> Close
            </button>
          )}
          <button onClick={() => setIsAssigning(!isAssigning)}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-700/60 border border-slate-600 text-slate-400 hover:text-slate-200 rounded-lg text-xs font-semibold transition-colors shrink-0">
            <User className="w-3.5 h-3.5" /> Assign
          </button>
        </div>

        {isAssigning && (
          <div className="px-6 py-3 bg-slate-800/80 border-b border-slate-700 flex items-center gap-3">
            <input type="text" placeholder="Enter analyst name..." value={assigneeInput} onChange={e => setAssigneeInput(e.target.value)}
              className="flex-1 bg-slate-900 border border-slate-700 rounded p-1.5 text-xs text-slate-200" />
            <button onClick={handleAssign} disabled={updateMutation.isPending} className="px-3 py-1.5 bg-blue-600 rounded text-xs font-bold">Save</button>
            <button onClick={() => setIsAssigning(false)} className="px-3 py-1.5 bg-slate-700 rounded text-xs">Cancel</button>
          </div>
        )}

        <div className="flex-1 overflow-y-auto p-6 space-y-6">
          <div className="grid grid-cols-2 gap-4">
            <div className="p-4 bg-slate-800/40 rounded-xl border border-slate-700/40">
              <p className="text-[10px] text-slate-500 uppercase tracking-widest font-bold mb-2">Description</p>
              <p className="text-sm text-slate-300 leading-relaxed">{incident.description || 'No description provided.'}</p>
            </div>
            <div className="p-4 bg-slate-800/40 rounded-xl border border-slate-700/40">
              <p className="text-[10px] text-slate-500 uppercase tracking-widest font-bold mb-3">Linked Alerts</p>
              <div className="flex flex-col gap-2">
                {incident.alert_ids.map(id => (
                  <div key={id} className="text-xs font-mono text-blue-400 bg-blue-500/10 px-2 py-1 rounded border border-blue-500/20">{id}</div>
                ))}
              </div>
            </div>
          </div>
          
          <div>
            <h3 className="text-sm font-bold text-slate-200 mb-3 flex items-center gap-2"><Activity className="w-4 h-4 text-blue-400" /> Incident Timeline</h3>
            <div className="bg-[#1e293b] p-4 rounded-xl border border-slate-700/80">
              {timelineLoading ? (
                <div className="flex justify-center p-4"><Loader2 className="w-5 h-5 animate-spin text-slate-500" /></div>
              ) : timelineItems.length > 0 ? (
                <Timeline items={timelineItems} />
              ) : (
                <p className="text-xs text-slate-500">No timeline events available.</p>
              )}
            </div>
          </div>
        </div>
      </div>
    </>
  );
}

export default function Incidents() {
  const [selectedIncident, setSelectedIncident] = useState<Incident | null>(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [statusFilter, setStatusFilter] = useState('ALL');
  const [toast, setToast] = useState<{ msg: string; type: 'success' | 'error' } | null>(null);

  const { data: allIncidents = [], isLoading } = useQuery({
    queryKey: ['incidents'],
    queryFn: incidentService.getIncidents,
  });

  const filtered = useMemo(() => allIncidents.filter((i: Incident) => {
    const q = searchTerm.toLowerCase();
    const matchQ = !q || i.id.toLowerCase().includes(q) || i.title.toLowerCase().includes(q);
    const matchStat = statusFilter === 'ALL' || i.status.toUpperCase() === statusFilter.toUpperCase();
    return matchQ && matchStat;
  }), [allIncidents, searchTerm, statusFilter]);

  return (
    <div className="flex flex-col h-full overflow-hidden animate-fade-in">
      {toast && <Toast message={toast.msg} type={toast.type} onClose={() => setToast(null)} />}

      <div className="flex items-center justify-between mb-4 shrink-0">
        <div>
          <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <ShieldAlert className="w-5 h-5 text-red-400" /> Incident Management
          </h1>
          <p className="text-xs text-slate-500 mt-0.5">{filtered.length} incidents · Active SOC cases</p>
        </div>
      </div>

      <div className="flex flex-wrap gap-3 mb-4 shrink-0">
        <div className="relative flex-1 min-w-52">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-slate-500" />
          <input type="text" value={searchTerm} onChange={e => setSearchTerm(e.target.value)}
            placeholder="Search incident ID, title…"
            className="w-full pl-9 pr-4 py-2 bg-slate-800/60 border border-slate-700/60 rounded-lg text-xs text-slate-200 placeholder-slate-600 focus:outline-none focus:border-blue-500/60" />
        </div>
        <div className="flex items-center gap-2">
          <Filter className="w-3.5 h-3.5 text-slate-500" />
          <select value={statusFilter} onChange={e => setStatusFilter(e.target.value)}
            className="bg-slate-800 border border-slate-700 rounded-lg px-2.5 py-2 text-xs text-slate-300 focus:outline-none focus:border-blue-500">
            <option value="ALL">All Statuses</option>
            <option value="OPEN">Open</option>
            <option value="INVESTIGATING">Investigating</option>
            <option value="CONTAINED">Contained</option>
            <option value="RESOLVED">Resolved</option>
            <option value="CLOSED">Closed</option>
          </select>
        </div>
      </div>

      <div className="flex-1 overflow-auto bg-[#1e293b] rounded-xl border border-slate-700/80">
        <table className="w-full text-xs min-w-[900px]">
          <thead className="sticky top-0 bg-[#111827] border-b border-slate-800 z-10">
            <tr className="text-[10px] font-bold text-slate-500 uppercase tracking-widest">
              <th className="px-4 py-3 text-left">Created</th>
              <th className="px-4 py-3 text-left">Severity</th>
              <th className="px-4 py-3 text-left">Priority</th>
              <th className="px-4 py-3 text-left">Title</th>
              <th className="px-4 py-3 text-left">Status</th>
              <th className="px-4 py-3 text-left">Assignee</th>
              <th className="px-4 py-3 text-right">Alerts</th>
              <th className="px-3 py-3" />
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/40">
            {isLoading && Array.from({ length: 6 }).map((_, i) => <SkeletonRow key={i} cols={8} />)}
            {!isLoading && filtered.length === 0 && (
              <tr><td colSpan={8}>
                <EmptyState icon={<Cpu className="w-8 h-8" />} title="No incidents match filters" desc="Escalate alerts to create an incident." />
              </td></tr>
            )}
            {!isLoading && filtered.map((i) => (
              <tr key={i.id} onClick={() => setSelectedIncident(i)}
                className="hover:bg-slate-800/40 transition-colors cursor-pointer">
                <td className="px-4 py-2.5 font-mono text-slate-400 whitespace-nowrap">{format(new Date(i.created_at), 'MM-dd HH:mm:ss')}</td>
                <td className="px-4 py-2.5"><SeverityBadge severity={i.severity} size="sm" /></td>
                <td className="px-4 py-2.5"><span className="font-bold text-slate-300">{i.priority || 'P3'}</span></td>
                <td className="px-4 py-2.5 text-slate-300 font-medium max-w-[200px] truncate">{i.title}</td>
                <td className="px-4 py-2.5"><StatusBadge status={i.status} /></td>
                <td className="px-4 py-2.5 text-slate-500 text-[11px]">{i.assignee || 'Unassigned'}</td>
                <td className="px-4 py-2.5 text-right font-mono text-slate-400">{i.alert_ids.length}</td>
                <td className="px-3 py-2.5 text-slate-600"><ChevronRight className="w-4 h-4" /></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {selectedIncident && <IncidentDetails incident={selectedIncident} onClose={() => setSelectedIncident(null)} setToast={setToast} />}
    </div>
  );
}
