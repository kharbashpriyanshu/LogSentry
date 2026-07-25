import { useState, useEffect } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { aiService } from '../services/aiService';
import { alertService } from '../services/alertService';
import { SeverityBadge, ProgressRing, Timeline, Toast, AnimatedCounter, SkeletonRow } from '../components/ui';
import {
  BrainCircuit, Loader2, Sparkles, Clock,
  Network, Shield, AlertOctagon, BookOpen, Link as LinkIcon,
  Search, Lock, History, ChevronRight
} from 'lucide-react';
import { format } from 'date-fns';
import type { DetectionAlert, AIAnalysisResponse, AIAnalysisModel } from '../types';

export default function AIAnalysis() {
  const queryClient = useQueryClient();
  const [selectedAlertId, setSelectedAlertId] = useState<string | null>(null);
  const [toast, setToast] = useState<{ msg: string; type: 'success' | 'error' } | null>(null);
  const [historyOpen, setHistoryOpen] = useState(false);
  const [selectedHistoryId, setSelectedHistoryId] = useState<string | null>(null);

  // Load state from local storage on mount
  useEffect(() => {
    const saved = localStorage.getItem('last_alert');
    if (saved) {
      try {
        const a = JSON.parse(saved);
        setSelectedAlertId(a.alert_id);
      } catch (e) {}
    }
  }, []);

  const { data: aiHealth } = useQuery({ queryKey: ['ai-health'], queryFn: aiService.checkHealth });
  const { data: aiProviders } = useQuery({ queryKey: ['ai-providers'], queryFn: aiService.getProviders });
  const { data: alerts = [], isLoading: alertsLoading } = useQuery({ queryKey: ['alerts'], queryFn: alertService.getAlerts });

  const selectedAlert = alerts.find((a: DetectionAlert) => a.alert_id === selectedAlertId);

  // Fetch analyses history for the selected alert
  const { data: analysesHistory = [], isLoading: historyLoading } = useQuery({
    queryKey: ['ai-analyses', selectedAlertId],
    queryFn: () => aiService.getAnalysesForAlert(selectedAlertId!),
    enabled: !!selectedAlertId,
  });

  // Determine current analysis to display
  const activeAnalysisModel: AIAnalysisModel | undefined = 
    selectedHistoryId ? analysesHistory.find((h: AIAnalysisModel) => h.id === selectedHistoryId) : analysesHistory[0];
    
  const currentAnalysis: AIAnalysisResponse | undefined = activeAnalysisModel?.raw_response;

  const analyzeMutation = useMutation({
    mutationFn: (alertId: string) => aiService.analyzeAlert(alertId),
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ['ai-analyses', selectedAlertId] });
      setSelectedHistoryId(null);
      setToast({ msg: 'AI analysis complete', type: 'success' });
    },
    onError: (err: any) => {
      setToast({ msg: err.response?.data?.detail || 'Failed to generate AI analysis. Verify API key and backend connection.', type: 'error' });
    }
  });

  const handleAnalyze = () => {
    if (!selectedAlertId) return;
    analyzeMutation.mutate(selectedAlertId);
  };

  const renderHistoryDrawer = () => {
    if (!historyOpen) return null;
    return (
      <div className="absolute top-0 right-0 w-80 h-full bg-[#1e293b] border-l border-slate-700/80 shadow-2xl z-20 flex flex-col transform transition-transform">
        <div className="p-4 border-b border-slate-800 flex justify-between items-center">
          <h3 className="text-sm font-bold text-slate-200 flex items-center gap-2"><History className="w-4 h-4" /> Analysis History</h3>
          <button onClick={() => setHistoryOpen(false)} className="text-slate-400 hover:text-white">&times;</button>
        </div>
        <div className="flex-1 overflow-y-auto divide-y divide-slate-800">
          {analysesHistory.length === 0 ? (
            <p className="text-xs text-slate-500 text-center p-4">No historical analyses found.</p>
          ) : analysesHistory.map((h: AIAnalysisModel) => (
            <button key={h.id} onClick={() => { setSelectedHistoryId(h.id); setHistoryOpen(false); }}
              className={`w-full text-left p-4 hover:bg-slate-800/50 transition-colors ${selectedHistoryId === h.id || (!selectedHistoryId && h.id === analysesHistory[0]?.id) ? 'bg-blue-500/10 border-l-2 border-blue-500' : ''}`}>
              <div className="flex justify-between items-center mb-1">
                <span className="text-xs font-bold text-slate-300">{format(new Date(h.created_at), 'MMM dd HH:mm:ss')}</span>
                <span className="text-[10px] text-blue-400 font-mono">{h.provider}</span>
              </div>
              <p className="text-[11px] text-slate-400 truncate">{h.summary}</p>
            </button>
          ))}
        </div>
      </div>
    );
  };

  return (
    <div className="flex flex-col h-full overflow-hidden animate-fade-in pb-12 relative">
      {toast && <Toast message={toast.msg} type={toast.type} onClose={() => setToast(null)} />}

      <div className="flex items-center justify-between mb-4 shrink-0">
        <div>
          <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <BrainCircuit className="w-5 h-5 text-blue-400" /> AI SOC Analyst
          </h1>
          <p className="text-xs text-slate-500 mt-0.5">
            Provider: <span className="text-blue-400 font-medium">{aiProviders?.active_provider || 'Loading...'}</span>
            {' · '}
            <span className={aiHealth?.healthy ? 'text-green-400' : 'text-yellow-400'}>
              {aiHealth?.healthy ? 'Online' : 'Offline'}
            </span>
          </p>
        </div>
      </div>

      <div className="flex flex-1 gap-5 overflow-hidden min-h-0 relative">
        {/* Left panel – incident selector */}
        <div className="w-80 flex flex-col shrink-0 overflow-hidden">
          <div className="bg-[#1e293b] rounded-xl border border-slate-700/80 flex flex-col overflow-hidden h-full">
            <div className="px-4 py-3 border-b border-slate-800 flex justify-between items-center bg-slate-800/40">
              <p className="text-xs font-bold text-slate-400 uppercase tracking-widest">Select Incident</p>
              <Search className="w-3.5 h-3.5 text-slate-500" />
            </div>
            <div className="flex-1 overflow-y-auto divide-y divide-slate-800/50">
              {alertsLoading ? (
                <div className="p-4 flex justify-center"><Loader2 className="w-5 h-5 animate-spin text-slate-500" /></div>
              ) : alerts.length === 0 ? (
                <div className="p-4 text-center text-xs text-slate-500">No alerts available</div>
              ) : alerts.map((a: DetectionAlert) => (
                <button key={a.alert_id} onClick={() => { setSelectedAlertId(a.alert_id); setSelectedHistoryId(null); localStorage.setItem('last_alert', JSON.stringify(a)); }}
                  className={`w-full flex items-start gap-3 px-4 py-3 hover:bg-slate-800/50 transition-colors text-left ${selectedAlertId === a.alert_id ? 'bg-blue-500/8 border-l-2 border-l-blue-500' : ''}`}>
                  <SeverityBadge severity={a.severity} size="sm" />
                  <div className="min-w-0 flex-1">
                    <p className="text-xs font-semibold text-slate-300 truncate leading-tight">{a.attack_type}</p>
                    <p className="text-[10px] text-slate-500 mt-0.5 truncate">{a.source_ip || 'Unknown source'}</p>
                  </div>
                  <ChevronRight className={`w-3.5 h-3.5 shrink-0 ${selectedAlertId === a.alert_id ? 'text-blue-400' : 'text-slate-600'}`} />
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* Right panel – analysis results */}
        <div className="flex-1 overflow-y-auto space-y-4 pr-2 relative">
          {/* Selected alert summary */}
          {selectedAlert && (
            <div className="bg-[#1e293b] rounded-xl border border-slate-700/80 p-5 shadow-lg relative overflow-hidden shrink-0">
              <div className="absolute top-0 right-0 w-64 h-64 bg-blue-500/5 rounded-full blur-3xl -z-10 translate-x-1/2 -translate-y-1/2" />
              <div className="flex items-start justify-between">
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2 flex-wrap mb-3">
                    <SeverityBadge severity={selectedAlert.severity} />
                    <span className="text-[10px] font-mono text-slate-600">{selectedAlert.alert_id}</span>
                    {selectedAlert.mitre_technique && <span className="text-[10px] font-bold text-orange-400 bg-orange-500/10 border border-orange-500/20 px-1.5 py-0.5 rounded font-mono">{selectedAlert.mitre_technique}</span>}
                  </div>
                  <h2 className="text-lg font-bold text-slate-100 leading-tight">{selectedAlert.title}</h2>
                  <p className="text-xs text-slate-400 mt-1.5">{selectedAlert.source_ip || '?'} → {selectedAlert.endpoint || '?'} · {selectedAlert.hostname || 'Unknown Host'}</p>
                </div>
                <div className="flex flex-col gap-2 shrink-0 ml-4">
                  <button onClick={handleAnalyze} disabled={analyzeMutation.isPending}
                    className="flex items-center justify-center gap-2 px-5 py-2.5 bg-blue-600 hover:bg-blue-700 disabled:bg-slate-700 text-white text-xs font-semibold rounded-lg transition-colors">
                    {analyzeMutation.isPending ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Sparkles className="w-3.5 h-3.5" />}
                    {analyzeMutation.isPending ? 'Analyzing…' : currentAnalysis ? 'Reanalyze Alert' : 'Start Assessment'}
                  </button>
                  {analysesHistory.length > 0 && (
                    <button onClick={() => setHistoryOpen(!historyOpen)} className="flex items-center justify-center gap-2 px-5 py-2 bg-slate-800 hover:bg-slate-700 border border-slate-600 text-slate-300 text-xs font-semibold rounded-lg transition-colors">
                      <History className="w-3.5 h-3.5" /> View History ({analysesHistory.length})
                    </button>
                  )}
                </div>
              </div>
            </div>
          )}

          {!selectedAlert && (
             <div className="h-full flex items-center justify-center text-slate-500 text-sm">Select an alert to begin AI analysis.</div>
          )}

          {analyzeMutation.isPending && (
            <div className="bg-[#1e293b] rounded-xl border border-slate-700/80 p-16 flex flex-col items-center text-center">
              <div className="relative">
                <Loader2 className="w-12 h-12 text-blue-400 animate-spin" />
                <BrainCircuit className="w-6 h-6 text-blue-300 absolute inset-0 m-auto" />
              </div>
              <p className="text-sm font-bold text-slate-200 mt-5">Synthesizing Threat Data…</p>
              <p className="text-xs text-slate-500 mt-2 max-w-sm">Correlating logs, evaluating MITRE ATT&CK techniques, and generating containment strategies natively via backend API.</p>
            </div>
          )}

          {currentAnalysis && !analyzeMutation.isPending && (
            <div className="space-y-4 animate-fade-in relative">
              {/* Score cards */}
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div className="bg-[#1e293b] rounded-xl border border-slate-700/80 p-5 flex items-center justify-between shadow-lg">
                  <div>
                    <p className="text-[10px] font-bold text-slate-500 uppercase tracking-widest mb-1">AI Confidence</p>
                    <p className="text-3xl font-extrabold text-blue-400"><AnimatedCounter value={Math.round(currentAnalysis.confidence_score * 100)} />%</p>
                  </div>
                  <ProgressRing value={Math.round(currentAnalysis.confidence_score * 100)} size={56} stroke={4} color="#3b82f6" />
                </div>
                
                <div className="bg-[#1e293b] rounded-xl border border-slate-700/80 p-5 flex flex-col justify-center shadow-lg">
                  <p className="text-[10px] font-bold text-slate-500 uppercase tracking-widest mb-1">False Positive Prob.</p>
                  <p className={`text-2xl font-extrabold ${currentAnalysis.false_positive_likelihood === 'Low' ? 'text-green-400' : currentAnalysis.false_positive_likelihood === 'Medium' ? 'text-yellow-400' : 'text-red-400'}`}>
                    {currentAnalysis.false_positive_likelihood}
                  </p>
                  <p className="text-[10px] text-slate-500 mt-1">AI heuristic assessment</p>
                </div>

                <div className="bg-[#1e293b] rounded-xl border border-slate-700/80 p-5 flex flex-col justify-center shadow-lg">
                  <p className="text-[10px] font-bold text-slate-500 uppercase tracking-widest mb-1">Provider Model</p>
                  <p className="text-xl font-extrabold text-slate-200 truncate">{activeAnalysisModel?.provider}</p>
                  <p className="text-[10px] text-blue-400 mt-1 font-semibold">{format(new Date(activeAnalysisModel!.created_at), 'MMM dd HH:mm:ss')}</p>
                </div>
              </div>

              {/* Executive & Confidence Explanation */}
              <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
                <div className="lg:col-span-2 bg-[#1e293b] rounded-xl border border-slate-700/80 p-5 shadow-lg">
                  <h3 className="text-xs font-bold text-blue-400 uppercase tracking-widest mb-3 flex items-center gap-2"><BookOpen className="w-4 h-4" /> Executive Summary</h3>
                  <p className="text-sm text-slate-300 leading-relaxed">{currentAnalysis.executive_summary}</p>
                </div>
                <div className="bg-[#1e293b] rounded-xl border border-slate-700/80 p-5 shadow-lg">
                  <h3 className="text-xs font-bold text-purple-400 uppercase tracking-widest mb-3 flex items-center gap-2"><BrainCircuit className="w-4 h-4" /> AI Severity Justification</h3>
                  <p className="text-xs text-slate-400 leading-relaxed italic border-l-2 border-slate-700 pl-3">
                    {currentAnalysis.severity_justification}
                  </p>
                </div>
              </div>

              {/* Technical Analysis */}
              <div className="bg-[#1e293b] rounded-xl border border-slate-700/80 p-5 shadow-lg">
                <h3 className="text-xs font-bold text-cyan-400 uppercase tracking-widest mb-3 flex items-center gap-2"><Search className="w-4 h-4" /> Technical Analysis</h3>
                <p className="text-sm text-slate-300 leading-relaxed font-mono bg-[#0f172a] p-4 rounded-lg border border-slate-800 whitespace-pre-wrap">{currentAnalysis.technical_explanation}</p>
              </div>

              {/* Attack Chain & Impact */}
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                <div className="bg-[#1e293b] rounded-xl border border-slate-700/80 p-5 shadow-lg">
                  <h3 className="text-xs font-bold text-orange-400 uppercase tracking-widest mb-4 flex items-center gap-2"><Network className="w-4 h-4" /> Inferred Attack Chain</h3>
                  <div className="space-y-0">
                    {!currentAnalysis.attack_chain || currentAnalysis.attack_chain.length === 0 ? (
                      <p className="text-xs text-slate-500 italic">No attack chain confidently identified.</p>
                    ) : (
                      currentAnalysis.attack_chain.map((step, i, arr) => (
                        <div key={i} className="flex gap-3 relative">
                          <div className="flex flex-col items-center">
                            <div className="w-5 h-5 rounded-full bg-slate-800 border border-slate-600 flex items-center justify-center shrink-0 z-10 text-[10px] font-bold text-orange-400">{i+1}</div>
                            {i < arr.length - 1 && <div className="w-px flex-1 bg-slate-700/50 my-1" />}
                          </div>
                          <div className="pb-4 pt-0.5">
                            <p className="text-xs font-bold text-slate-200">{step.stage}</p>
                            <p className="text-[10px] text-slate-400 mt-0.5">{step.evidence}</p>
                          </div>
                        </div>
                      ))
                    )}
                  </div>
                </div>

                <div className="space-y-4">
                  <div className="bg-[#1e293b] rounded-xl border border-slate-700/80 p-5 shadow-lg">
                    <h3 className="text-xs font-bold text-red-400 uppercase tracking-widest mb-3 flex items-center gap-2"><AlertOctagon className="w-4 h-4" /> Business Impact</h3>
                    <p className="text-sm text-slate-300 leading-relaxed">{currentAnalysis.potential_impact}</p>
                  </div>
                  
                  <div className="bg-[#1e293b] rounded-xl border border-slate-700/80 p-5 shadow-lg">
                    <h3 className="text-xs font-bold text-slate-400 uppercase tracking-widest mb-3 flex items-center gap-2"><LinkIcon className="w-4 h-4" /> Related Vulnerabilities (CVE)</h3>
                    <div className="flex gap-2 flex-wrap">
                      {!currentAnalysis.cve_references || currentAnalysis.cve_references.length === 0 ? (
                        <span className="text-xs text-slate-500 italic">No CVE identified.</span>
                      ) : (
                        currentAnalysis.cve_references.map(cve => (
                          <span key={cve} className="px-2 py-1 bg-slate-800 border border-slate-700 rounded text-xs font-mono text-blue-400 font-bold">{cve}</span>
                        ))
                      )}
                    </div>
                  </div>
                </div>
              </div>

              {/* Recommendations */}
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                <div className="bg-green-500/5 rounded-xl border border-green-500/15 p-5 shadow-lg">
                  <h3 className="text-xs font-bold text-green-400 uppercase tracking-widest mb-3 flex items-center gap-2"><Shield className="w-4 h-4" /> Containment Strategy</h3>
                  <div className="space-y-3">
                    {!currentAnalysis.containment_strategy || currentAnalysis.containment_strategy.length === 0 ? (
                       <p className="text-xs text-slate-500 italic">No specific containment recommendations.</p>
                    ) : (
                      currentAnalysis.containment_strategy.map((str, idx) => (
                        <div key={idx} className="bg-slate-900/50 p-3 rounded border border-slate-800/80">
                          <div className="flex items-center gap-2 mb-1">
                            <span className={`text-[9px] font-bold uppercase px-1.5 py-0.5 rounded ${str.priority === 'Immediate' ? 'bg-red-500/20 text-red-400' : 'bg-orange-500/20 text-orange-400'}`}>{str.priority}</span>
                            <span className="text-xs font-semibold text-slate-200">{str.action}</span>
                          </div>
                          <p className="text-[10px] text-slate-400 ml-1">{str.reason}</p>
                        </div>
                      ))
                    )}
                  </div>
                </div>
                <div className="bg-[#1e293b] rounded-xl border border-slate-700/80 p-5 shadow-lg">
                  <h3 className="text-xs font-bold text-yellow-400 uppercase tracking-widest mb-3 flex items-center gap-2"><Lock className="w-4 h-4" /> Remediation Actions</h3>
                  <p className="text-sm text-slate-300 leading-relaxed whitespace-pre-line">
                    {currentAnalysis.recommended_actions}
                  </p>
                </div>
              </div>
              
              <div className="pb-8"></div>
            </div>
          )}

          {renderHistoryDrawer()}
        </div>
      </div>
    </div>
  );
}
