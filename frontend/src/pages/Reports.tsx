import { useState, useEffect } from 'react';
import { reportService } from '../services/reportService';
import { alertService } from '../services/alertService';
import { SeverityBadge, Timeline, Toast } from '../components/ui';
import { FileText, Download, CheckCircle2, AlertCircle, Loader2, Clock, Shield, Target, User, RefreshCw, Printer, Building2, BrainCircuit } from 'lucide-react';
import api from '../services/api';
import { format } from 'date-fns';

const REPORT_TYPES = [
  { id: 'incident', title: 'Incident Report', desc: 'Full forensic detail with timeline, threat intel & AI analysis. Suitable for SOC teams.', pages: '8–12', icon: '🔴' },
  { id: 'technical', title: 'Technical Report', desc: 'Attack metrics, payload analysis, IOCs, and MITRE mapping for L2/L3 analysts.', pages: '5–8', icon: '🔬' },
  { id: 'executive', title: 'Executive Summary', desc: 'High-level business impact overview for CISO and management. Non-technical.', pages: '2–4', icon: '📊' },
] as const;

export default function Reports() {
  const [reportType, setReportType] = useState<'executive' | 'technical' | 'incident'>('incident');
  const [alert, setAlert] = useState<any>(null);
  const [aiAnalysis, setAiAnalysis] = useState<any>(null);
  const [enrichments, setEnrichments] = useState<any>([]);
  const [generatedReport, setGeneratedReport] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [toast, setToast] = useState<{ msg: string; type: 'success' | 'error' } | null>(null);

  useEffect(() => {
    const savedAlert = localStorage.getItem('last_alert');
    const savedAi = localStorage.getItem('last_ai_analysis');
    const savedEnrich = localStorage.getItem('last_enrichment');
    const fetchAlerts = async () => {
      if (!savedAlert) {
        try {
          const alerts = await alertService.getAlerts();
          if (alerts && alerts.length > 0) setAlert(alerts[0]);
        } catch (e) {
          console.error("Failed to load alerts for reports", e);
        }
      }
    };
    fetchAlerts();
  }, []);

  const handleGenerate = async () => {
    if (!alert) {
      setToast({ msg: 'No incident selected for reporting', type: 'error' });
      return;
    }
    const targetAlert = alert;
    setLoading(true);
    setError(null);
    try {
      const response = await reportService.generateReport({
        report_type: reportType,
        alert: targetAlert,
        enrichments: enrichments || [],
        ai_analysis: aiAnalysis || null,
      });
      setGeneratedReport(response);
      setToast({ msg: 'Report generated successfully', type: 'success' });
    } catch (err: any) {
      setError(err.message || 'Failed to generate report');
      setToast({ msg: 'Failed to generate report on backend', type: 'error' });
    } finally {
      setLoading(false);
    }
  };

  const handleDownload = async (fmt: 'pdf' | 'csv' | 'json') => {
    if (!generatedReport) return;
    try {
      const endpoint = `/reports/export/${fmt}`;
      const response = await api.get(endpoint, { responseType: 'blob' });
      const blob = new Blob([response.data], { type: response.headers['content-type'] as string });
      const filename = `logsentry_report_${generatedReport.report_id.slice(-8)}.${fmt === 'csv' ? 'zip' : fmt}`;
      const link = document.createElement('a');
      link.href = window.URL.createObjectURL(blob);
      link.download = filename;
      link.click();
      setToast({ msg: `${fmt.toUpperCase()} export downloaded`, type: 'success' });
    } catch {
      setToast({ msg: `Export requires backend connection. Start the API server and try again.`, type: 'error' });
    }
  };

  const previewTimeline = [
    { event: 'Attack Detected', detail: `${alert?.attack_type || 'Security event'} detected on ${alert?.hostname || 'host'}`, time: alert?.timestamp ? format(new Date(alert.timestamp), 'HH:mm:ss') : '--', type: 'alert' as const },
    { event: 'Threat Intel Enrichment', detail: 'AbuseIPDB and OTX queried for IOC context', time: '+0.8s', type: 'info' as const },
    { event: 'AI Analysis Completed', detail: 'LLM risk assessment and remediation generated', time: '+2.1s', type: 'info' as const },
    { event: 'Report Generated', detail: `${reportType.charAt(0).toUpperCase() + reportType.slice(1)} report compiled`, time: 'Now', type: 'success' as const },
  ];

  const activeAlert = alert;

  return (
    <div className="space-y-5 animate-fade-in">
      {toast && <Toast message={toast.msg} type={toast.type} onClose={() => setToast(null)} />}

      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <FileText className="w-5 h-5 text-green-400" /> Incident Reporting Engine
          </h1>
          <p className="text-xs text-slate-500 mt-0.5">Generate professional security reports for distribution</p>
        </div>
      </div>

      {error && (
        <div className="bg-red-500/8 border border-red-500/20 rounded-xl p-4 flex items-start gap-3">
          <AlertCircle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
          <p className="text-sm text-red-300">{error}</p>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        {/* Config panel */}
        <div className="space-y-4">
          {/* Alert Context */}
          <div className="bg-[#1e293b] border border-slate-700/80 rounded-xl p-5">
            <h2 className="text-xs font-bold text-slate-400 uppercase tracking-widest mb-3">Source Alert</h2>
            {activeAlert ? (
              <div className="p-3 bg-slate-800/50 rounded-lg border border-slate-700/40">
                <div className="flex items-center gap-2 mb-2 flex-wrap">
                  <SeverityBadge severity={activeAlert.severity || 'HIGH'} size="sm" />
                  <span className="text-[10px] font-mono text-slate-600">{activeAlert.alert_id}</span>
                </div>
                <p className="text-xs font-semibold text-slate-200 truncate">{activeAlert.attack_type}</p>
                <p className="text-[11px] text-slate-500 mt-1 font-mono">{activeAlert.source_ip}</p>
              </div>
            ) : (
              <div className="p-3 bg-slate-800/50 rounded-lg border border-slate-700/40 text-center">
                <p className="text-xs text-slate-500">No alert selected</p>
              </div>
            )}
            <p className="text-[10px] text-slate-600 mt-2">Select different alert on the Alerts page</p>
          </div>

          {/* Report Type */}
          <div className="bg-[#1e293b] border border-slate-700/80 rounded-xl p-5">
            <h2 className="text-xs font-bold text-slate-400 uppercase tracking-widest mb-3">Report Type</h2>
            <div className="space-y-2">
              {REPORT_TYPES.map(t => (
                <label key={t.id} className={`block p-3.5 rounded-xl border cursor-pointer transition-all ${reportType === t.id ? 'bg-blue-600/10 border-blue-500/40' : 'bg-slate-800/30 border-slate-700/40 hover:border-slate-600'}`}>
                  <input type="radio" name="reportType" value={t.id} checked={reportType === t.id} onChange={() => setReportType(t.id as any)} className="sr-only" />
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-sm font-semibold text-slate-200">{t.icon} {t.title}</span>
                    <span className="text-[10px] text-slate-500">{t.pages}p</span>
                  </div>
                  <p className="text-[11px] text-slate-500 leading-relaxed">{t.desc}</p>
                </label>
              ))}
            </div>
          </div>

          <button onClick={handleGenerate} disabled={loading}
            className="w-full flex items-center justify-center gap-2 py-3 bg-blue-600 hover:bg-blue-700 disabled:bg-slate-700 text-white text-sm font-semibold rounded-xl transition-colors">
            {loading ? <><Loader2 className="w-4 h-4 animate-spin" /> Generating…</> : <><FileText className="w-4 h-4" /> Generate Report</>}
          </button>
        </div>

        {/* Preview panel */}
        <div className="lg:col-span-2 space-y-4">
          {/* Report preview */}
          {generatedReport ? (
            <div className="bg-[#1e293b] border border-green-500/20 rounded-xl p-6 space-y-5 animate-fade-in">
              {/* Header */}
              <div className="flex items-start justify-between border-b border-slate-800 pb-4">
                <div>
                  <div className="flex items-center gap-2 mb-2">
                    <CheckCircle2 className="w-5 h-5 text-green-400" />
                    <span className="text-xs font-bold text-green-400 uppercase tracking-widest">Report Ready</span>
                  </div>
                  <h3 className="text-lg font-bold text-slate-100">{generatedReport.title}</h3>
                  <p className="text-[11px] font-mono text-slate-500 mt-1">{generatedReport.report_id}</p>
                </div>
                <button onClick={handleGenerate} className="p-2 rounded-lg bg-slate-800 border border-slate-700 text-slate-400 hover:text-slate-200 transition-colors" title="Regenerate">
                  <RefreshCw className="w-4 h-4" />
                </button>
              </div>

              {/* Metadata grid */}
              <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
                {[
                  { icon: <Clock className="w-3.5 h-3.5" />, label: 'Generated', val: format(new Date(generatedReport.generated_at), 'MMM d, HH:mm') },
                  { icon: <User className="w-3.5 h-3.5" />, label: 'Generated By', val: 'LogSentry Engine' },
                  { icon: <FileText className="w-3.5 h-3.5" />, label: 'Report Type', val: generatedReport.report_type.charAt(0).toUpperCase() + generatedReport.report_type.slice(1) },
                  { icon: <Shield className="w-3.5 h-3.5" />, label: 'Severity', val: generatedReport.severity || activeAlert?.severity || 'UNKNOWN' },
                ].map(item => (
                  <div key={item.label} className="p-3 bg-slate-800/40 rounded-xl border border-slate-700/40">
                    <div className="flex items-center gap-1.5 text-slate-500 mb-1.5 text-[10px] font-bold uppercase">{item.icon}{item.label}</div>
                    <p className="text-sm font-semibold text-slate-200">{item.val}</p>
                  </div>
                ))}
              </div>

              <div className="flex gap-4 mb-4 items-center">
                <button onClick={() => window.print()} className="flex items-center gap-2 px-6 py-2.5 bg-blue-600 hover:bg-blue-700 text-white font-semibold rounded-lg text-sm transition-colors shadow-lg shadow-blue-900/20">
                  <Printer className="w-4 h-4" /> Print to PDF
                </button>
                <div className="flex-1" />
                {[
                  { fmt: 'pdf' as const, label: 'Download Raw Data' },
                  { fmt: 'csv' as const, label: 'Export CSV (ZIP)' },
                  { fmt: 'json' as const, label: 'Export JSON' },
                ].map(({ fmt, label }) => (
                  <button key={fmt} onClick={() => handleDownload(fmt)}
                    className={`flex items-center gap-2 px-3 py-2 rounded-lg border border-slate-700 bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-semibold transition-colors`}>
                    <Download className={`w-3.5 h-3.5`} /> {label}
                  </button>
                ))}
              </div>

              {/* LIVE PDF PREVIEW (A4 Document Format) */}
              <div className="bg-white rounded-xl shadow-2xl mx-auto overflow-hidden text-slate-900 print:w-[210mm] print:shadow-none print:mx-0 w-full max-w-[800px]">
                {/* Report Cover */}
                <div className="p-12 border-b-8 border-blue-900 bg-slate-50 relative">
                  <div className="absolute top-0 right-0 w-64 h-64 bg-blue-100 rounded-bl-full -z-0 opacity-50" />
                  <div className="relative z-10">
                    <div className="flex items-center justify-between mb-24">
                      <div className="flex items-center gap-3">
                        <div className="p-2.5 bg-blue-900 rounded-lg"><Shield className="w-8 h-8 text-white" /></div>
                        <div>
                          <h1 className="text-2xl font-black text-slate-900 tracking-tight">LogSentry</h1>
                          <p className="text-[10px] font-bold text-slate-500 uppercase tracking-widest">Enterprise SIEM</p>
                        </div>
                      </div>
                      <div className="text-right">
                        <p className="text-[10px] font-bold text-slate-500 uppercase tracking-widest mb-1">Confidentiality</p>
                        <p className="text-sm font-bold text-red-600 border border-red-200 bg-red-50 px-3 py-1 rounded">TLP: RED (RESTRICTED)</p>
                      </div>
                    </div>

                    <p className="text-sm font-bold text-blue-600 uppercase tracking-widest mb-2">{generatedReport.report_type} Security Report</p>
                    <h2 className="text-4xl font-black text-slate-900 mb-6 leading-tight">{generatedReport.title}</h2>
                    
                    <div className="grid grid-cols-2 gap-8 max-w-lg mt-12">
                      <div>
                        <p className="text-[10px] font-bold text-slate-500 uppercase tracking-widest mb-1">Generated Date</p>
                        <p className="text-sm font-bold text-slate-900">{format(new Date(generatedReport.generated_at), 'MMMM do, yyyy HH:mm')}</p>
                      </div>
                      <div>
                        <p className="text-[10px] font-bold text-slate-500 uppercase tracking-widest mb-1">Report ID</p>
                        <p className="text-sm font-bold font-mono text-slate-900">{generatedReport.report_id}</p>
                      </div>
                      <div>
                        <p className="text-[10px] font-bold text-slate-500 uppercase tracking-widest mb-1">Severity</p>
                        <p className={`text-sm font-bold ${generatedReport.severity === 'CRITICAL' ? 'text-red-600' : 'text-orange-600'}`}>{generatedReport.severity}</p>
                      </div>
                      <div>
                        <p className="text-[10px] font-bold text-slate-500 uppercase tracking-widest mb-1">Prepared By</p>
                        <p className="text-sm font-bold text-slate-900">LogSentry AI Forensics</p>
                      </div>
                    </div>
                  </div>
                </div>

                <div className="p-12 space-y-12">
                  {/* Executive Summary */}
                  <section>
                    <h3 className="text-lg font-black text-slate-900 uppercase tracking-widest border-b-2 border-slate-200 pb-2 mb-4 flex items-center gap-2"><Building2 className="w-5 h-5 text-blue-600" /> Executive Summary</h3>
                    <p className="text-sm text-slate-700 leading-relaxed font-serif">
                      On {format(new Date(generatedReport.generated_at), 'MMM d, yyyy')}, the LogSentry Detection Engine identified a high-confidence <strong className="text-slate-900">{generatedReport.attack_type}</strong> originating from <strong className="text-slate-900 font-mono">{generatedReport.source_ip}</strong>. 
                      The attack targeted internal assets and triggered immediate triage. Automated AI assessment indicates a high probability of malicious intent, mapping to MITRE ATT&CK techniques. Immediate containment is recommended.
                    </p>
                  </section>

                  {/* Incident Details Grid */}
                  <section>
                    <h3 className="text-lg font-black text-slate-900 uppercase tracking-widest border-b-2 border-slate-200 pb-2 mb-4 flex items-center gap-2"><Target className="w-5 h-5 text-red-600" /> Incident Context</h3>
                    <div className="grid grid-cols-2 gap-x-8 gap-y-4 text-sm">
                      <div className="border-b border-slate-100 pb-2"><span className="font-bold text-slate-500">Source IP:</span> <span className="float-right font-mono font-bold">{generatedReport.source_ip}</span></div>
                      <div className="border-b border-slate-100 pb-2"><span className="font-bold text-slate-500">Target Asset:</span> <span className="float-right font-mono font-bold">{activeAlert?.endpoint || 'Unknown'}</span></div>
                      <div className="border-b border-slate-100 pb-2"><span className="font-bold text-slate-500">Attack Type:</span> <span className="float-right font-bold">{generatedReport.attack_type}</span></div>
                      <div className="border-b border-slate-100 pb-2"><span className="font-bold text-slate-500">MITRE Technique:</span> <span className="float-right font-bold font-mono text-orange-600">{activeAlert?.mitre_technique || 'N/A'}</span></div>
                    </div>
                  </section>

                  {/* AI Analysis (If Incident Report) */}
                  {reportType === 'incident' && (
                    <section>
                      <h3 className="text-lg font-black text-slate-900 uppercase tracking-widest border-b-2 border-slate-200 pb-2 mb-4 flex items-center gap-2"><BrainCircuit className="w-5 h-5 text-purple-600" /> Technical AI Assessment</h3>
                      <div className="bg-slate-50 p-6 rounded-lg border border-slate-200">
                        <p className="text-sm text-slate-700 leading-relaxed font-mono whitespace-pre-wrap">{aiAnalysis?.technical_explanation || 'No technical assessment available.'}</p>
                        <div className="mt-6 pt-6 border-t border-slate-200">
                          <p className="text-xs font-bold text-slate-500 uppercase mb-2">Recommended Mitigation</p>
                          <p className="text-sm text-slate-900 font-semibold">{aiAnalysis?.recommended_actions || 'Isolate asset and review logs.'}</p>
                        </div>
                      </div>
                    </section>
                  )}

                  {/* Extracted Evidence */}
                  <section>
                    <h3 className="text-lg font-black text-slate-900 uppercase tracking-widest border-b-2 border-slate-200 pb-2 mb-4 flex items-center gap-2"><FileText className="w-5 h-5 text-emerald-600" /> Extracted Evidence</h3>
                    <div className="bg-slate-900 text-slate-300 p-4 rounded-lg font-mono text-[10px] leading-relaxed break-all shadow-inner">
                      {activeAlert?.raw_log_reference || JSON.stringify(activeAlert?.evidence || {}, null, 2)}
                    </div>
                  </section>

                  {/* Footer */}
                  <div className="pt-12 mt-12 border-t-2 border-slate-100 text-center text-xs text-slate-500 font-bold uppercase tracking-widest">
                    LogSentry Automated Reporting Engine · Page 1 of 1 · End of Document
                  </div>
                </div>
              </div>
            </div>
          ) : (
            <div className="bg-[#1e293b] border border-slate-700/80 rounded-xl p-12 flex flex-col items-center text-center shadow-xl">
              <div className="p-5 bg-slate-800/60 rounded-2xl border border-slate-700 mb-5 relative group">
                <FileText className="w-12 h-12 text-slate-500 group-hover:text-blue-400 transition-colors" />
                <div className="absolute -bottom-2 -right-2 p-1.5 bg-blue-500 rounded-full animate-bounce">
                  <Download className="w-3 h-3 text-white" />
                </div>
              </div>
              <p className="text-lg font-bold text-slate-200">No Report Generated</p>
              <p className="text-sm text-slate-500 mt-2 max-w-sm leading-relaxed">Configure report settings on the left and click "Generate Report" to build a professional, print-ready document.</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
