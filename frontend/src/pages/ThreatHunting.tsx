import { useState } from 'react';
import { useMutation } from '@tanstack/react-query';
import {
  Search, Bot, Sparkles, Database,
  Zap, Table, Clock, CheckCircle2,
} from 'lucide-react';
import { huntingService, type CopilotResponse, type ColumnarQueryResult } from '../services/huntingService';

const EXAMPLE_QUERIES = [
  'Find all failed root logins and SSH brute force attempts',
  'Show all PowerShell download cradles using WebClient or IEX',
  'Find SQL injection attacks and UNION SELECT probes',
  'Search for internal server errors (status 500) on admin endpoints',
  'Find command injection probes with cat or passwd',
];

const EXAMPLE_SQL = [
  { label: 'Top Attacking IPs', sql: 'SELECT source_ip, COUNT(*) as hit_count, COUNT(DISTINCT path) as endpoints FROM logs GROUP BY source_ip ORDER BY hit_count DESC LIMIT 10' },
  { label: 'HTTP Status Code Breakdown', sql: 'SELECT status_code, COUNT(*) as frequency FROM logs GROUP BY status_code ORDER BY frequency DESC' },
  { label: 'Active Ingestion Parsers', sql: 'SELECT source_type as parser, COUNT(*) as events FROM logs GROUP BY source_type ORDER BY events DESC' },
];

export default function ThreatHunting() {
  const [activeTab, setActiveTab] = useState<'copilot' | 'duckdb'>('copilot');

  // Copilot state
  const [naturalPrompt, setNaturalPrompt] = useState('Find all failed root logins and SSH brute force attempts');
  const [copilotData, setCopilotData] = useState<CopilotResponse | null>(null);

  // DuckDB state
  const [sqlQuery, setSqlQuery] = useState(EXAMPLE_SQL[0].sql);
  const [duckdbData, setDuckdbData] = useState<ColumnarQueryResult | null>(null);

  // Mutations
  const copilotMutation = useMutation({
    mutationFn: (prompt: string) => huntingService.askCopilot(prompt),
    onSuccess: (data) => setCopilotData(data),
  });

  const duckdbMutation = useMutation({
    mutationFn: (query: string) => huntingService.runColumnarQuery(query),
    onSuccess: (data) => setDuckdbData(data),
  });

  return (
    <div className="space-y-6 max-w-7xl mx-auto pb-12">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-[var(--border-subtle)]">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="p-1.5 rounded-lg bg-purple-500/10 text-purple-800 dark:text-purple-300 border border-purple-500/20">
              <Bot className="w-5 h-5" />
            </span>
            <h1 className="text-2xl font-black tracking-tight text-[var(--text-primary)]">
              AI Threat Hunting & Forensics Hub
            </h1>
            <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[11px] font-semibold bg-blue-500/10 text-blue-800 dark:text-blue-300 border border-blue-500/20">
              <Zap className="w-3.5 h-3.5 text-blue-800 dark:text-blue-300" />
              DuckDB Sub-Second Engine
            </span>
          </div>
          <p className="text-xs text-[var(--text-muted)]">
            Investigate hypotheses using conversational natural language or execute high-speed columnar analytical SQL queries.
          </p>
        </div>

        {/* View Toggle */}
        <div className="flex p-1 bg-[var(--bg-card)] border border-[var(--border-default)] rounded-xl shadow-xs">
          <button
            onClick={() => setActiveTab('copilot')}
            className={`inline-flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-bold transition-all cursor-pointer ${
              activeTab === 'copilot'
                ? 'bg-purple-600 text-white shadow-xs'
                : 'text-[var(--text-secondary)] hover:text-[var(--text-primary)]'
            }`}
          >
            <Sparkles className="w-3.5 h-3.5" />
            AI Query Copilot
          </button>
          <button
            onClick={() => setActiveTab('duckdb')}
            className={`inline-flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-bold transition-all cursor-pointer ${
              activeTab === 'duckdb'
                ? 'bg-blue-600 text-white shadow-xs'
                : 'text-[var(--text-secondary)] hover:text-[var(--text-primary)]'
            }`}
          >
            <Database className="w-3.5 h-3.5" />
            DuckDB Columnar SQL
          </button>
        </div>
      </div>

      {/* VIEW 1: AI THREAT HUNTING COPILOT */}
      {activeTab === 'copilot' && (
        <div className="space-y-6">
          {/* Natural Language Search Input */}
          <div className="bg-[var(--bg-card)] border border-[var(--border-default)] rounded-xl p-6 shadow-xs">
            <h2 className="text-sm font-bold text-[var(--text-primary)] mb-1 flex items-center gap-2">
              <Bot className="w-4 h-4 text-purple-800 dark:text-purple-300" />
              Ask the AI Threat Hunter
            </h2>
            <p className="text-xs text-[var(--text-muted)] mb-4">
              Enter your investigation hypothesis in plain English. The copilot translates it into precision Lucene filter syntax and executes the search instantly.
            </p>

            <div className="flex gap-2">
              <div className="relative flex-1">
                <Search className="w-4 h-4 text-[var(--text-muted)] absolute left-3.5 top-3" />
                <input
                  type="text"
                  value={naturalPrompt}
                  onChange={(e) => setNaturalPrompt(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && copilotMutation.mutate(naturalPrompt)}
                  placeholder="e.g. Find all failed root logins from external IPs in the last 4 hours..."
                  className="w-full pl-10 pr-4 py-2.5 rounded-xl bg-[var(--bg-input)] border border-[var(--border-default)] text-xs text-[var(--text-primary)] focus:outline-hidden focus:ring-2 focus:ring-purple-500/50"
                />
              </div>

              <button
                onClick={() => copilotMutation.mutate(naturalPrompt)}
                disabled={copilotMutation.isPending}
                className="px-5 py-2.5 rounded-xl bg-purple-600 hover:bg-purple-700 text-white text-xs font-bold transition-all flex items-center gap-2 shadow-xs cursor-pointer disabled:opacity-50"
              >
                <Sparkles className={`w-4 h-4 ${copilotMutation.isPending ? 'animate-spin' : ''}`} />
                {copilotMutation.isPending ? 'Translating...' : 'Hunt'}
              </button>
            </div>

            {/* Quick Chips */}
            <div className="flex flex-wrap items-center gap-2 mt-4 pt-3 border-t border-[var(--border-subtle)]">
              <span className="text-[11px] font-bold text-[var(--text-muted)]">Example Hypotheses:</span>
              {EXAMPLE_QUERIES.map((q, i) => (
                <button
                  key={i}
                  onClick={() => {
                    setNaturalPrompt(q);
                    copilotMutation.mutate(q);
                  }}
                  className="text-[11px] px-2.5 py-1 rounded-lg bg-[var(--bg-card-subtle)] hover:bg-purple-500/10 hover:text-purple-800 dark:hover:text-purple-300 border border-[var(--border-subtle)] text-[var(--text-secondary)] transition-all cursor-pointer truncate max-w-xs"
                >
                  {q}
                </button>
              ))}
            </div>
          </div>

          {/* Copilot Result & Tactical Analysis */}
          {copilotData && (
            <div className="space-y-4">
              <div className="p-5 rounded-xl bg-purple-500/10 border border-purple-500/20 shadow-xs">
                <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 mb-3">
                  <div className="flex items-center gap-2">
                    <span className="px-2.5 py-1 rounded-md text-[11px] font-mono font-bold bg-purple-600 text-white shadow-xs">
                      Lucene: {copilotData.translated_lucene}
                    </span>
                    {copilotData.target_mitre && (
                      <span className="px-2 py-0.5 rounded text-[11px] font-bold bg-orange-500/15 text-orange-800 dark:text-orange-300 border border-orange-500/30">
                        {copilotData.target_mitre}
                      </span>
                    )}
                  </div>
                  <span className="text-xs font-mono font-semibold text-[var(--text-muted)] flex items-center gap-1">
                    <Clock className="w-3.5 h-3.5" />
                    {copilotData.search_result.execution_time_ms.toFixed(1)}ms execution
                  </span>
                </div>

                <p className="text-xs font-semibold text-[var(--text-primary)]">
                  {copilotData.ai_tactical_summary}
                </p>
                <p className="text-[11px] text-[var(--text-muted)] mt-1">
                  Reasoning: {copilotData.reasoning}
                </p>
              </div>

              {/* Matched Logs Table */}
              <div className="bg-[var(--bg-card)] border border-[var(--border-default)] rounded-xl overflow-hidden shadow-xs">
                <div className="p-4 border-b border-[var(--border-subtle)] flex items-center justify-between">
                  <h3 className="text-xs font-bold text-[var(--text-primary)] flex items-center gap-2">
                    <Table className="w-3.5 h-3.5 text-blue-800 dark:text-blue-300" />
                    Matched Telemetry Events ({copilotData.search_result.total_hits} hits)
                  </h3>
                  <span className="text-[11px] text-[var(--text-muted)] font-mono">
                    Showing top {copilotData.search_result.results.length} results
                  </span>
                </div>

                <div className="overflow-x-auto">
                  <table className="w-full text-left border-collapse text-xs">
                    <thead>
                      <tr className="border-b border-[var(--border-subtle)] bg-[var(--bg-card-subtle)]/50 text-[11px] font-bold text-[var(--text-muted)] uppercase tracking-wider">
                        <th className="py-2.5 px-3">Timestamp</th>
                        <th className="py-2.5 px-3">Source IP</th>
                        <th className="py-2.5 px-3">Method</th>
                        <th className="py-2.5 px-3">Endpoint / Resource</th>
                        <th className="py-2.5 px-3 text-center">Status</th>
                        <th className="py-2.5 px-3">Raw Log</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-[var(--border-subtle)] font-mono text-[11px]">
                      {copilotData.search_result.results.map((ev, i) => (
                        <tr key={i} className="hover:bg-[var(--bg-card-hover)] transition-colors">
                          <td className="py-2 px-3 text-[var(--text-muted)]">{ev.timestamp?.slice(11, 19) || '—'}</td>
                          <td className="py-2 px-3 text-blue-800 dark:text-blue-300 font-bold">{ev.source_ip || '127.0.0.1'}</td>
                          <td className="py-2 px-3 text-[var(--text-secondary)]">{ev.method || 'GET'}</td>
                          <td className="py-2 px-3 text-[var(--text-primary)] truncate max-w-xs">{ev.endpoint || '/'}</td>
                          <td className="py-2 px-3 text-center">
                            <span className={`px-1.5 py-0.2 rounded text-[10px] font-bold ${
                              String(ev.status_code).startsWith('2') ? 'bg-emerald-500/10 text-emerald-800 dark:text-emerald-300' : 'bg-red-500/10 text-red-800 dark:text-red-300'
                            }`}>
                              {ev.status_code || 200}
                            </span>
                          </td>
                          <td className="py-2 px-3 text-[var(--text-muted)] truncate max-w-sm">{ev.raw_log}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* VIEW 2: DUCKDB COLUMNAR SQL CONSOLE */}
      {activeTab === 'duckdb' && (
        <div className="space-y-6">
          <div className="bg-[var(--bg-card)] border border-[var(--border-default)] rounded-xl p-6 shadow-xs">
            <div className="flex items-center justify-between mb-2">
              <h2 className="text-sm font-bold text-[var(--text-primary)] flex items-center gap-2">
                <Database className="w-4 h-4 text-blue-800 dark:text-blue-300" />
                DuckDB Vectorized Columnar SQL Console
              </h2>
              <span className="text-[11px] font-mono text-emerald-800 dark:text-emerald-300 font-bold bg-emerald-500/10 px-2 py-0.5 rounded border border-emerald-500/20">
                Vectorized SIMD Engine
              </span>
            </div>
            <p className="text-xs text-[var(--text-muted)] mb-4">
              Query millions of telemetry records with sub-second execution speeds. Table available: <code>logs (id, timestamp, source, source_type, source_ip, http_method, path, status_code)</code>
            </p>

            <div className="relative">
              <textarea
                value={sqlQuery}
                onChange={(e) => setSqlQuery(e.target.value)}
                rows={3}
                className="w-full p-4 rounded-xl bg-slate-950 text-slate-100 text-xs font-mono border border-slate-800 focus:outline-hidden focus:ring-1 focus:ring-blue-500"
              />
            </div>

            <div className="flex flex-wrap items-center justify-between gap-3 mt-4 pt-3 border-t border-[var(--border-subtle)]">
              <div className="flex flex-wrap gap-2">
                <span className="text-[11px] font-bold text-[var(--text-muted)]">Presets:</span>
                {EXAMPLE_SQL.map((preset, i) => (
                  <button
                    key={i}
                    onClick={() => {
                      setSqlQuery(preset.sql);
                      duckdbMutation.mutate(preset.sql);
                    }}
                    className="text-[11px] px-2.5 py-1 rounded-lg bg-[var(--bg-card-subtle)] hover:bg-blue-500/10 hover:text-blue-800 dark:hover:text-blue-300 border border-[var(--border-subtle)] text-[var(--text-secondary)] transition-all cursor-pointer"
                  >
                    {preset.label}
                  </button>
                ))}
              </div>

              <button
                onClick={() => duckdbMutation.mutate(sqlQuery)}
                disabled={duckdbMutation.isPending}
                className="px-5 py-2 rounded-lg bg-blue-600 hover:bg-blue-700 text-white text-xs font-bold transition-all flex items-center gap-2 shadow-xs cursor-pointer disabled:opacity-50"
              >
                <Zap className={`w-3.5 h-3.5 ${duckdbMutation.isPending ? 'animate-bounce' : ''}`} />
                {duckdbMutation.isPending ? 'Executing SQL...' : 'Execute Vectorized Query'}
              </button>
            </div>
          </div>

          {/* DuckDB Tabular Results */}
          {duckdbData && (
            <div className="bg-[var(--bg-card)] border border-[var(--border-default)] rounded-xl overflow-hidden shadow-xs">
              <div className="p-4 border-b border-[var(--border-subtle)] flex items-center justify-between bg-[var(--bg-card-subtle)]/50">
                <div className="flex items-center gap-2">
                  <CheckCircle2 className="w-4 h-4 text-emerald-800 dark:text-emerald-300" />
                  <span className="text-xs font-bold text-[var(--text-primary)]">
                    {duckdbData.summary}
                  </span>
                </div>
                <span className="px-2 py-0.5 rounded text-[11px] font-mono font-bold bg-blue-500/10 text-blue-800 dark:text-blue-300 border border-blue-500/20">
                  {duckdbData.execution_time_ms} ms
                </span>
              </div>

              <div className="overflow-x-auto">
                <table className="w-full text-left border-collapse text-xs">
                  <thead>
                    <tr className="border-b border-[var(--border-subtle)] bg-[var(--bg-card-subtle)] text-[11px] font-bold text-[var(--text-muted)] uppercase tracking-wider">
                      {duckdbData.columns.map((col, idx) => (
                        <th key={idx} className="py-3 px-4 font-mono">{col}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[var(--border-subtle)] font-mono text-xs">
                    {duckdbData.rows.map((row, rIdx) => (
                      <tr key={rIdx} className="hover:bg-[var(--bg-card-hover)] transition-colors">
                        {row.map((cell, cIdx) => (
                          <td key={cIdx} className="py-2.5 px-4 text-[var(--text-primary)]">
                            {String(cell ?? 'NULL')}
                          </td>
                        ))}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
