import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { threatIntelService } from '../services/threatIntelService';
import { EmptyState, Toast } from '../components/ui';
import {
  ShieldAlert, Search, Globe, Shield, Server, CheckCircle2, XCircle,
  Clock, AlertTriangle, ExternalLink, Target, Cpu, Activity,
  MapPin, Hash, Building2, History, Network, Lock, Eye, Filter,
  Check, RefreshCw, AlertOctagon, UserCheck, KeyRound, ShieldCheck
} from 'lucide-react';

interface ThreatStats {
  total_observables: number;
  total_matches: number;
  malicious_matches: number;
  suspicious_matches: number;
  exposed_matches: number;
  unreviewed_matches: number;
  total_sources: number;
  healthy_sources: number;
  telemetry?: {
    events_processed: number;
    observables_extracted: number;
    local_matches: number;
    background_lookups_queued: number;
    background_lookups_completed: number;
    cache_hits: number;
    cache_misses: number;
    cache_hit_ratio: number;
    errors_total: number;
  };
}

interface ThreatMatch {
  id: string;
  observable_id: string;
  observable_value: string;
  observable_type: string;
  raw_masked: string;
  classification: string;
  confidence: number;
  verdict_reason: string;
  event_id: string | null;
  alert_id: string | null;
  incident_id: string | null;
  review_status: string;
  reviewed_by: string | null;
  analyst_notes: string | null;
  tenant_id: string;
  matched_at: string;
}

interface ThreatSource {
  id: string;
  name: string;
  category: string;
  reliability_tier: number;
  is_enabled: boolean;
  health_status: string;
  supported_types: string[];
  rate_limit_state: any;
  last_sync: string | null;
}

export default function ThreatIntel() {
  const queryClient = useQueryClient();
  const [activeTab, setActiveTab] = useState<'investigate' | 'matches' | 'sources' | 'audit'>('investigate');
  const [indicatorInput, setIndicatorInput] = useState('');
  const [forceExternal, setForceExternal] = useState(false);
  const [investigationResult, setInvestigationResult] = useState<any | null>(null);
  const [unmaskedValues, setUnmaskedValues] = useState<Record<string, string>>({});
  const [toast, setToast] = useState<{ msg: string; type: 'success' | 'error' } | null>(null);

  // Review modal state
  const [reviewMatchId, setReviewMatchId] = useState<string | null>(null);
  const [reviewStatus, setReviewStatus] = useState('confirmed_threat');
  const [reviewNotes, setReviewNotes] = useState('');

  // Unmask Mutation
  const unmaskMutation = useMutation({
    mutationFn: (observableId: string) => threatIntelService.unmaskObservable(observableId),
    onSuccess: (data) => {
      setUnmaskedValues((prev) => ({ ...prev, [data.observable_id]: data.unmasked_value }));
      refetchAudits();
      setToast({
        msg: `Decrypted PII observable: ${data.unmasked_value} (Audit event logged)`,
        type: 'success',
      });
    },
    onError: (err: any) => {
      setToast({
        msg: err.response?.data?.detail || 'Failed to unmask observable (requires SOC Manager or Admin)',
        type: 'error',
      });
    },
  });

  // Queries
  const { data: stats } = useQuery<ThreatStats>({
    queryKey: ['tiore-stats'],
    queryFn: threatIntelService.getStats,
    refetchInterval: 15000,
  });

  const { data: matches, refetch: refetchMatches } = useQuery<ThreatMatch[]>({
    queryKey: ['tiore-matches'],
    queryFn: () => threatIntelService.getMatches(),
    refetchInterval: 10000,
  });

  const { data: sources } = useQuery<ThreatSource[]>({
    queryKey: ['tiore-sources'],
    queryFn: threatIntelService.getSources,
  });

  const { data: audits, refetch: refetchAudits } = useQuery<any[]>({
    queryKey: ['tiore-audit'],
    queryFn: () => threatIntelService.getAudit(50),
    refetchInterval: 15000,
  });

  // Lookup Mutation
  const lookupMutation = useMutation({
    mutationFn: (indicator: string) => threatIntelService.lookupIndicator(indicator, forceExternal),
    onSuccess: (data) => {
      setInvestigationResult(data);
      refetchAudits();
      queryClient.invalidateQueries({ queryKey: ['tiore-stats'] });
      setToast({
        msg: `Investigated ${data.observable.masked_value} — Verdict: ${data.reputation.classification}`,
        type: 'success',
      });
    },
    onError: (err: any) => {
      setToast({
        msg: err?.response?.data?.detail || 'Failed to investigate observable.',
        type: 'error',
      });
    },
  });

  // Match Review Mutation
  const reviewMutation = useMutation({
    mutationFn: ({ matchId, status, notes }: { matchId: string; status: string; notes?: string }) =>
      threatIntelService.reviewMatch(matchId, status, notes),
    onSuccess: () => {
      refetchMatches();
      queryClient.invalidateQueries({ queryKey: ['tiore-stats'] });
      setReviewMatchId(null);
      setReviewNotes('');
      setToast({ msg: 'Threat match triage status updated successfully.', type: 'success' });
    },
    onError: (err: any) => {
      setToast({ msg: err?.response?.data?.detail || 'Failed to update review status.', type: 'error' });
    },
  });

  const handleLookup = (e: React.FormEvent) => {
    e.preventDefault();
    if (!indicatorInput.trim()) return;
    lookupMutation.mutate(indicatorInput.trim());
  };

  const setAndLookup = (val: string) => {
    setIndicatorInput(val);
    lookupMutation.mutate(val);
  };

  return (
    <div className="space-y-6 animate-fade-in pb-12">
      {toast && <Toast message={toast.msg} type={toast.type} onClose={() => setToast(null)} />}

      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-lg bg-orange-500/10 text-orange-400 border border-orange-500/20">
              <ShieldAlert className="w-6 h-6" />
            </div>
            <div>
              <h1 className="text-xl font-bold text-[var(--text-primary)]">Threat Intelligence Center (TIORE)</h1>
              <p className="text-xs text-[var(--text-muted)] mt-0.5">
                Observable reputation, multi-source feed correlation, and privacy-preserving IOC triage.
              </p>
            </div>
          </div>
        </div>

        {/* Tab Navigation */}
        <div className="flex items-center gap-1.5 p-1 bg-[var(--bg-card)] border border-[var(--border-default)] rounded-xl text-xs font-semibold">
          <button
            onClick={() => setActiveTab('investigate')}
            className={`px-3 py-1.5 rounded-lg transition-all flex items-center gap-1.5 ${
              activeTab === 'investigate' ? 'bg-orange-500 text-white shadow-sm' : 'text-[var(--text-secondary)] hover:text-[var(--text-primary)]'
            }`}
          >
            <Search className="w-3.5 h-3.5" /> Indicator Search
          </button>
          <button
            onClick={() => setActiveTab('matches')}
            className={`px-3 py-1.5 rounded-lg transition-all flex items-center gap-1.5 ${
              activeTab === 'matches' ? 'bg-orange-500 text-white shadow-sm' : 'text-[var(--text-secondary)] hover:text-[var(--text-primary)]'
            }`}
          >
            <Target className="w-3.5 h-3.5" /> Threat Matches
            {stats?.unreviewed_matches ? (
              <span className="ml-1 px-1.5 py-0.2 rounded-full text-[10px] bg-red-600 text-white font-bold">
                {stats.unreviewed_matches}
              </span>
            ) : null}
          </button>
          <button
            onClick={() => setActiveTab('sources')}
            className={`px-3 py-1.5 rounded-lg transition-all flex items-center gap-1.5 ${
              activeTab === 'sources' ? 'bg-orange-500 text-white shadow-sm' : 'text-[var(--text-secondary)] hover:text-[var(--text-primary)]'
            }`}
          >
            <Server className="w-3.5 h-3.5" /> Feed Sources
          </button>
          <button
            onClick={() => setActiveTab('audit')}
            className={`px-3 py-1.5 rounded-lg transition-all flex items-center gap-1.5 ${
              activeTab === 'audit' ? 'bg-orange-500 text-white shadow-sm' : 'text-[var(--text-secondary)] hover:text-[var(--text-primary)]'
            }`}
          >
            <Lock className="w-3.5 h-3.5" /> Audit Log
          </button>
        </div>
      </div>

      {/* KPI Overview Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="bg-[var(--bg-card)] border border-[var(--border-default)] rounded-xl p-4 shadow-sm">
          <p className="text-[10px] uppercase font-bold text-[var(--text-muted)] tracking-wider">Tracked Observables</p>
          <p className="text-2xl font-extrabold text-[var(--text-primary)] mt-1">{stats?.total_observables ?? 0}</p>
          <p className="text-[11px] text-[var(--text-muted)] mt-1">Across 6 indicator types</p>
        </div>
        <div className="bg-[var(--bg-card)] border border-[var(--border-default)] rounded-xl p-4 shadow-sm">
          <p className="text-[10px] uppercase font-bold text-red-400 tracking-wider">Active Malicious Threats</p>
          <p className="text-2xl font-extrabold text-red-500 mt-1">{stats?.malicious_matches ?? 0}</p>
          <p className="text-[11px] text-[var(--text-muted)] mt-1">High confidence matches</p>
        </div>
        <div className="bg-[var(--bg-card)] border border-[var(--border-default)] rounded-xl p-4 shadow-sm">
          <p className="text-[10px] uppercase font-bold text-yellow-400 tracking-wider">Triage Needed</p>
          <p className="text-2xl font-extrabold text-yellow-500 mt-1">{stats?.unreviewed_matches ?? 0}</p>
          <p className="text-[11px] text-[var(--text-muted)] mt-1">Unreviewed log correlations</p>
        </div>
        <div className="bg-[var(--bg-card)] border border-[var(--border-default)] rounded-xl p-4 shadow-sm">
          <p className="text-[10px] uppercase font-bold text-green-400 tracking-wider">Feed Health</p>
          <p className="text-2xl font-extrabold text-green-500 mt-1">
            {stats?.healthy_sources ?? 0} / {stats?.total_sources ?? 0}
          </p>
          <p className="text-[11px] text-[var(--text-muted)] mt-1">All adapters operational</p>
        </div>
      </div>

      {/* ==================================================================== */}
      {/* TAB 1: INVESTIGATE                                                    */}
      {/* ==================================================================== */}
      {activeTab === 'investigate' && (
        <div className="grid grid-cols-1 lg:grid-cols-4 gap-5">
          {/* Search Column */}
          <div className="lg:col-span-1 space-y-4">
            <div className="bg-[var(--bg-card)] border border-[var(--border-default)] rounded-xl p-5 shadow-sm">
              <h2 className="text-xs font-bold text-[var(--text-secondary)] uppercase tracking-wider mb-3 flex items-center gap-1.5">
                <Search className="w-4 h-4 text-orange-400" /> Indicator Query
              </h2>
              <form onSubmit={handleLookup} className="space-y-3">
                <div>
                  <input
                    type="text"
                    value={indicatorInput}
                    onChange={(e) => setIndicatorInput(e.target.value)}
                    placeholder="IP, Domain, URL, Hash, Email, Phone..."
                    className="w-full bg-[var(--bg-page)] border border-[var(--border-default)] rounded-lg px-3 py-2.5 text-xs text-[var(--text-primary)] font-mono placeholder-[var(--text-muted)] focus:outline-none focus:border-orange-500"
                  />
                  <p className="text-[10px] text-[var(--text-muted)] mt-1">
                    Supports IPv4/v6, Domains, URLs, MD5/SHA-256, Email, Phone.
                  </p>
                </div>

                <div className="flex items-center gap-2 pt-1 pb-1">
                  <input
                    type="checkbox"
                    id="forceExternal"
                    checked={forceExternal}
                    onChange={(e) => setForceExternal(e.target.checked)}
                    className="rounded border-[var(--border-default)] text-orange-500 focus:ring-0"
                  />
                  <label htmlFor="forceExternal" className="text-xs text-[var(--text-secondary)] select-none">
                    Force External Feed Query
                  </label>
                </div>

                <button
                  type="submit"
                  disabled={lookupMutation.isPending}
                  className="w-full py-2.5 bg-orange-600 hover:bg-orange-700 disabled:opacity-50 text-white text-xs font-bold rounded-lg transition-colors flex items-center justify-center gap-2 shadow-sm"
                >
                  {lookupMutation.isPending ? (
                    <>
                      <Cpu className="w-3.5 h-3.5 animate-spin" /> Resolving Reputation…
                    </>
                  ) : (
                    <>
                      <Search className="w-3.5 h-3.5" /> Investigate Indicator
                    </>
                  )}
                </button>
              </form>

              {/* Quick Preset Indicators */}
              <div className="mt-5 pt-4 border-t border-[var(--border-subtle)]">
                <p className="text-[10px] font-bold text-[var(--text-muted)] uppercase tracking-wider mb-2">
                  Sample Curated IOCs
                </p>
                <div className="space-y-1.5">
                  <button
                    onClick={() => setAndLookup('45.155.205.233')}
                    className="w-full text-left text-xs font-mono px-2 py-1.5 rounded hover:bg-[var(--bg-page)] text-[var(--text-secondary)] hover:text-orange-400 flex items-center justify-between"
                  >
                    <span>45.155.205.233</span>
                    <span className="text-[9px] px-1 py-0.5 rounded bg-red-500/10 text-red-400 border border-red-500/20 font-sans">
                      Log4j Scanner
                    </span>
                  </button>
                  <button
                    onClick={() => setAndLookup('threat-actor.xyz')}
                    className="w-full text-left text-xs font-mono px-2 py-1.5 rounded hover:bg-[var(--bg-page)] text-[var(--text-secondary)] hover:text-orange-400 flex items-center justify-between"
                  >
                    <span>threat-actor.xyz</span>
                    <span className="text-[9px] px-1 py-0.5 rounded bg-red-500/10 text-red-400 border border-red-500/20 font-sans">
                      C2 Domain
                    </span>
                  </button>
                  <button
                    onClick={() => setAndLookup('http://169.254.169.254/latest/meta-data')}
                    className="w-full text-left text-xs font-mono px-2 py-1.5 rounded hover:bg-[var(--bg-page)] text-[var(--text-secondary)] hover:text-orange-400 flex items-center justify-between"
                  >
                    <span className="truncate max-w-[130px]">169.254.169.254</span>
                    <span className="text-[9px] px-1 py-0.5 rounded bg-yellow-500/10 text-yellow-400 border border-yellow-500/20 font-sans">
                      Cloud Metadata
                    </span>
                  </button>
                  <button
                    onClick={() => setAndLookup('275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f')}
                    className="w-full text-left text-xs font-mono px-2 py-1.5 rounded hover:bg-[var(--bg-page)] text-[var(--text-secondary)] hover:text-orange-400 flex items-center justify-between"
                  >
                    <span className="truncate max-w-[130px]">275a021b...fd0f</span>
                    <span className="text-[9px] px-1 py-0.5 rounded bg-red-500/10 text-red-400 border border-red-500/20 font-sans">
                      WannaCry
                    </span>
                  </button>
                </div>
              </div>
            </div>

            {/* Privacy Policy Callout */}
            <div className="bg-[var(--bg-card)] border border-[var(--border-default)] rounded-xl p-4 shadow-sm text-xs text-[var(--text-muted)] space-y-2">
              <div className="flex items-center gap-1.5 font-bold text-[var(--text-secondary)]">
                <ShieldCheck className="w-4 h-4 text-green-400" /> Zero Data Leakage Guarantee
              </div>
              <p className="text-[11px] leading-relaxed">
                RFC 1918 addresses and internal domains are strictly suppressed. Sensitive query strings are redacted.
                PII (emails, phones) is evaluated via tenant-keyed HMAC or k-anonymity prefixes without disclosing raw identifiers.
              </p>
            </div>
          </div>

          {/* Results Column */}
          <div className="lg:col-span-3 space-y-4">
            {!lookupMutation.isPending && !investigationResult && (
              <div className="bg-[var(--bg-card)] border border-[var(--border-default)] rounded-xl h-full flex flex-col justify-center min-h-[420px]">
                <EmptyState
                  icon={<Globe className="w-10 h-10 text-orange-400" />}
                  title="Enter an Indicator to Investigate"
                  desc="Search indicators across local threat database, memory cache, and commercial intelligence providers (AbuseIPDB, OTX, URLhaus, ThreatFox, VirusTotal, HIBP)."
                />
              </div>
            )}

            {lookupMutation.isPending && (
              <div className="bg-[var(--bg-card)] border border-[var(--border-default)] rounded-xl p-16 flex flex-col items-center justify-center min-h-[420px]">
                <Cpu className="w-10 h-10 text-orange-500 animate-spin mb-4" />
                <p className="text-sm font-semibold text-[var(--text-primary)]">Evaluating Observable Reputation…</p>
                <p className="text-xs text-[var(--text-muted)] mt-1">
                  Checking in-memory cache, privacy gate, and multi-source feeds
                </p>
              </div>
            )}

            {!lookupMutation.isPending && investigationResult && (
              <div className="space-y-4">
                {/* Main Verdict Card */}
                <div
                  className={`bg-[var(--bg-card)] border rounded-xl p-6 shadow-sm ${
                    investigationResult.reputation.classification === 'MALICIOUS'
                      ? 'border-red-500/40 bg-red-500/5'
                      : investigationResult.reputation.classification === 'SUSPICIOUS'
                      ? 'border-yellow-500/40 bg-yellow-500/5'
                      : investigationResult.reputation.classification === 'EXPOSED'
                      ? 'border-purple-500/40 bg-purple-500/5'
                      : 'border-green-500/30 bg-green-500/5'
                  }`}
                >
                  <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-4">
                    <div>
                      <div className="flex items-center gap-3 flex-wrap">
                        <span className="text-2xl font-bold font-mono text-[var(--text-primary)]">
                          {unmaskedValues[investigationResult.observable.id] || investigationResult.observable.masked_value}
                        </span>
                        {investigationResult.observable.is_pii && (
                          <button
                            onClick={() => unmaskMutation.mutate(investigationResult.observable.id)}
                            disabled={unmaskMutation.isPending || !!unmaskedValues[investigationResult.observable.id]}
                            className="px-2.5 py-1 text-xs rounded-lg border border-amber-500/30 bg-amber-500/10 text-amber-600 dark:text-amber-400 hover:bg-amber-500/20 flex items-center gap-1.5 transition-colors cursor-pointer"
                            title="Authorized SOC Unmasking (Audited)"
                          >
                            <Lock className="w-3.5 h-3.5" />
                            <span>{unmaskedValues[investigationResult.observable.id] ? 'Decrypted (Audited)' : 'Unmask PII (Audited)'}</span>
                          </button>
                        )}
                        <span
                          className={`px-3 py-1 rounded-md text-xs font-bold border ${
                            investigationResult.reputation.classification === 'MALICIOUS'
                              ? 'text-red-400 bg-red-500/20 border-red-500/40'
                              : investigationResult.reputation.classification === 'SUSPICIOUS'
                              ? 'text-yellow-400 bg-yellow-500/20 border-yellow-500/40'
                              : investigationResult.reputation.classification === 'EXPOSED'
                              ? 'text-purple-400 bg-purple-500/20 border-purple-500/40'
                              : 'text-green-400 bg-green-500/20 border-green-500/40'
                          }`}
                        >
                          {investigationResult.reputation.classification}
                        </span>
                        <span className="px-2 py-0.5 rounded text-[10px] font-bold border border-[var(--border-default)] text-[var(--text-muted)] uppercase">
                          {investigationResult.observable.type}
                        </span>
                        {investigationResult.reputation.is_cached && (
                          <span className="px-2 py-0.5 rounded text-[10px] font-bold border border-blue-500/30 bg-blue-500/10 text-blue-400">
                            {investigationResult.reputation.cache_source?.toUpperCase() || 'CACHED'}
                          </span>
                        )}
                      </div>
                      <p className="text-xs text-[var(--text-secondary)] mt-2 font-medium">
                        {investigationResult.reputation.verdict_reason}
                      </p>
                    </div>

                    <div className="flex items-center gap-4 border-t sm:border-t-0 sm:border-l border-[var(--border-subtle)] pt-3 sm:pt-0 sm:pl-6 shrink-0">
                      <div className="text-center">
                        <p className="text-3xl font-extrabold text-[var(--text-primary)]">
                          {Math.round(investigationResult.reputation.confidence * 100)}%
                        </p>
                        <p className="text-[10px] font-bold uppercase text-[var(--text-muted)] mt-0.5">Confidence</p>
                      </div>
                    </div>
                  </div>

                  {/* Metadata Bar */}
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 mt-6 pt-4 border-t border-[var(--border-subtle)] text-xs">
                    <div>
                      <p className="text-[10px] font-bold text-[var(--text-muted)] uppercase">Privacy Boundary</p>
                      <p className="font-semibold text-[var(--text-secondary)] mt-0.5">
                        {investigationResult.observable.privacy_classification}
                      </p>
                    </div>
                    <div>
                      <p className="text-[10px] font-bold text-[var(--text-muted)] uppercase">External Lookup</p>
                      <p className="font-semibold text-[var(--text-secondary)] mt-0.5">
                        {investigationResult.observable.is_eligible_for_external_lookup ? 'Eligible' : 'Suppressed'}
                      </p>
                    </div>
                    <div>
                      <p className="text-[10px] font-bold text-[var(--text-muted)] uppercase">First Seen</p>
                      <p className="font-semibold text-[var(--text-secondary)] mt-0.5">
                        {investigationResult.observable.first_seen
                          ? new Date(investigationResult.observable.first_seen).toLocaleDateString()
                          : 'Just now'}
                      </p>
                    </div>
                    <div>
                      <p className="text-[10px] font-bold text-[var(--text-muted)] uppercase">Audit Disclosed</p>
                      <p className="font-semibold text-[var(--text-secondary)] mt-0.5">
                        {investigationResult.audit.external_disclosed ? 'Yes (Public Feeds)' : 'No (Local Only)'}
                      </p>
                    </div>
                  </div>
                </div>

                {/* Threat Types & Source Evidence */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {/* Threat Types */}
                  <div className="bg-[var(--bg-card)] border border-[var(--border-default)] rounded-xl p-5 shadow-sm">
                    <h3 className="text-xs font-bold text-[var(--text-muted)] uppercase tracking-wider mb-3 flex items-center gap-1.5">
                      <Target className="w-3.5 h-3.5 text-orange-400" /> Associated Threat Categories
                    </h3>
                    {investigationResult.reputation.threat_types?.length > 0 ? (
                      <div className="flex flex-wrap gap-2">
                        {investigationResult.reputation.threat_types.map((type: string) => (
                          <span
                            key={type}
                            className="px-2.5 py-1 bg-red-500/10 border border-red-500/20 text-red-400 text-xs font-semibold rounded-md"
                          >
                            {type}
                          </span>
                        ))}
                      </div>
                    ) : (
                      <p className="text-xs text-[var(--text-muted)]">No active threat tags associated.</p>
                    )}
                  </div>

                  {/* Fingerprint & Compliance */}
                  <div className="bg-[var(--bg-card)] border border-[var(--border-default)] rounded-xl p-5 shadow-sm">
                    <h3 className="text-xs font-bold text-[var(--text-muted)] uppercase tracking-wider mb-3 flex items-center gap-1.5">
                      <KeyRound className="w-3.5 h-3.5 text-cyan-400" /> Cryptographic Fingerprint
                    </h3>
                    <p className="text-xs font-mono text-[var(--text-secondary)] break-all bg-[var(--bg-page)] p-2.5 rounded-lg border border-[var(--border-default)]">
                      {investigationResult.observable.fingerprint}
                    </p>
                    <p className="text-[10px] text-[var(--text-muted)] mt-2">
                      Keyed HMAC-SHA256 for sensitive PII; SHA-256 canonical hash for public observables.
                    </p>
                  </div>
                </div>

                {/* Source Matches Evidence List */}
                <div className="bg-[var(--bg-card)] border border-[var(--border-default)] rounded-xl p-5 shadow-sm">
                  <h3 className="text-xs font-bold text-[var(--text-muted)] uppercase tracking-wider mb-3">
                    Intelligence Feed Evidence Records
                  </h3>
                  {investigationResult.reputation.source_matches?.length > 0 ? (
                    <div className="space-y-3">
                      {investigationResult.reputation.source_matches.map((match: any, idx: number) => (
                        <div
                          key={idx}
                          className="p-3.5 bg-[var(--bg-page)] border border-[var(--border-default)] rounded-lg text-xs space-y-1.5"
                        >
                          <div className="flex items-center justify-between">
                            <span className="font-bold text-[var(--text-primary)]">{match.source_name}</span>
                            <span className="text-[10px] px-2 py-0.5 rounded font-bold border border-orange-500/20 bg-orange-500/10 text-orange-400">
                              Tier {match.reliability_tier}
                            </span>
                          </div>
                          <div className="text-[11px] text-[var(--text-muted)]">
                            Classification: <span className="font-semibold text-red-400">{match.classification}</span> |
                            Confidence: {Math.round(match.confidence * 100)}%
                          </div>
                          <pre className="text-[10px] font-mono text-[var(--text-secondary)] bg-[var(--bg-card)] p-2 rounded overflow-x-auto">
                            {JSON.stringify(match.evidence, null, 2)}
                          </pre>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <p className="text-xs text-[var(--text-muted)]">
                      No external threat feed matches on record. Observable resolved via local policy.
                    </p>
                  )}
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* ==================================================================== */}
      {/* TAB 2: THREAT MATCHES                                                 */}
      {/* ==================================================================== */}
      {activeTab === 'matches' && (
        <div className="space-y-4">
          <div className="bg-[var(--bg-card)] border border-[var(--border-default)] rounded-xl overflow-hidden shadow-sm">
            <div className="p-4 border-b border-[var(--border-default)] flex items-center justify-between">
              <div>
                <h2 className="text-sm font-bold text-[var(--text-primary)]">Correlated Threat Matches</h2>
                <p className="text-xs text-[var(--text-muted)]">
                  Active threats identified during log ingestion and detection runs.
                </p>
              </div>
              <button
                onClick={() => refetchMatches()}
                className="px-3 py-1.5 bg-[var(--bg-page)] border border-[var(--border-default)] rounded-lg text-xs font-semibold text-[var(--text-secondary)] hover:text-[var(--text-primary)] flex items-center gap-1.5"
              >
                <RefreshCw className="w-3.5 h-3.5" /> Refresh
              </button>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead className="bg-[var(--bg-page)] border-b border-[var(--border-default)] text-[10px] text-[var(--text-muted)] uppercase tracking-wider">
                  <tr>
                    <th className="px-4 py-3 text-left">Classification</th>
                    <th className="px-4 py-3 text-left">Type</th>
                    <th className="px-4 py-3 text-left">Observable</th>
                    <th className="px-4 py-3 text-left">Verdict Reason</th>
                    <th className="px-4 py-3 text-left">Confidence</th>
                    <th className="px-4 py-3 text-left">Review Status</th>
                    <th className="px-4 py-3 text-left">Matched At</th>
                    <th className="px-4 py-3 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[var(--border-subtle)]">
                  {matches && matches.length > 0 ? (
                    matches.map((m) => (
                      <tr key={m.id} className="hover:bg-[var(--bg-page)]/50 transition-colors">
                        <td className="px-4 py-3">
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                              m.classification === 'MALICIOUS'
                                ? 'text-red-400 bg-red-500/10 border-red-500/30'
                                : m.classification === 'SUSPICIOUS'
                                ? 'text-yellow-400 bg-yellow-500/10 border-yellow-500/30'
                                : 'text-purple-400 bg-purple-500/10 border-purple-500/30'
                            }`}
                          >
                            {m.classification}
                          </span>
                        </td>
                        <td className="px-4 py-3 font-semibold uppercase text-[var(--text-muted)] text-[10px]">
                          {m.observable_type}
                        </td>
                        <td className="px-4 py-3 font-mono font-medium text-[var(--text-primary)]">
                          {m.observable_value}
                        </td>
                        <td className="px-4 py-3 text-[var(--text-secondary)] max-w-xs truncate">{m.verdict_reason}</td>
                        <td className="px-4 py-3 font-bold text-[var(--text-primary)]">
                          {Math.round(m.confidence * 100)}%
                        </td>
                        <td className="px-4 py-3">
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                              m.review_status === 'confirmed_threat'
                                ? 'bg-red-500/20 text-red-400'
                                : m.review_status === 'false_positive'
                                ? 'bg-green-500/20 text-green-400'
                                : 'bg-slate-700/50 text-slate-300'
                            }`}
                          >
                            {m.review_status}
                          </span>
                        </td>
                        <td className="px-4 py-3 text-[var(--text-muted)] text-[11px]">
                          {new Date(m.matched_at).toLocaleTimeString()}
                        </td>
                        <td className="px-4 py-3 text-right">
                          <button
                            onClick={() => {
                              setReviewMatchId(m.id);
                              setReviewStatus(m.review_status || 'confirmed_threat');
                              setReviewNotes(m.analyst_notes || '');
                            }}
                            className="px-2.5 py-1 bg-orange-600/15 border border-orange-500/30 hover:bg-orange-600/25 text-orange-400 rounded text-[11px] font-semibold transition-colors"
                          >
                            Triage
                          </button>
                        </td>
                      </tr>
                    ))
                  ) : (
                    <tr>
                      <td colSpan={8} className="px-4 py-8 text-center text-[var(--text-muted)]">
                        No threat matches recorded for this tenant yet.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* ==================================================================== */}
      {/* TAB 3: FEED SOURCES                                                  */}
      {/* ==================================================================== */}
      {activeTab === 'sources' && (
        <div className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {sources && sources.length > 0 ? (
              sources.map((s) => (
                <div
                  key={s.id}
                  className="bg-[var(--bg-card)] border border-[var(--border-default)] rounded-xl p-5 shadow-sm space-y-3"
                >
                  <div className="flex items-start justify-between">
                    <div>
                      <h3 className="font-bold text-sm text-[var(--text-primary)]">{s.name}</h3>
                      <p className="text-[11px] text-[var(--text-muted)] capitalize">{s.category} Feed</p>
                    </div>
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-bold border flex items-center gap-1 ${
                        s.health_status === 'healthy'
                          ? 'text-green-400 bg-green-500/10 border-green-500/20'
                          : 'text-yellow-400 bg-yellow-500/10 border-yellow-500/20'
                      }`}
                    >
                      {s.health_status === 'healthy' ? (
                        <CheckCircle2 className="w-3 h-3" />
                      ) : (
                        <AlertTriangle className="w-3 h-3" />
                      )}
                      {s.health_status.toUpperCase()}
                    </span>
                  </div>

                  <div className="space-y-1.5 text-xs text-[var(--text-secondary)]">
                    <div className="flex justify-between">
                      <span className="text-[var(--text-muted)]">Reliability Tier:</span>
                      <span className="font-semibold text-orange-400">Tier {s.reliability_tier}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-[var(--text-muted)]">Status:</span>
                      <span className="font-semibold text-green-400">Enabled</span>
                    </div>
                  </div>

                  <div className="pt-2 border-t border-[var(--border-subtle)]">
                    <p className="text-[10px] font-bold text-[var(--text-muted)] uppercase mb-1.5">Supported Indicators</p>
                    <div className="flex flex-wrap gap-1">
                      {s.supported_types.map((t) => (
                        <span
                          key={t}
                          className="px-2 py-0.5 rounded bg-[var(--bg-page)] text-[var(--text-secondary)] text-[10px] border border-[var(--border-default)] font-mono uppercase"
                        >
                          {t}
                        </span>
                      ))}
                    </div>
                  </div>
                </div>
              ))
            ) : (
              <div className="col-span-3 text-center py-12 text-[var(--text-muted)]">
                Loading intelligence sources…
              </div>
            )}
          </div>
        </div>
      )}

      {/* ==================================================================== */}
      {/* TAB 4: AUDIT LOG                                                     */}
      {/* ==================================================================== */}
      {activeTab === 'audit' && (
        <div className="bg-[var(--bg-card)] border border-[var(--border-default)] rounded-xl overflow-hidden shadow-sm">
          <div className="p-4 border-b border-[var(--border-default)] flex items-center justify-between">
            <div>
              <h2 className="text-sm font-bold text-[var(--text-primary)]">Analyst Investigation Audit Log</h2>
              <p className="text-xs text-[var(--text-muted)]">
                Compliance trail documenting every manual lookup and external feed disclosure.
              </p>
            </div>
            <button
              onClick={() => refetchAudits()}
              className="px-3 py-1.5 bg-[var(--bg-page)] border border-[var(--border-default)] rounded-lg text-xs font-semibold text-[var(--text-secondary)] hover:text-[var(--text-primary)] flex items-center gap-1.5"
            >
              <RefreshCw className="w-3.5 h-3.5" /> Refresh
            </button>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead className="bg-[var(--bg-page)] border-b border-[var(--border-default)] text-[10px] text-[var(--text-muted)] uppercase tracking-wider">
                <tr>
                  <th className="px-4 py-3 text-left">Timestamp</th>
                  <th className="px-4 py-3 text-left">Analyst</th>
                  <th className="px-4 py-3 text-left">Role</th>
                  <th className="px-4 py-3 text-left">Indicator Type</th>
                  <th className="px-4 py-3 text-left">Masked Observable</th>
                  <th className="px-4 py-3 text-left">External Disclosed</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[var(--border-subtle)]">
                {audits && audits.length > 0 ? (
                  audits.map((a) => (
                    <tr key={a.id} className="hover:bg-[var(--bg-page)]/50 transition-colors">
                      <td className="px-4 py-3 text-[var(--text-muted)] text-[11px]">
                        {new Date(a.timestamp).toLocaleString()}
                      </td>
                      <td className="px-4 py-3 font-semibold text-[var(--text-primary)]">{a.actor_username}</td>
                      <td className="px-4 py-3 text-[var(--text-secondary)]">{a.actor_role}</td>
                      <td className="px-4 py-3 uppercase text-[10px] font-bold text-[var(--text-muted)]">
                        {a.observable_type}
                      </td>
                      <td className="px-4 py-3 font-mono text-[var(--text-primary)]">{a.masked_value}</td>
                      <td className="px-4 py-3">
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                            a.external_disclosed ? 'bg-orange-500/20 text-orange-400' : 'bg-green-500/20 text-green-400'
                          }`}
                        >
                          {a.external_disclosed ? 'Disclosed (Feeds)' : 'Local Only'}
                        </span>
                      </td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan={6} className="px-4 py-8 text-center text-[var(--text-muted)]">
                      No investigation audit records found.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Review Modal Dialog */}
      {reviewMatchId && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
          <div className="bg-[var(--bg-card)] border border-[var(--border-default)] rounded-xl max-w-md w-full p-6 shadow-2xl space-y-4">
            <h3 className="text-base font-bold text-[var(--text-primary)] flex items-center gap-2">
              <UserCheck className="w-5 h-5 text-orange-400" /> Triage Threat Match
            </h3>
            <p className="text-xs text-[var(--text-muted)]">
              Update the investigation review status and add analyst notes for SOC audit records.
            </p>

            <div className="space-y-3">
              <div>
                <label className="text-xs font-semibold text-[var(--text-secondary)] block mb-1">
                  Review Status
                </label>
                <select
                  value={reviewStatus}
                  onChange={(e) => setReviewStatus(e.target.value)}
                  className="w-full bg-[var(--bg-page)] border border-[var(--border-default)] rounded-lg px-3 py-2 text-xs text-[var(--text-primary)]"
                >
                  <option value="confirmed_threat">Confirmed Threat (Escalate)</option>
                  <option value="under_review">Under Active Investigation</option>
                  <option value="false_positive">False Positive</option>
                  <option value="benign_exception">Benign Corporate Exception</option>
                </select>
              </div>

              <div>
                <label className="text-xs font-semibold text-[var(--text-secondary)] block mb-1">
                  Analyst Triage Notes
                </label>
                <textarea
                  value={reviewNotes}
                  onChange={(e) => setReviewNotes(e.target.value)}
                  placeholder="Document findings, remediation action, or false-positive rationale..."
                  rows={3}
                  className="w-full bg-[var(--bg-page)] border border-[var(--border-default)] rounded-lg p-2.5 text-xs text-[var(--text-primary)]"
                />
              </div>
            </div>

            <div className="flex justify-end gap-2 pt-2">
              <button
                onClick={() => setReviewMatchId(null)}
                className="px-4 py-2 bg-[var(--bg-page)] border border-[var(--border-default)] rounded-lg text-xs font-semibold text-[var(--text-secondary)] hover:text-[var(--text-primary)]"
              >
                Cancel
              </button>
              <button
                onClick={() =>
                  reviewMutation.mutate({
                    matchId: reviewMatchId,
                    status: reviewStatus,
                    notes: reviewNotes,
                  })
                }
                disabled={reviewMutation.isPending}
                className="px-4 py-2 bg-orange-600 hover:bg-orange-700 text-white rounded-lg text-xs font-bold disabled:opacity-50"
              >
                {reviewMutation.isPending ? 'Saving…' : 'Save Triage'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
