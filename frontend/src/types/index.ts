export interface Severity {
  value: string;
}

export interface DetectionAlert {
  alert_id: string;
  timestamp: string;
  rule_name: string;
  rule_version: string;
  severity: string;
  confidence: number;
  risk_score: number;
  title: string;
  description: string;
  source_ip?: string;
  destination_ip?: string;
  endpoint?: string;
  attack_type: string;
  mitre_technique?: string;
  mitre_tactic?: string;
  recommendation?: string;
  evidence: Record<string, any>;
  raw_log_reference: string;
  hostname?: string;
  status?: string;
  assignee?: string;
  resolved_at?: string;
  resolution_note?: string;
}

export interface ThreatEnrichment {
  provider: string;
  reputation?: string;
  confidence?: number;
  country?: string;
  isp?: string;
  pulse_count?: number;
  mitre_technique?: string;
  mitre_tactic?: string;
  ioc_tags: string[];
  references: string[];
  timestamp: string;
}

export interface ProviderStatus {
  name: string;
  status: string;
  score?: number;
  latency?: number;
}

export interface NormalizedThreatIntel {
  observable: string;
  observable_type: string;
  risk: { score: number; level: string };
  reputation: Record<string, any>;
  geo: { country?: string; countryCode?: string; isp?: string };
  providers: ProviderStatus[];
  mitre: string[];
  ioc_tags: string[];
  cached: boolean;
  enriched_at: string;
}

export interface ContainmentAction {
  priority: string;
  action: string;
  reason: string;
}

export interface AttackStage {
  stage: string;
  evidence: string;
  confidence: number;
}

export interface AIAnalysisResponse {
  executive_summary: string;
  technical_explanation: string;
  severity_justification: string;
  likely_attack_goal: string;
  potential_impact: string;
  recommended_actions: string;
  containment_strategy: ContainmentAction[];
  attack_chain: AttackStage[];
  cve_references: string[];
  mitre_technique?: string;
  confidence_score: number;
  false_positive_likelihood: string;
  analyst_notes: string;
}

export interface AIAnalysisModel {
  id: string;
  provider: string;
  created_at: string;
  summary: string;
  confidence_score: number;
  raw_response: AIAnalysisResponse;
}

export interface Incident {
  id: string;
  title: string;
  description?: string;
  severity: string;
  priority?: string;
  category?: string;
  tags?: string;
  status: string;
  assignee?: string;
  created_at: string;
  updated_at: string;
  resolved_at?: string;
  alert_ids: string[];
}

export interface IncidentCreate {
  title: string;
  description?: string;
  severity: string;
  priority?: string;
  category?: string;
  tags?: string;
  alert_ids?: string[];
}

export interface IncidentUpdate {
  title?: string;
  description?: string;
  severity?: string;
  priority?: string;
  category?: string;
  tags?: string;
  status?: string;
  assignee?: string;
  add_alert_ids?: string[];
}

export interface AlertUpdate {
  status?: string;
  assignee?: string;
  severity?: string;
  resolution_note?: string;
}

export interface TimelineEvent {
  id: string;
  entity_type: string;
  entity_id: string;
  action: string;
  actor?: string;
  old_value?: string;
  new_value?: string;
  metadata_json?: Record<string, any>;
  created_at: string;
}
