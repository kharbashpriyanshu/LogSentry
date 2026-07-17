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

export interface AIAnalysisResponse {
  executive_summary: string;
  technical_explanation: string;
  severity_justification: string;
  likely_attack_goal: string;
  potential_impact: string;
  recommended_actions: string;
  mitre_technique?: string;
  confidence_score: number;
  false_positive_likelihood: string;
  analyst_notes: string;
}
