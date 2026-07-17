import api from './api';
import type { DetectionAlert } from '../types';

export const alertService = {
  getAlerts: async (): Promise<DetectionAlert[]> => {
    // In a real scenario, this would be a GET request.
    // For now, since we only have a POST in the backend to create, 
    // we'll simulate fetching alerts or just return an empty array if backend doesn't support GET /alerts
    try {
      const response = await api.get('/alerts');
      return response.data;
    } catch {
      // Mock data for display if backend GET /alerts doesn't exist
      return [
        {
          alert_id: "alert-1",
          timestamp: new Date().toISOString(),
          rule_name: "sqli_detect",
          rule_version: "1.0",
          severity: "HIGH",
          confidence: 0.9,
          risk_score: 80,
          title: "SQL Injection Attempt",
          description: "Detected SQL injection in URL parameters",
          source_ip: "192.168.1.5",
          attack_type: "SQL Injection",
          mitre_technique: "T1190",
          evidence: {},
          raw_log_reference: "raw-1"
        }
      ];
    }
  },
};
