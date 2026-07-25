import api from './api';
import type { DetectionAlert, ThreatEnrichment, AIAnalysisResponse } from '../types';

export interface GenerateReportRequest {
  report_type: 'executive' | 'technical' | 'incident';
  alert: DetectionAlert;
  enrichments: ThreatEnrichment[];
  ai_analysis: AIAnalysisResponse;
}

export const reportService = {
  generateReport: async (payload: GenerateReportRequest) => {
    const res = await api.post('/reports/generate', payload);
    return res.data;
  },

  getReportTypes: async () => {
    const res = await api.get('/reports/types');
    return res.data;
  },

  exportPDFUrl: () => {
    return 'http://127.0.0.1:8000/api/v1/reports/export/pdf';
  },

  exportCSVUrl: () => {
    return 'http://127.0.0.1:8000/api/v1/reports/export/csv';
  },

  exportJSONUrl: () => {
    return 'http://127.0.0.1:8000/api/v1/reports/export/json';
  },
};
