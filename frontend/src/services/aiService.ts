import api from './api';
import type { AIAnalysisResponse, DetectionAlert } from '../types';

export const aiService = {
  getHealth: async () => {
    const res = await api.get('/ai/health');
    return res.data;
  },
  getProviders: async () => {
    const res = await api.get('/ai/providers');
    return res.data;
  },
  analyzeAlert: async (alert: DetectionAlert): Promise<AIAnalysisResponse> => {
    const res = await api.post('/ai/analyze', alert);
    return res.data;
  },
};
