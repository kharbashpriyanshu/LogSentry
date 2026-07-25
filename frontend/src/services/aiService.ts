import api from './api';

export const aiService = {
  getProviders: async () => {
    const response = await api.get('/ai/providers');
    return response.data;
  },
  
  checkHealth: async () => {
    const response = await api.get('/ai/health');
    return response.data;
  },

  analyzeAlert: async (alertId: string) => {
    const response = await api.post('/ai/analyze', { alert_id: alertId });
    return response.data;
  },
  
  getAnalysesForAlert: async (alertId: string) => {
    const response = await api.get(`/ai/alerts/${alertId}/ai-analyses`);
    return response.data;
  }
};
