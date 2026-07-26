import api from './api';

export const healthService = {
  getBackendHealth: async () => {
    const res = await api.get('/health');
    return res.data;
  },
  getMetrics: async () => {
    const res = await api.get('/metrics');
    return res.data;
  },
  getIntegrations: async () => {
    const res = await api.get('/health/integrations');
    return res.data;
  },
};
