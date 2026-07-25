import api from './api';

export const dashboardService = {
  getSummary: async () => {
    const response = await api.get('/dashboard/summary');
    return response.data;
  },
  getAlertTrend: async () => {
    const response = await api.get('/dashboard/alert-trend');
    return response.data;
  },
  getSeverityDistribution: async () => {
    const response = await api.get('/dashboard/severity-distribution');
    return response.data;
  },
  getTopSources: async () => {
    const response = await api.get('/dashboard/top-sources');
    return response.data;
  }
};
