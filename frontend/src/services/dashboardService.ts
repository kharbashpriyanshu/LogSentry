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
  },
  getActivity: async () => {
    const response = await api.get('/dashboard/activity');
    return response.data;
  },
  getTopAttackTypes: async () => {
    const response = await api.get('/dashboard/top-attack-types');
    return response.data;
  },
  getTopMitre: async () => {
    const response = await api.get('/dashboard/top-mitre');
    return response.data;
  },
  getRecentIncidents: async () => {
    const response = await api.get('/dashboard/recent-incidents');
    return response.data;
  },
};
