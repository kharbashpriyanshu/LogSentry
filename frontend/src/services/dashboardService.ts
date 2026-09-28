import api from './api';

export const dashboardService = {
  getSummary: async (time_range_hours?: number) => {
    const response = await api.get('/dashboard/summary', { params: time_range_hours ? { time_range_hours } : {} });
    return response.data;
  },
  getAlertTrend: async (days?: number) => {
    const response = await api.get('/dashboard/alert-trend', { params: days ? { days } : {} });
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
  getActivity: async (limit?: number) => {
    const response = await api.get('/dashboard/activity', { params: limit ? { limit } : {} });
    return response.data;
  },
  getRecentActivity: async (limit?: number) => {
    const response = await api.get('/dashboard/activity', { params: limit ? { limit } : {} });
    return response.data;
  },
  getTopAttackTypes: async (limit?: number) => {
    const response = await api.get('/dashboard/top-attack-types', { params: limit ? { limit } : {} });
    return response.data;
  },
  getTopMitre: async (limit?: number) => {
    const response = await api.get('/dashboard/top-mitre', { params: limit ? { limit } : {} });
    return response.data;
  },
  getRecentIncidents: async (limit?: number) => {
    const response = await api.get('/dashboard/recent-incidents', { params: limit ? { limit } : {} });
    return response.data;
  },
};
