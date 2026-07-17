import api from './api';

export const healthService = {
  getBackendHealth: async () => {
    const res = await api.get('/health');
    return res.data;
  },
};
