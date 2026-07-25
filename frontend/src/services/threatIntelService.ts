import api from './api';
import type { ThreatEnrichment, DetectionAlert } from '../types';

export const threatIntelService = {
  getHealth: async () => {
    const res = await api.get('/enrichment/health');
    return res.data;
  },
  getProviders: async () => {
    const res = await api.get('/enrichment/providers');
    return res.data;
  },
  analyzeAlert: async (alert: DetectionAlert): Promise<ThreatEnrichment[]> => {
    const res = await api.post('/enrichment/analyze', alert);
    return res.data;
  },
  lookupIoc: async (observable: string, forceRefresh = false) => {
    const res = await api.get(`/enrichment/ioc/${encodeURIComponent(observable)}`, {
      params: { force_refresh: forceRefresh }
    });
    return res.data;
  },
  getHistory: async () => {
    const res = await api.get('/enrichment/history');
    return res.data;
  }
};
