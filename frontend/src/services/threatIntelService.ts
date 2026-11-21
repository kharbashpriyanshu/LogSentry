import api from './api';
import type { ThreatEnrichment, DetectionAlert } from '../types';

export const threatIntelService = {
  // Legacy enrichment endpoints for backwards compatibility
  getHealth: async () => {
    const res = await api.get('/enrichment/health');
    return res.data;
  },
  getProviders: async () => {
    const res = await api.get('/threat-intel/sources');
    return res.data;
  },
  analyzeAlert: async (alert: DetectionAlert): Promise<ThreatEnrichment[]> => {
    const res = await api.post('/enrichment/analyze', alert);
    return res.data;
  },
  lookupIoc: async (observable: string, forceRefresh = false) => {
    const res = await api.post('/threat-intel/lookup', {
      indicator: observable,
      force_external: forceRefresh,
    });
    return res.data;
  },
  getHistory: async () => {
    const res = await api.get('/threat-intel/audit');
    return res.data;
  },

  // TIORE Enterprise Endpoints
  lookupIndicator: async (indicator: string, forceExternal = false) => {
    const res = await api.post('/threat-intel/lookup', {
      indicator,
      force_external: forceExternal,
    });
    return res.data;
  },
  getMatches: async (classification?: string) => {
    const res = await api.get('/threat-intel/matches', {
      params: classification ? { classification } : undefined,
    });
    return res.data;
  },
  reviewMatch: async (matchId: string, reviewStatus: string, notes?: string) => {
    const res = await api.patch(`/threat-intel/matches/${matchId}/review`, {
      review_status: reviewStatus,
      notes,
    });
    return res.data;
  },
  getObservables: async (page = 1, obsType?: string) => {
    const res = await api.get('/threat-intel/observables', {
      params: { page, obs_type: obsType || undefined },
    });
    return res.data;
  },
  getSources: async () => {
    const res = await api.get('/threat-intel/sources');
    return res.data;
  },
  getAudit: async (limit = 50) => {
    const res = await api.get('/threat-intel/audit', { params: { limit } });
    return res.data;
  },
  getStats: async () => {
    const res = await api.get('/threat-intel/stats');
    return res.data;
  },
  unmaskObservable: async (observableId: string) => {
    const res = await api.post(`/threat-intel/observables/${observableId}/unmask`);
    return res.data;
  },
};
