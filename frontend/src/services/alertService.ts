import api from './api';
import type { DetectionAlert, AlertUpdate, TimelineEvent } from '../types';

export const alertService = {
  getAlerts: async (): Promise<DetectionAlert[]> => {
    const response = await api.get('/alerts');
    return response.data;
  },
  updateAlert: async (id: string, payload: AlertUpdate): Promise<DetectionAlert> => {
    const response = await api.patch(`/alerts/${id}`, payload);
    return response.data;
  },
  getAlertTimeline: async (id: string): Promise<TimelineEvent[]> => {
    const response = await api.get(`/alerts/${id}/timeline`);
    return response.data;
  }
};
