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
  },
  falsePositive: async (id: string, payload: { reason: string, notes: string, marked_by: string }): Promise<DetectionAlert> => {
    const response = await api.post(`/alerts/${id}/false-positive`, payload);
    return response.data;
  },
  resolve: async (id: string, payload: { resolution_type: string, notes: string, resolved_by: string }): Promise<DetectionAlert> => {
    const response = await api.post(`/alerts/${id}/resolve`, payload);
    return response.data;
  },
  assign: async (id: string, payload: { assignee: string, priority?: string, notes?: string, assigned_by: string }): Promise<DetectionAlert> => {
    const response = await api.post(`/alerts/${id}/assign`, payload);
    return response.data;
  },
  addComment: async (id: string, payload: { content: string, author: string }): Promise<void> => {
    await api.post(`/alerts/${id}/comments`, payload);
  },
  investigate: async (id: string, payload: { title: string, description: string, priority: string, category: string, tags?: string, investigator: string }): Promise<any> => {
    const response = await api.post(`/alerts/${id}/investigate`, payload);
    return response.data;
  }
};
