import api from './api';
import type { Incident, IncidentCreate, IncidentUpdate, TimelineEvent } from '../types';

export const incidentService = {
  getIncidents: async (): Promise<Incident[]> => {
    const response = await api.get('/incidents');
    return response.data;
  },
  getIncident: async (id: string): Promise<Incident> => {
    const response = await api.get(`/incidents/${id}`);
    return response.data;
  },
  createIncident: async (payload: IncidentCreate): Promise<Incident> => {
    const response = await api.post('/incidents', payload);
    return response.data;
  },
  updateIncident: async (id: string, payload: IncidentUpdate): Promise<Incident> => {
    const response = await api.patch(`/incidents/${id}`, payload);
    return response.data;
  },
  getIncidentTimeline: async (id: string): Promise<TimelineEvent[]> => {
    const response = await api.get(`/incidents/${id}/timeline`);
    return response.data;
  },
  addComment: async (id: string, payload: { content: string, author: string }): Promise<void> => {
    await api.post(`/incidents/${id}/comments`, payload);
  }
};
