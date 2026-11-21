import api from './api';

export interface ConnectedServer {
  id: string;
  hostname: string;
  ip: string;
  parser: string;
  platform: 'linux' | 'windows' | 'web' | 'cloud' | 'network' | 'k8s';
  total_events: number;
  last_seen: string;
  status: 'streaming' | 'idle';
}

export interface ServerPingPayload {
  server_name: string;
  server_ip: string;
  platform: string;
  parser: string;
  sample_log?: string;
  tenant_id?: string;
}

export interface IngestionInfo {
  api_endpoint: string;
  syslog_udp: string;
  syslog_tcp: string;
  supported_platforms: Array<{
    id: string;
    name: string;
    distros: string;
    methods: string[];
  }>;
}

export const integrationService = {
  getServers: async (): Promise<ConnectedServer[]> => {
    const res = await api.get('/integrations/servers');
    return res.data;
  },

  testPing: async (payload: ServerPingPayload): Promise<any> => {
    const res = await api.post('/integrations/test-ping', payload);
    return res.data;
  },

  getIngestionInfo: async (): Promise<IngestionInfo> => {
    const res = await api.get('/integrations/ingestion-info');
    return res.data;
  },
};
