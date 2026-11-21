import api from './api';

export interface QuarantineRecord {
  ip: string;
  quarantined_at: string;
  expires_at: string;
  status: 'ACTIVE' | 'RELEASED';
  reason: string;
  trigger_alert: string;
  provider: string;
}

export const soarService = {
  quarantineIp: async (ip: string, durationMinutes = 60, reason = 'Analyst manual 1-click containment', trigger = 'Manual SOAR Action'): Promise<any> => {
    const res = await api.post('/soar/quarantine', {
      ip,
      duration_minutes: durationMinutes,
      reason,
      trigger,
    });
    return res.data;
  },

  getQuarantinedIps: async (): Promise<QuarantineRecord[]> => {
    const res = await api.get('/soar/quarantines');
    return res.data;
  },

  releaseIp: async (ip: string, reason = 'Containment expired'): Promise<any> => {
    const res = await api.post(`/soar/release/${ip}`, { reason });
    return res.data;
  },

  getIptablesDropScript: async (ip: string): Promise<string> => {
    return `sudo iptables -A INPUT -s ${ip} -j DROP\nsudo iptables -A FORWARD -s ${ip} -j DROP\necho "[LogSentry SOAR] Blocked ${ip} on host firewall"`;
  },
};
