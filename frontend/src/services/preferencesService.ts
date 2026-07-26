export interface AppPreferences {
  autoRefreshInterval: '5s' | '10s' | '30s' | '60s' | 'off';
  tableDensity: 'compact' | 'comfortable';
  timestampFormat: 'iso' | 'relative' | 'standard';
  clockFormat: '12h' | '24h';
  autoRefreshDashboard: boolean;
  notificationPreference: 'all' | 'critical' | 'muted';
}

const STORAGE_KEY = 'logsentry_user_preferences_v1';

const DEFAULT_PREFERENCES: AppPreferences = {
  autoRefreshInterval: '10s',
  tableDensity: 'comfortable',
  timestampFormat: 'iso',
  clockFormat: '24h',
  autoRefreshDashboard: true,
  notificationPreference: 'all',
};

export const preferencesService = {
  getPreferences: (): AppPreferences => {
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      if (!raw) return DEFAULT_PREFERENCES;
      return { ...DEFAULT_PREFERENCES, ...JSON.parse(raw) };
    } catch {
      return DEFAULT_PREFERENCES;
    }
  },
  savePreferences: (prefs: Partial<AppPreferences>): AppPreferences => {
    const current = preferencesService.getPreferences();
    const updated = { ...current, ...prefs };
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(updated));
      window.dispatchEvent(new CustomEvent('logsentry:preferences-updated', { detail: updated }));
    } catch {
      // Ignore storage errors in restricted envs
    }
    return updated;
  },
  resetPreferences: (): AppPreferences => {
    try {
      localStorage.removeItem(STORAGE_KEY);
      window.dispatchEvent(new CustomEvent('logsentry:preferences-updated', { detail: DEFAULT_PREFERENCES }));
    } catch {
      // Ignore
    }
    return DEFAULT_PREFERENCES;
  },
  getDefaults: (): AppPreferences => DEFAULT_PREFERENCES,
};
