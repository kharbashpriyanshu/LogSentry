import api from './api';

export interface HuntingSearchResult {
  query: string;
  total_hits: number;
  execution_time_ms: number;
  results: Array<Record<string, any>>;
  facets: Record<string, Record<string, number>>;
  time_histogram: Array<Record<string, any>>;
}

export interface CopilotResponse {
  natural_query: string;
  translated_lucene: string;
  reasoning: string;
  target_mitre?: string;
  search_result: HuntingSearchResult;
  ai_tactical_summary: string;
}

export interface ColumnarQueryResult {
  columns: string[];
  rows: any[][];
  total_rows: number;
  execution_time_ms: number;
  summary: string;
}

export const huntingService = {
  search: async (query: string, limit = 50): Promise<HuntingSearchResult> => {
    const res = await api.post('/hunting/search', { query, limit });
    return res.data;
  },

  askCopilot: async (natural_query: string, limit = 50): Promise<CopilotResponse> => {
    const res = await api.post('/hunting/copilot', { natural_query, limit });
    return res.data;
  },

  runColumnarQuery: async (sql_query: string): Promise<ColumnarQueryResult> => {
    const res = await api.post('/hunting/analytics', { sql_query });
    return res.data;
  },
};
