import axios from 'axios';

const BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:3000';

const client = axios.create({ baseURL: BASE_URL });

export const api = {
  getGraph: () => client.get('/api/graph').then((r) => r.data),
  getChains: () => client.get('/api/analysis/chains').then((r) => r.data),
  getCves: () => client.get('/api/cves').then((r) => r.data),
  getConflicts: () => client.get('/api/intel/conflicts').then((r) => r.data),
};
