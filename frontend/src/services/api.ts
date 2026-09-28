import axios from 'axios';

const api = axios.create({
  baseURL: import.meta.env.VITE_API_URL || ((window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1') ? `http://${window.location.hostname}:8000/api/v1` : '/api/v1'),
  headers: {
    'Content-Type': 'application/json',
  },
});

export default api;
