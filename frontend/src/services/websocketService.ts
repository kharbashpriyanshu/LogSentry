type EventCallback = (event: any) => void;

class WebSocketService {
  private ws: WebSocket | null = null;
  private reconnectAttempts = 0;
  private maxReconnectAttempts = 5;
  private baseDelay = 1000; // 1s
  private listeners: Set<EventCallback> = new Set();
  
  public connect() {
    if (this.ws?.readyState === WebSocket.OPEN) return;
    
    // Determine WS URL based on API URL (assuming it's relative or we can build it)
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    // Use localhost:8000 for local dev if not specified
    const host = window.location.hostname === 'localhost' ? 'localhost:8000' : window.location.host;
    const wsUrl = `${protocol}//${host}/api/v1/dashboard/ws/events`;
    
    this.ws = new WebSocket(wsUrl);
    
    this.ws.onopen = () => {
      console.log('WebSocket connected');
      this.reconnectAttempts = 0;
    };
    
    this.ws.onmessage = (message) => {
      try {
        const data = JSON.parse(message.data);
        this.listeners.forEach(cb => cb(data));
      } catch (e) {
        console.error('Failed to parse WS message', e);
      }
    };
    
    this.ws.onclose = () => {
      console.log('WebSocket disconnected');
      this.attemptReconnect();
    };
    
    this.ws.onerror = (err) => {
      console.error('WebSocket error', err);
      this.ws?.close();
    };
  }
  
  private attemptReconnect() {
    if (this.reconnectAttempts >= this.maxReconnectAttempts) {
      console.error('Max WebSocket reconnect attempts reached.');
      return;
    }
    
    const delay = this.baseDelay * Math.pow(2, this.reconnectAttempts);
    this.reconnectAttempts++;
    console.log(`Reconnecting to WebSocket in ${delay}ms...`);
    setTimeout(() => this.connect(), delay);
  }
  
  public addListener(cb: EventCallback) {
    this.listeners.add(cb);
  }
  
  public removeListener(cb: EventCallback) {
    this.listeners.delete(cb);
  }
  
  public disconnect() {
    this.listeners.clear();
    if (this.ws) {
      this.ws.close();
      this.ws = null;
    }
  }
}

export const wsService = new WebSocketService();
