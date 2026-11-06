/**
 * K-Valkyrie Telemetry WebSocket Client Service
 * Handles live event streaming, auto-reconnection with backoff, and event dispatch.
 */

export const ConnectionState = {
  CONNECTING: 'CONNECTING',
  OPEN: 'OPEN',
  CLOSED: 'CLOSED',
  RECONNECTING: 'RECONNECTING',
};

class TelemetryWebSocketService {
  constructor() {
    this.ws = null;
    this.subscribers = new Map();
    this.state = ConnectionState.CLOSED;
    this.reconnectAttempts = 0;
    this.maxReconnectAttempts = 10;
    this.baseDelayMs = 1000;
    this.heartbeatInterval = null;
    this.stateListeners = new Set();
  }

  connect(url = 'ws://localhost:8000/ws/telemetry') {
    if (this.ws && (this.ws.readyState === WebSocket.OPEN || this.ws.readyState === WebSocket.CONNECTING)) {
      return;
    }

    this._updateState(this.reconnectAttempts > 0 ? ConnectionState.RECONNECTING : ConnectionState.CONNECTING);

    try {
      this.ws = new WebSocket(url);

      this.ws.onopen = () => {
        this._updateState(ConnectionState.OPEN);
        this.reconnectAttempts = 0;
        this._startHeartbeat();
      };

      this.ws.onmessage = (event) => {
        try {
          const payload = JSON.parse(event.data);
          const eventType = payload.type || 'message';
          const handlers = this.subscribers.get(eventType) || [];
          handlers.forEach((fn) => fn(payload.data || payload));
        } catch (e) {
          console.error('[WebSocket] Parse error:', e);
        }
      };

      this.ws.onclose = () => {
        this._cleanup();
        this._updateState(ConnectionState.CLOSED);
        this._scheduleReconnect(url);
      };

      this.ws.onerror = (err) => {
        console.warn('[WebSocket] Connection error:', err);
        if (this.ws) this.ws.close();
      };
    } catch (e) {
      this._scheduleReconnect(url);
    }
  }

  subscribe(eventType, callback) {
    if (!this.subscribers.has(eventType)) {
      this.subscribers.set(eventType, new Set());
    }
    this.subscribers.get(eventType).add(callback);
    return () => this.unsubscribe(eventType, callback);
  }

  unsubscribe(eventType, callback) {
    if (this.subscribers.has(eventType)) {
      this.subscribers.get(eventType).delete(callback);
    }
  }

  onStateChange(callback) {
    this.stateListeners.add(callback);
    callback(this.state);
    return () => this.stateListeners.delete(callback);
  }

  send(data) {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(typeof data === 'string' ? data : JSON.stringify(data));
      return true;
    }
    return false;
  }

  close() {
    this._cleanup();
    if (this.ws) {
      this.ws.close();
      this.ws = null;
    }
    this._updateState(ConnectionState.CLOSED);
  }

  _startHeartbeat() {
    this._stopHeartbeat();
    this.heartbeatInterval = setInterval(() => {
      if (this.ws && this.ws.readyState === WebSocket.OPEN) {
        this.ws.send(JSON.stringify({ type: 'ping', timestamp: Date.now() }));
      }
    }, 15000);
  }

  _stopHeartbeat() {
    if (this.heartbeatInterval) {
      clearInterval(this.heartbeatInterval);
      this.heartbeatInterval = null;
    }
  }

  _cleanup() {
    this._stopHeartbeat();
  }

  _scheduleReconnect(url) {
    if (this.reconnectAttempts >= this.maxReconnectAttempts) {
      console.error('[WebSocket] Max reconnection attempts reached.');
      return;
    }
    const delay = Math.min(this.baseDelayMs * Math.pow(1.5, this.reconnectAttempts), 30000);
    this.reconnectAttempts++;
    setTimeout(() => this.connect(url), delay);
  }

  _updateState(newState) {
    this.state = newState;
    this.stateListeners.forEach((fn) => fn(newState));
  }
}

export function createWebSocketStream(url = 'ws://localhost:8000/ws/telemetry') {
  const stream = new TelemetryWebSocketService();
  stream.connect(url);
  return stream;
}

export const telemetryStream = new TelemetryWebSocketService();
export default telemetryStream;
