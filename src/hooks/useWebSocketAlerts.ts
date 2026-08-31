import { useState, useEffect, useCallback, useRef } from 'react';

export type ConnectionStatus = 'connected' | 'connecting' | 'disconnected' | 'error';

export interface WebSocketAlert {
  id: string;
  case_id?: string;
  timestamp: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  title: string;
  description: string;
  source?: string;
  read?: boolean;
  threat_score?: number;
  category?: string;
  sender?: string;
  subject?: string;
}

const INITIAL_ALERTS: WebSocketAlert[] = [
  {
    id: 'alt_001',
    case_id: 'sample-1',
    timestamp: new Date(Date.now() - 1000 * 60 * 12).toISOString(),
    severity: 'CRITICAL',
    title: 'BEC Payroll Spoofing Attack Detected',
    description: 'CEO impersonation attempting wire redirection. SPF neutral, display name mismatch, urgence trigger.',
    source: 'mail-gateway-01',
    read: false,
    threat_score: 92,
    category: 'BEC_IMPERSONATION',
    sender: 'ceo-office@company-exec.net',
    subject: 'URGENT: Updated Direct Deposit Routing'
  },
  {
    id: 'alt_002',
    case_id: 'sample-2',
    timestamp: new Date(Date.now() - 1000 * 60 * 45).toISOString(),
    severity: 'HIGH',
    title: 'Credential Harvester Landing Page Identified',
    description: 'Obfuscated JavaScript redirecting to cloned Microsoft 365 sign-in page on Russian bulletproof ASN.',
    source: 'pipeline-heuristics',
    read: false,
    threat_score: 84,
    category: 'CREDENTIAL_HARVESTING',
    sender: 'security@microsoft-auth-verify.com',
    subject: 'Action Required: Verify Office 365 Password Expiry'
  },
  {
    id: 'alt_003',
    case_id: 'sample-3',
    timestamp: new Date(Date.now() - 1000 * 60 * 120).toISOString(),
    severity: 'MEDIUM',
    title: 'Anomalous Email Hop Timing (14s latency in AS4837)',
    description: 'Unusual delay detected between internal gateway and external relay node.',
    source: 'traceroute-engine',
    read: true,
    threat_score: 55,
    category: 'HOP_ANOMALY',
    sender: 'billing@vendor-supplies.co.uk',
    subject: 'Invoice #884920 Overdue Notification'
  }
];

export function useWebSocketAlerts() {
  const [alerts, setAlerts] = useState<WebSocketAlert[]>(INITIAL_ALERTS);
  const [activeToast, setActiveToast] = useState<WebSocketAlert | null>(null);
  const [status, setStatus] = useState<ConnectionStatus>('disconnected');
  const [soundEnabled, setSoundEnabled] = useState<boolean>(true);
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimeoutRef = useRef<any>(null);

  const unreadCount = alerts.filter(a => !a.read).length;

  const playNotificationSound = useCallback(() => {
    if (!soundEnabled) return;
    try {
      if (typeof window !== 'undefined' && window.AudioContext) {
        const ctx = new (window.AudioContext || (window as any).webkitAudioContext)();
        const osc = ctx.createOscillator();
        const gain = ctx.createGain();
        osc.type = 'sine';
        osc.frequency.setValueAtTime(880, ctx.currentTime);
        osc.frequency.exponentialRampToValueAtTime(440, ctx.currentTime + 0.15);
        gain.gain.setValueAtTime(0.1, ctx.currentTime);
        gain.gain.exponentialRampToValueAtTime(0.01, ctx.currentTime + 0.15);
        osc.connect(gain);
        gain.connect(ctx.destination);
        osc.start();
        osc.stop(ctx.currentTime + 0.15);
      }
    } catch {
      // Audio context might be restricted before user gesture
    }
  }, [soundEnabled]);

  const addAlert = useCallback((newAlert: WebSocketAlert) => {
    setAlerts(prev => [newAlert, ...prev.slice(0, 49)]);
    setActiveToast(newAlert);
    playNotificationSound();
  }, [playNotificationSound]);

  const connect = useCallback(() => {
    if (typeof window === 'undefined') return;
    setStatus('connecting');

    try {
      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      const wsUrl = `${protocol}//${window.location.host}/ws/alerts`;
      const ws = new WebSocket(wsUrl);
      wsRef.current = ws;

      ws.onopen = () => {
        setStatus('connected');
      };

      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          if (data && (data.title || data.type === 'ALERT')) {
            const incoming: WebSocketAlert = {
              id: data.id || `alt_${Date.now()}`,
              case_id: data.case_id || data.caseId,
              timestamp: data.timestamp || new Date().toISOString(),
              severity: data.severity || 'HIGH',
              title: data.title || 'Threat Detected',
              description: data.description || data.message || 'Suspicious forensic pattern observed',
              source: data.source || 'live-stream',
              read: false,
              threat_score: data.threat_score || 75,
              category: data.category || 'THREAT_ALERT',
              sender: data.sender,
              subject: data.subject
            };
            addAlert(incoming);
          }
        } catch (e) {
          console.warn('[WebSocket] Error parsing incoming alert:', e);
        }
      };

      ws.onerror = () => {
        setStatus('error');
      };

      ws.onclose = () => {
        setStatus('disconnected');
        // Retry connection after 5 seconds
        reconnectTimeoutRef.current = setTimeout(() => {
          connect();
        }, 5000);
      };
    } catch {
      setStatus('disconnected');
    }
  }, [addAlert]);

  useEffect(() => {
    connect();
    return () => {
      if (reconnectTimeoutRef.current) clearTimeout(reconnectTimeoutRef.current);
      if (wsRef.current) {
        wsRef.current.close();
      }
    };
  }, [connect]);

  const dismissToast = useCallback(() => {
    setActiveToast(null);
  }, []);

  const broadcastTestAlert = useCallback((custom?: Partial<WebSocketAlert>) => {
    const mockAlert: WebSocketAlert = {
      id: `alt_${Date.now()}`,
      case_id: 'sample-1',
      timestamp: new Date().toISOString(),
      severity: custom?.severity || 'CRITICAL',
      title: custom?.title || 'Simulated Phishing IOC Broadcast',
      description: custom?.description || 'Manual test alert generated by SOC analyst from forensic pipeline console.',
      source: 'soc-manual-test',
      read: false,
      threat_score: 95,
      category: 'TEST_ALERT',
      ...custom
    };
    addAlert(mockAlert);
  }, [addAlert]);

  const reconnect = useCallback(() => {
    if (wsRef.current) {
      wsRef.current.close();
    }
    connect();
  }, [connect]);

  return {
    alerts,
    activeToast,
    status,
    unreadCount,
    soundEnabled,
    setSoundEnabled,
    dismissToast,
    broadcastTestAlert,
    reconnect
  };
}
