import React, { useState } from 'react';
import { 
  Bell, 
  ShieldAlert, 
  AlertTriangle, 
  Info, 
  Volume2, 
  VolumeX, 
  Radio, 
  RefreshCw, 
  ExternalLink,
  CheckCircle2,
  Clock,
  Send,
  Sparkles
} from 'lucide-react';
import { WebSocketAlert, ConnectionStatus } from '../hooks/useWebSocketAlerts';
import { EmailAnalysis } from '../types';

interface AlertsViewProps {
  currentAnalysis: EmailAnalysis;
  onSelectAnalysis: (analysis: EmailAnalysis) => void;
  onNavigateToOverview: () => void;
  liveAlerts: WebSocketAlert[];
  wsStatus: ConnectionStatus;
  soundEnabled: boolean;
  onToggleSound: () => void;
  onBroadcastTestAlert: (custom?: Partial<WebSocketAlert>) => void;
  onReconnectWs: () => void;
}

export function AlertsView({
  currentAnalysis,
  onSelectAnalysis,
  onNavigateToOverview,
  liveAlerts,
  wsStatus,
  soundEnabled,
  onToggleSound,
  onBroadcastTestAlert,
  onReconnectWs
}: AlertsViewProps) {
  const [filterSeverity, setFilterSeverity] = useState<string>('ALL');

  const filteredAlerts = liveAlerts.filter(alert => {
    if (filterSeverity === 'ALL') return true;
    return alert.severity === filterSeverity;
  });

  return (
    <div className="flex-1 flex flex-col h-full bg-[#0F172A] overflow-y-auto p-6 space-y-6">
      {/* Top Banner */}
      <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 shadow-xl flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div className="flex items-center gap-4">
          <div className="w-12 h-12 rounded-2xl bg-cyan-950/80 border border-cyan-800/80 flex items-center justify-center">
            <Bell className="w-6 h-6 text-cyan-400" />
          </div>
          <div>
            <h2 className="text-lg font-bold text-slate-100 flex items-center gap-2">
              <span>Real-Time Threat Alerts &amp; SIEM Feed</span>
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Live WebSocket stream for critical IOC matches, high-risk BEC triggers, and header anomalies.
            </p>
          </div>
        </div>

        {/* Controls */}
        <div className="flex flex-wrap items-center gap-3">
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-xs">
            <span className={`w-2 h-2 rounded-full ${
              wsStatus === 'connected' ? 'bg-emerald-500 animate-pulse' :
              wsStatus === 'connecting' ? 'bg-amber-500 animate-ping' :
              'bg-red-500'
            }`} />
            <span className="font-mono capitalize text-slate-300">WS: {wsStatus}</span>
            {wsStatus !== 'connected' && (
              <button
                onClick={onReconnectWs}
                className="text-cyan-400 hover:text-cyan-300 ml-1 p-0.5"
                title="Reconnect WebSocket"
              >
                <RefreshCw className="w-3 h-3" />
              </button>
            )}
          </div>

          <button
            onClick={onToggleSound}
            className={`p-2 rounded-lg border transition-colors ${
              soundEnabled
                ? 'bg-cyan-950/60 border-cyan-800 text-cyan-400'
                : 'bg-slate-800 border-slate-700 text-slate-500 hover:text-slate-300'
            }`}
            title={soundEnabled ? 'Mute Alert Chimes' : 'Enable Alert Chimes'}
          >
            {soundEnabled ? <Volume2 className="w-4 h-4" /> : <VolumeX className="w-4 h-4" />}
          </button>

          <button
            onClick={() => onBroadcastTestAlert()}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700 text-xs font-semibold text-slate-200 transition-colors"
          >
            <Send className="w-3.5 h-3.5 text-cyan-400" />
            <span>Emit Test Alert</span>
          </button>
        </div>
      </div>

      {/* Severity Filter Tabs */}
      <div className="flex items-center gap-2">
        {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(s => (
          <button
            key={s}
            onClick={() => setFilterSeverity(s)}
            className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-colors ${
              filterSeverity === s
                ? 'bg-cyan-600 text-white shadow-sm'
                : 'bg-slate-900 border border-slate-800 text-slate-400 hover:text-slate-200'
            }`}
          >
            {s === 'ALL' ? `All Alerts (${liveAlerts.length})` : s}
          </button>
        ))}
      </div>

      {/* Alerts Feed */}
      <div className="space-y-3">
        {filteredAlerts.length === 0 ? (
          <div className="p-12 text-center rounded-2xl bg-slate-900/40 border border-slate-800 text-slate-500">
            <Bell className="w-8 h-8 mx-auto mb-2 opacity-40" />
            <p className="text-sm font-medium">No live alerts in this category</p>
          </div>
        ) : (
          filteredAlerts.map(alert => {
            const isCritical = alert.severity === 'CRITICAL';
            const isHigh = alert.severity === 'HIGH';

            return (
              <div
                key={alert.id}
                className={`p-5 rounded-2xl border transition-all ${
                  isCritical
                    ? 'bg-red-950/20 border-red-900/60 hover:border-red-700'
                    : isHigh
                    ? 'bg-amber-950/20 border-amber-900/60 hover:border-amber-700'
                    : 'bg-slate-900 border-slate-800 hover:border-slate-700'
                }`}
              >
                <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-4">
                  <div className="space-y-1.5 flex-1">
                    <div className="flex items-center gap-2.5">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider ${
                        isCritical
                          ? 'bg-red-900/80 text-red-200'
                          : isHigh
                          ? 'bg-amber-900/80 text-amber-200'
                          : 'bg-slate-800 text-slate-300'
                      }`}>
                        {alert.severity}
                      </span>
                      <span className="text-xs font-mono text-slate-500">{alert.id}</span>
                      <span className="text-xs text-slate-500 flex items-center gap-1">
                        <Clock className="w-3 h-3" />
                        {new Date(alert.timestamp).toLocaleTimeString()}
                      </span>
                    </div>

                    <h3 className="text-sm font-bold text-slate-100">{alert.title}</h3>
                    <p className="text-xs text-slate-300 leading-relaxed">{alert.description}</p>

                    {alert.sender && (
                      <div className="text-xs font-mono text-slate-400 pt-1">
                        From: <span className="text-cyan-300">{alert.sender}</span>
                      </div>
                    )}
                  </div>

                  <div className="flex sm:flex-col items-end justify-between gap-2 shrink-0">
                    <span className="text-xs font-bold text-slate-400 bg-slate-950 px-2.5 py-1 rounded border border-slate-800">
                      Score: {alert.threat_score || 80}/100
                    </span>
                    <button
                      onClick={() => onNavigateToOverview()}
                      className="flex items-center gap-1 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-cyan-600 text-xs font-semibold text-slate-200 hover:text-white transition-colors"
                    >
                      <span>Investigate</span>
                      <ExternalLink className="w-3.5 h-3.5" />
                    </button>
                  </div>
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}
