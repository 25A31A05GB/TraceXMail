import React from 'react';
import { ShieldAlert, AlertTriangle, Info, X, ExternalLink } from 'lucide-react';
import { WebSocketAlert } from '../hooks/useWebSocketAlerts';

interface AlertToastProps {
  alert: WebSocketAlert | null;
  onDismiss: () => void;
  onInspect: (alert: WebSocketAlert) => void;
}

export function AlertToast({ alert, onDismiss, onInspect }: AlertToastProps) {
  if (!alert) return null;

  const isCritical = alert.severity === 'CRITICAL';
  const isHigh = alert.severity === 'HIGH';

  return (
    <div className="fixed bottom-6 right-6 z-50 max-w-md w-full animate-in fade-in slide-in-from-bottom-5 duration-200">
      <div className={`p-4 rounded-xl border shadow-2xl backdrop-blur-md ${
        isCritical
          ? 'bg-red-950/90 border-red-700/80 text-red-100 shadow-red-950/40'
          : isHigh
          ? 'bg-amber-950/90 border-amber-700/80 text-amber-100 shadow-amber-950/40'
          : 'bg-slate-900/90 border-slate-700 text-slate-100'
      }`}>
        <div className="flex items-start justify-between gap-3">
          <div className="flex items-center gap-2">
            {isCritical ? (
              <ShieldAlert className="w-5 h-5 text-red-400 shrink-0" />
            ) : isHigh ? (
              <AlertTriangle className="w-5 h-5 text-amber-400 shrink-0" />
            ) : (
              <Info className="w-5 h-5 text-cyan-400 shrink-0" />
            )}
            <div>
              <div className="flex items-center gap-2">
                <span className={`text-[10px] font-bold uppercase tracking-wider px-1.5 py-0.5 rounded ${
                  isCritical ? 'bg-red-800 text-red-200' : isHigh ? 'bg-amber-800 text-amber-200' : 'bg-slate-800 text-slate-300'
                }`}>
                  {alert.severity}
                </span>
                <span className="text-xs font-semibold">{alert.title}</span>
              </div>
            </div>
          </div>
          <button
            onClick={onDismiss}
            className="text-slate-400 hover:text-slate-200 p-1 rounded transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        <p className="mt-2 text-xs text-slate-300 line-clamp-2 leading-relaxed">
          {alert.description}
        </p>

        {alert.sender && (
          <div className="mt-2 text-[11px] text-slate-400 font-mono truncate">
            Sender: {alert.sender}
          </div>
        )}

        <div className="mt-3 flex items-center justify-end gap-2">
          <button
            onClick={onDismiss}
            className="px-2.5 py-1 text-xs text-slate-400 hover:text-slate-200 rounded transition-colors"
          >
            Dismiss
          </button>
          <button
            onClick={() => {
              onInspect(alert);
              onDismiss();
            }}
            className="flex items-center gap-1 px-3 py-1 bg-cyan-600 hover:bg-cyan-500 text-white rounded text-xs font-semibold transition-colors"
          >
            <span>Inspect Case</span>
            <ExternalLink className="w-3 h-3" />
          </button>
        </div>
      </div>
    </div>
  );
}
