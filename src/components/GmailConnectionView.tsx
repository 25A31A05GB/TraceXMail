import { useState, useEffect } from 'react';

import {
  Mail,
  CheckCircle2,
  RefreshCw,
  LogOut,
  ShieldCheck,
  Zap,
  AlertCircle,
} from 'lucide-react';

const API_URL = (
  (import.meta as any).env?.VITE_API_URL ||
  ''
).replace(/\/$/, '');
interface GmailStatusResponse {
  is_connected: boolean;
  oauth_configured: boolean;
  email_address: string | null;
  last_polled_at: string | null;
  polling_interval_seconds: number;
  history_id: string | null;
  created_at?: string;
}

interface GmailConnectionViewProps {
  onNewCasesProcessed?: () => void;
}

export function GmailConnectionView({ onNewCasesProcessed }: GmailConnectionViewProps) {
  const [status, setStatus] = useState<GmailStatusResponse | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [refreshing, setRefreshing] = useState<boolean>(false);
  const [syncing, setSyncing] = useState<boolean>(false);
  const [syncResult, setSyncResult] = useState<string | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const fetchStatus = async () => {
    setLoading(true);

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 10000);

    try {
      const res = await fetch(`${API_URL}/api/gmail/status`, {
        signal: controller.signal,
      });

      if (!res.ok) {
        throw new Error(`HTTP ${res.status}`);
      }

      const data = await res.json();
      setStatus(data);
      setErrorMsg(null);
    } catch (e: any) {
      if (e?.name === 'AbortError') {
        setErrorMsg('Gmail service is taking too long to respond. Please try again.');
      } else {
        setErrorMsg('Failed to fetch Gmail status. Please try again.');
      }
    } finally {
      clearTimeout(timeout);
      setLoading(false);
      setRefreshing(false);
    }
  };

  const handleConnectGmail = async () => {
    try {
      setErrorMsg('');
      setSyncResult('');

      const res = await fetch(`${API_URL}/api/gmail/oauth/start`, {
        headers: {
          'x-organization-id': 'org_acme_soc_01',
        },
      });

      const contentType = res.headers.get('content-type') || '';
      const raw = await res.text();

      let data: any = null;

      if (contentType.includes('application/json')) {
        try {
          data = JSON.parse(raw);
        } catch {
          throw new Error(`Invalid JSON response from Gmail OAuth endpoint: ${raw.slice(0, 200)}`);
        }
      } else {
        throw new Error(
          `Gmail OAuth endpoint returned ${res.status} ${res.statusText}: ${raw.slice(0, 200)}`
        );
      }

      if (!res.ok || !data?.url) {
        throw new Error(
          data?.detail ||
          data?.message ||
          `Failed to start Gmail OAuth (${res.status})`
        );
      }

      const popup = window.open(
        data.url,
        'TraceXMailGmailOAuth',
        'width=600,height=700,resizable=yes,scrollbars=yes'
      );

      if (!popup) {
        throw new Error('OAuth popup was blocked. Please allow popups for TraceXMail.');
      }
    } catch (err: any) {
      console.error('[GmailOAuth] Failed to start OAuth flow:', err);
      setErrorMsg('Error starting Gmail OAuth flow: ' + (err?.message || String(err)));
    }
  };

  const handleSyncNow = async () => {
    setSyncing(true);
    setSyncResult(null);
    setErrorMsg(null);
    try {
      const res = await fetch(`${API_URL}/api/gmail/poll-now`, { method: 'POST' });
      if (res.ok) {
        const data = await res.json();
        if (data.status === 'needs_reauthorization') {
          setErrorMsg('Gmail connection expired or revoked. Please disconnect and reconnect.');
          setSyncResult(null);
        } else if (data.status === 'error') {
          setErrorMsg('Error syncing Gmail: ' + data.error);
          setSyncResult(null);
        } else {
          const count = data.processed_cases_count || 0;
          setSyncResult(`Sync complete: ${count} new email(s) ingested & analyzed through the pipeline.`);
          if (count > 0 && onNewCasesProcessed) {
            onNewCasesProcessed();
          }
        }
        fetchStatus();
      } else {
        setErrorMsg('Failed to sync Gmail mailbox.');
      }
    } catch (e: any) {
      setErrorMsg('Error during sync: ' + e.message);
    } finally {
      setSyncing(false);
    }
  };

  // Listen for OAuth success only after handleSyncNow is initialized.
  useEffect(() => {
    fetchStatus();

    const handleMessage = (event: MessageEvent) => {
      if (event.data && event.data.type === 'GMAIL_OAUTH_SUCCESS') {
        console.log('[GmailOAuth] OAuth completed successfully');
        setErrorMsg(null);
        setSyncResult('Gmail account connected successfully.');
        fetchStatus();
        handleSyncNow();
      }
    };

    window.addEventListener('message', handleMessage);
    return () => window.removeEventListener('message', handleMessage);
  }, []);

  const handleDisconnect = async () => {
    if (!confirm('Are you sure you want to disconnect this Gmail account?')) return;
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 8000);
    try {
      const res = await fetch(`${API_URL}/api/gmail/disconnect`, { method: 'POST', signal: controller.signal });
      clearTimeout(timeout);
      if (res.ok) {
        fetchStatus();
        setSyncResult('Gmail account disconnected.');
      }
    } catch (e: any) {
      clearTimeout(timeout);
      if (e?.name === 'AbortError') setErrorMsg('Request timed out — retry');
      else setErrorMsg('Error disconnecting Gmail account.');
    }
  };

  if (loading) {
    return (
      <div className="bg-[#1E293B] border border-slate-700 rounded-xl p-6 flex items-center justify-center gap-3 text-slate-400 text-xs">
        <RefreshCw className="w-4 h-4 animate-spin text-blue-400" />
        <span>Loading Gmail Connection Status...</span>
      </div>
    );
  }

  return (
    <div className="bg-[#1E293B] border border-slate-700 rounded-xl p-6 space-y-5 shadow-md">
      {/* Top Banner */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-700 pb-4">
        <div className="flex items-center gap-3.5">
          <div className="w-10 h-10 rounded-lg bg-rose-500/15 border border-rose-500/30 flex items-center justify-center text-rose-400">
            <Mail className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-base font-semibold text-white">Gmail Real-Time Ingestion Engine</h3>
              <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-purple-500/20 text-purple-300 border border-purple-500/30">
                OAuth 2.0 & Fernet Encrypted
              </span>
              {refreshing && (
                <span className="ml-2 flex items-center gap-1.5 text-xs text-slate-400">
                  <RefreshCw className="w-3 h-3 animate-spin text-blue-400" />
                  refreshing...
                </span>
              )}
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              Connect a real Gmail account via OAuth 2.0 to automatically detect and ingest incoming emails into the TraceXMail forensic pipeline in real-time.
            </p>
          </div>
        </div>

        {status?.is_connected ? (
          <div className="flex items-center gap-2">
            <button
              onClick={handleSyncNow}
              disabled={syncing}
              className="bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white px-3.5 py-1.5 rounded-lg text-xs font-semibold flex items-center gap-1.5 cursor-pointer shadow-sm transition-colors"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${syncing ? 'animate-spin' : ''}`} />
              <span>{syncing ? 'Syncing Mail...' : 'Sync Now'}</span>
            </button>
            <button
              onClick={handleDisconnect}
              className="bg-slate-800 hover:bg-rose-950 hover:text-rose-300 border border-slate-700 hover:border-rose-700 text-slate-300 px-3 py-1.5 rounded-lg text-xs font-semibold flex items-center gap-1.5 cursor-pointer transition-colors"
            >
              <LogOut className="w-3.5 h-3.5" />
              <span>Disconnect</span>
            </button>
          </div>
        ) : (
          <button
            onClick={handleConnectGmail}
            className="bg-rose-600 hover:bg-rose-500 text-white px-4 py-2 rounded-lg text-xs font-semibold flex items-center gap-2 cursor-pointer shadow-md shadow-rose-600/30 transition-colors shrink-0"
          >
            <Zap className="w-4 h-4 fill-white" />
            <span>Connect Gmail Account</span>
          </button>
        )}
      </div>

      {/* Notifications / Alerts */}
      {errorMsg && (
        <div className="p-3.5 bg-rose-950/60 border border-rose-500/60 rounded-lg text-rose-200 text-xs flex items-center justify-between gap-2.5">
          <div className="flex items-center gap-2.5">
            <AlertCircle className="w-4 h-4 text-rose-400 shrink-0" />
            <span>{errorMsg}</span>
          </div>
          <button
            onClick={() => fetchStatus()}
            className="px-3 py-1 bg-rose-900 hover:bg-rose-800 text-rose-100 rounded text-xs font-semibold transition-colors"
          >
            Retry
          </button>
        </div>
      )}

      {syncResult && (
        <div className="p-3.5 bg-emerald-950/60 border border-emerald-500/60 rounded-lg text-emerald-200 text-xs flex items-center gap-2.5 font-mono">
          <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
          <span>{syncResult}</span>
        </div>
      )}

      {/* Connection Details or Connect Prompt */}
      {status?.is_connected ? (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="bg-[#0F172A] p-3.5 rounded-lg border border-slate-800 space-y-1">
            <span className="text-[10px] uppercase font-mono text-slate-400 block">Connected Mailbox</span>
            <div className="flex items-center gap-2 text-xs font-mono font-bold text-emerald-400 truncate">
              <span className="w-2 h-2 rounded-full bg-emerald-500 animate-ping shrink-0" />
              <span className="truncate">{status.email_address}</span>
            </div>
          </div>

          <div className="bg-[#0F172A] p-3.5 rounded-lg border border-slate-800 space-y-1">
            <span className="text-[10px] uppercase font-mono text-slate-400 block">Last Real-Time Check</span>
            <div className="text-xs font-mono text-slate-200 font-semibold">
              {status.last_polled_at ? new Date(status.last_polled_at).toLocaleTimeString() : 'Just now'}
              <span className="text-[10px] text-slate-400 ml-1.5">(Auto-polling every 20s)</span>
            </div>
          </div>

          <div className="bg-[#0F172A] p-3.5 rounded-lg border border-slate-800 space-y-1">
            <span className="text-[10px] uppercase font-mono text-slate-400 block">Least Privilege Scope</span>
            <div className="flex items-center gap-1.5 text-xs font-mono text-purple-300 font-semibold">
              <ShieldCheck className="w-3.5 h-3.5 text-purple-400" />
              <span>gmail.readonly</span>
            </div>
          </div>
        </div>
      ) : (
        <div className="p-4 bg-[#0F172A] rounded-lg border border-slate-800 space-y-3 text-xs text-slate-300">
          <div className="flex items-start gap-3">
            <ShieldCheck className="w-5 h-5 text-emerald-400 shrink-0 mt-0.5" />
            <div className="space-y-1">
              <p className="font-semibold text-slate-200">Security & Least Privilege Architecture</p>
              <p className="text-slate-400 text-[11px] leading-relaxed">
                TraceXMail requests strictly <strong>gmail.readonly</strong> access. It cannot delete, send, or modify your emails. All OAuth tokens are encrypted using AES-256 Fernet keys in storage.
              </p>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
