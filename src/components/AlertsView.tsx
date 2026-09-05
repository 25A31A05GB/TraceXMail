import React, { useState, useEffect } from 'react';
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
  Sparkles,
  Share2,
  Settings2,
  Check,
  X,
  AlertCircle,
  Code2,
  ChevronDown,
  ChevronUp,
  Sliders,
  Flame,
  Globe
} from 'lucide-react';
import { WebSocketAlert, ConnectionStatus } from '../hooks/useWebSocketAlerts';
import { EmailAnalysis } from '../types';
import { forensicApi } from '../lib/api';

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
  const [activeTab, setActiveTab] = useState<'feed' | 'slack'>('feed');
  const [filterSeverity, setFilterSeverity] = useState<string>('ALL');

  // Slack SOC Integration state
  const [slackStatus, setSlackStatus] = useState<any>(null);
  const [slackLoading, setSlackLoading] = useState<boolean>(false);
  const [webhookInput, setWebhookInput] = useState<string>('');
  const [autoSendSlack, setAutoSendSlack] = useState<boolean>(true);
  const [minSeveritySlack, setMinSeveritySlack] = useState<'ALL' | 'MEDIUM' | 'HIGH' | 'CRITICAL'>('HIGH');
  const [slackChannel, setSlackChannel] = useState<string>('#soc-alerts');
  const [slackUsername, setSlackUsername] = useState<string>('TraceXMail SOC Bot');
  
  const [testingSlack, setTestingSlack] = useState<boolean>(false);
  const [savingConfig, setSavingConfig] = useState<boolean>(false);
  const [slackFeedback, setSlackFeedback] = useState<{ type: 'success' | 'error'; message: string } | null>(null);
  const [sendingAlertId, setSendingAlertId] = useState<string | null>(null);
  const [expandedPayloadId, setExpandedPayloadId] = useState<string | null>(null);
  const [deliveryLogs, setDeliveryLogs] = useState<any[]>([]);

  // Load Slack SOC status
  const loadSlackStatus = async () => {
    try {
      setSlackLoading(true);
      const res = await forensicApi.getSlackStatus();
      setSlackStatus(res);
      setAutoSendSlack(res.auto_send);
      setMinSeveritySlack((res.min_severity as any) || 'HIGH');
      if (res.channel) setSlackChannel(res.channel);
      if (res.username) setSlackUsername(res.username);
      if (res.recent_deliveries) {
        setDeliveryLogs(res.recent_deliveries);
      }
    } catch (err: any) {
      console.warn('Error loading Slack status:', err);
    } finally {
      setSlackLoading(false);
    }
  };

  useEffect(() => {
    loadSlackStatus();
  }, []);

  const handleSaveSlackConfig = async () => {
    try {
      setSavingConfig(true);
      setSlackFeedback(null);
      const res = await forensicApi.updateSlackConfig({
        webhook_url: webhookInput.trim() || undefined,
        auto_send: autoSendSlack,
        min_severity: minSeveritySlack,
        channel: slackChannel.trim() || undefined,
        username: slackUsername.trim() || undefined
      });
      setSlackFeedback({ type: 'success', message: 'Slack SOC Webhook configuration saved successfully.' });
      if (webhookInput) setWebhookInput('');
      await loadSlackStatus();
    } catch (err: any) {
      setSlackFeedback({ type: 'error', message: err?.response?.data?.error || err.message || 'Failed to save Slack configuration' });
    } finally {
      setSavingConfig(false);
    }
  };

  const handleTestSlack = async () => {
    try {
      setTestingSlack(true);
      setSlackFeedback(null);
      const res = await forensicApi.testSlackWebhook(webhookInput.trim() || undefined);
      if (res.success) {
        setSlackFeedback({ type: 'success', message: `Test Block Kit alert sent to Slack! (Status: ${res.statusCode || 200})` });
      } else {
        setSlackFeedback({ type: 'error', message: res.message || 'Slack webhook request returned an error code.' });
      }
      await loadSlackStatus();
    } catch (err: any) {
      setSlackFeedback({ type: 'error', message: err?.response?.data?.message || err.message || 'Failed to send test alert to Slack' });
    } finally {
      setTestingSlack(false);
    }
  };

  const handleSendAlertToSlack = async (alert: WebSocketAlert) => {
    try {
      setSendingAlertId(alert.id);
      const targetCaseId = alert.case_id || 'sample-paypal-phish';
      const res = await forensicApi.sendCaseToSlack(targetCaseId);
      if (res.status === 'DELIVERED') {
        setSlackFeedback({ type: 'success', message: `Alert "${alert.title}" successfully dispatched to Slack!` });
      } else if (res.status === 'SKIPPED_SEVERITY') {
        setSlackFeedback({ type: 'error', message: `Alert skipped: severity is below the configured threshold (${minSeveritySlack}).` });
      } else {
        setSlackFeedback({ type: 'error', message: `Slack dispatch logged: ${res.status}. Check delivery logs.` });
      }
      await loadSlackStatus();
    } catch (err: any) {
      setSlackFeedback({ type: 'error', message: err?.response?.data?.error || 'Failed to dispatch alert to Slack' });
    } finally {
      setSendingAlertId(null);
    }
  };

  const filteredAlerts = liveAlerts.filter(alert => {
    if (filterSeverity === 'ALL') return true;
    return alert.severity === filterSeverity;
  });

  return (
    <div className="flex-1 flex flex-col h-full bg-[#14120f] overflow-y-auto p-6 space-y-6">
      {/* Top Banner */}
      <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 shadow-xl flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div className="flex items-center gap-4">
          <div className="w-12 h-12 rounded-2xl bg-cyan-950/80 border border-cyan-800/80 flex items-center justify-center">
            <Bell className="w-6 h-6 text-cyan-400" />
          </div>
          <div>
            <h2 className="text-lg font-bold text-slate-100 flex items-center gap-2">
              <span>Real-Time Threat Alerts &amp; SIEM Feed</span>
              {slackStatus?.configured && (
                <span className="flex items-center gap-1 text-[11px] font-semibold bg-emerald-950 text-emerald-300 border border-emerald-800 px-2 py-0.5 rounded-full">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
                  Slack Connected
                </span>
              )}
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Live WebSocket stream for critical IOC matches, high-risk BEC triggers, and automated Slack SOC dispatching.
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
            <span className="font-sans font-semibold text-slate-300">
              {wsStatus === 'connected' ? 'Connected' : wsStatus === 'connecting' ? 'Reconnecting...' : 'Disconnected'}
            </span>
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

      {/* Primary Navigation Tabs (Feed vs Slack SOC Hub) */}
      <div className="flex items-center justify-between border-b border-slate-800 pb-3">
        <div className="flex items-center gap-3">
          <button
            onClick={() => setActiveTab('feed')}
            className={`flex items-center gap-2 px-4 py-2 rounded-xl text-sm font-semibold transition-colors ${
              activeTab === 'feed'
                ? 'bg-cyan-600 text-white shadow-md'
                : 'bg-slate-900 border border-slate-800 text-slate-400 hover:text-slate-200'
            }`}
          >
            <Bell className="w-4 h-4" />
            <span>Live Alerts ({liveAlerts.length})</span>
          </button>

          <button
            onClick={() => setActiveTab('slack')}
            className={`flex items-center gap-2 px-4 py-2 rounded-xl text-sm font-semibold transition-colors ${
              activeTab === 'slack'
                ? 'bg-emerald-600 text-white shadow-md'
                : 'bg-slate-900 border border-slate-800 text-slate-400 hover:text-slate-200'
            }`}
          >
            <Share2 className="w-4 h-4" />
            <span>Slack SOC Integration</span>
            {slackStatus?.configured && (
              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-ping" />
            )}
          </button>
        </div>

        {activeTab === 'feed' && (
          <div className="flex items-center gap-2">
            {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(s => (
              <button
                key={s}
                onClick={() => setFilterSeverity(s)}
                className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-colors ${
                  filterSeverity === s
                    ? 'bg-slate-800 text-cyan-400 border border-cyan-800/80 shadow-sm'
                    : 'bg-slate-900/60 border border-slate-800 text-slate-400 hover:text-slate-200'
                }`}
              >
                {s === 'ALL' ? 'All' : s}
              </button>
            ))}
          </div>
        )}
      </div>

      {/* Global Feedback Banner */}
      {slackFeedback && (
        <div className={`p-4 rounded-xl border flex items-center justify-between text-xs ${
          slackFeedback.type === 'success'
            ? 'bg-emerald-950/40 border-emerald-800 text-emerald-300'
            : 'bg-red-950/40 border-red-800 text-red-300'
        }`}>
          <div className="flex items-center gap-2">
            {slackFeedback.type === 'success' ? <CheckCircle2 className="w-4 h-4 shrink-0 text-emerald-400" /> : <AlertCircle className="w-4 h-4 shrink-0 text-red-400" />}
            <span>{slackFeedback.message}</span>
          </div>
          <button onClick={() => setSlackFeedback(null)} className="p-1 hover:opacity-75">
            <X className="w-3.5 h-3.5" />
          </button>
        </div>
      )}

      {/* TAB 1: LIVE ALERTS FEED */}
      {activeTab === 'feed' && (
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
                        {alert.category && (
                          <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-cyan-400 border border-slate-700">
                            {alert.category}
                          </span>
                        )}
                        <span className="text-xs text-slate-500 flex items-center gap-1">
                          <Clock className="w-3 h-3" />
                          {new Date(alert.timestamp).toLocaleTimeString()}
                        </span>
                      </div>

                      <h3 className="text-sm font-bold text-slate-100">{alert.title}</h3>
                      <p className="text-xs text-slate-300 leading-relaxed">{alert.description}</p>

                      {alert.sender && (
                        <div className="text-xs font-mono text-slate-400 pt-1">
                          Sender: <span className="text-cyan-300">{alert.sender}</span>
                        </div>
                      )}
                    </div>

                    <div className="flex sm:flex-col items-end justify-between gap-2 shrink-0">
                      <span className="text-xs font-bold text-slate-400 bg-slate-950 px-2.5 py-1 rounded border border-slate-800">
                        Score: {alert.threat_score || 80}/100
                      </span>
                      
                      <div className="flex items-center gap-2">
                        <button
                          onClick={() => handleSendAlertToSlack(alert)}
                          disabled={sendingAlertId === alert.id}
                          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-emerald-950 hover:bg-emerald-800 border border-emerald-800 text-xs font-semibold text-emerald-300 transition-colors disabled:opacity-50"
                          title="Forward this case & alert directly to Slack webhook"
                        >
                          <Share2 className={`w-3.5 h-3.5 ${sendingAlertId === alert.id ? 'animate-spin' : ''}`} />
                          <span>{sendingAlertId === alert.id ? 'Sending...' : 'Send to Slack'}</span>
                        </button>

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
                </div>
              );
            })
          )}
        </div>
      )}

      {/* TAB 2: SLACK SOC INTEGRATION CONFIGURATION & LOGS */}
      {activeTab === 'slack' && (
        <div className="space-y-6">
          {/* Configuration Card */}
          <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 shadow-xl space-y-6">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-base font-bold text-slate-100 flex items-center gap-2">
                  <Settings2 className="w-5 h-5 text-emerald-400" />
                  <span>Slack Webhook Dispatcher Configuration</span>
                </h3>
                <p className="text-xs text-slate-400 mt-1">
                  Connect your Security Operations Center (SOC) channel to receive automated high-fidelity Block Kit forensic alerts.
                </p>
              </div>

              <div className="flex items-center gap-2">
                <span className={`px-2.5 py-1 rounded-full text-xs font-semibold flex items-center gap-1.5 ${
                  slackStatus?.configured
                    ? 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                    : 'bg-amber-950 text-amber-300 border border-amber-800'
                }`}>
                  <span className={`w-2 h-2 rounded-full ${slackStatus?.configured ? 'bg-emerald-400' : 'bg-amber-400'}`} />
                  {slackStatus?.configured ? 'Active & Ready' : 'Unconfigured Webhook'}
                </span>
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-6 pt-2">
              {/* Webhook Input */}
              <div className="space-y-2">
                <label className="text-xs font-bold text-slate-300 uppercase tracking-wider flex items-center justify-between">
                  <span>Slack Incoming Webhook URL</span>
                  {slackStatus?.webhook_url_masked && (
                    <span className="text-[11px] font-mono text-slate-500 lowercase">
                      Current: {slackStatus.webhook_url_masked}
                    </span>
                  )}
                </label>
                <input
                  type="password"
                  placeholder={slackStatus?.configured ? '•••••••••••• (Leave blank to keep existing)' : 'https://hooks.slack.com/services/T00/B00/XXXX'}
                  value={webhookInput}
                  onChange={(e) => setWebhookInput(e.target.value)}
                  className="w-full px-3.5 py-2.5 rounded-xl bg-slate-950 border border-slate-800 text-xs font-mono text-slate-200 focus:outline-none focus:border-emerald-500"
                />
                <p className="text-[11px] text-slate-500">
                  Generate in Slack via: Apps &gt; Custom Integrations &gt; Incoming Webhooks.
                </p>
              </div>

              {/* Channel & Bot Name */}
              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-2">
                  <label className="text-xs font-bold text-slate-300 uppercase tracking-wider">
                    Target Channel
                  </label>
                  <input
                    type="text"
                    placeholder="#soc-alerts"
                    value={slackChannel}
                    onChange={(e) => setSlackChannel(e.target.value)}
                    className="w-full px-3.5 py-2.5 rounded-xl bg-slate-950 border border-slate-800 text-xs font-mono text-slate-200 focus:outline-none focus:border-emerald-500"
                  />
                </div>
                <div className="space-y-2">
                  <label className="text-xs font-bold text-slate-300 uppercase tracking-wider">
                    Sender Name
                  </label>
                  <input
                    type="text"
                    placeholder="TraceXMail SOC Bot"
                    value={slackUsername}
                    onChange={(e) => setSlackUsername(e.target.value)}
                    className="w-full px-3.5 py-2.5 rounded-xl bg-slate-950 border border-slate-800 text-xs font-mono text-slate-200 focus:outline-none focus:border-emerald-500"
                  />
                </div>
              </div>

              {/* Auto Send Toggle */}
              <div className="flex items-center justify-between p-4 rounded-xl bg-slate-950 border border-slate-800">
                <div>
                  <div className="text-xs font-bold text-slate-200">Auto-Dispatch New Cases</div>
                  <div className="text-[11px] text-slate-400 mt-0.5">
                    Automatically emit a Slack alert whenever a new email is analyzed
                  </div>
                </div>
                <button
                  type="button"
                  onClick={() => setAutoSendSlack(!autoSendSlack)}
                  className={`relative inline-flex h-6 w-11 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none ${
                    autoSendSlack ? 'bg-emerald-600' : 'bg-slate-700'
                  }`}
                >
                  <span
                    className={`inline-block h-5 w-5 transform rounded-full bg-white shadow-lg ring-0 transition duration-200 ease-in-out ${
                      autoSendSlack ? 'translate-x-5' : 'translate-x-0'
                    }`}
                  />
                </button>
              </div>

              {/* Minimum Severity Filter */}
              <div className="space-y-2">
                <label className="text-xs font-bold text-slate-300 uppercase tracking-wider">
                  Minimum Alert Threshold
                </label>
                <select
                  value={minSeveritySlack}
                  onChange={(e) => setMinSeveritySlack(e.target.value as any)}
                  className="w-full px-3.5 py-2.5 rounded-xl bg-slate-950 border border-slate-800 text-xs font-semibold text-slate-200 focus:outline-none focus:border-emerald-500"
                >
                  <option value="ALL">All Analyses (Including Clean / Low Risk)</option>
                  <option value="MEDIUM">Medium &amp; Above (Score &gt;= 40)</option>
                  <option value="HIGH">High &amp; Above (Score &gt;= 70 - Recommended)</option>
                  <option value="CRITICAL">Critical Only (Score &gt;= 85)</option>
                </select>
              </div>
            </div>

            {/* Action Buttons */}
            <div className="flex items-center justify-end gap-3 pt-4 border-t border-slate-800">
              <button
                onClick={handleTestSlack}
                disabled={testingSlack}
                className="flex items-center gap-2 px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 border border-slate-700 text-xs font-semibold text-slate-200 transition-colors disabled:opacity-50"
              >
                <Send className={`w-3.5 h-3.5 ${testingSlack ? 'animate-spin' : 'text-emerald-400'}`} />
                <span>{testingSlack ? 'Testing Webhook...' : 'Test Slack Connection'}</span>
              </button>

              <button
                onClick={handleSaveSlackConfig}
                disabled={savingConfig}
                className="flex items-center gap-2 px-5 py-2 rounded-xl bg-emerald-600 hover:bg-emerald-500 text-xs font-bold text-white transition-colors shadow-lg disabled:opacity-50"
              >
                <Check className="w-4 h-4" />
                <span>{savingConfig ? 'Saving...' : 'Save Slack Settings'}</span>
              </button>
            </div>
          </div>

          {/* Delivery Logs Table */}
          <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 shadow-xl space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
                  <Clock className="w-4 h-4 text-cyan-400" />
                  <span>Slack SOC Dispatch History ({deliveryLogs.length})</span>
                </h3>
                <p className="text-xs text-slate-400 mt-0.5">
                  Audit log of recent automated and manual case alerts pushed to Slack.
                </p>
              </div>
              <button
                onClick={loadSlackStatus}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-slate-300"
              >
                <RefreshCw className={`w-3 h-3 ${slackLoading ? 'animate-spin' : ''}`} />
                <span>Refresh</span>
              </button>
            </div>

            {deliveryLogs.length === 0 ? (
              <div className="p-8 text-center rounded-xl bg-slate-950/60 border border-slate-800 text-slate-500 text-xs">
                No Slack deliveries recorded yet. Analyze an email or click &ldquo;Test Slack Connection&rdquo; to populate logs.
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs border-collapse">
                  <thead>
                    <tr className="border-b border-slate-800 text-slate-400 uppercase text-[10px] tracking-wider">
                      <th className="py-2.5 px-3">Time</th>
                      <th className="py-2.5 px-3">Subject / Trigger</th>
                      <th className="py-2.5 px-3">Severity</th>
                      <th className="py-2.5 px-3">Threat Score</th>
                      <th className="py-2.5 px-3">Status</th>
                      <th className="py-2.5 px-3">HTTP Code</th>
                      <th className="py-2.5 px-3 text-right">Details</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60 text-slate-300">
                    {deliveryLogs.map((log) => {
                      const isDelivered = log.status === 'DELIVERED';
                      const isSkipped = log.status === 'SKIPPED_SEVERITY';
                      const isExpanded = expandedPayloadId === log.id;

                      return (
                        <React.Fragment key={log.id}>
                          <tr className="hover:bg-slate-800/30">
                            <td className="py-3 px-3 font-mono text-slate-400">
                              {new Date(log.timestamp).toLocaleTimeString()}
                            </td>
                            <td className="py-3 px-3 font-semibold text-slate-200 max-w-xs truncate">
                              {log.subject}
                            </td>
                            <td className="py-3 px-3">
                              <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                                log.severity === 'CRITICAL' ? 'bg-red-950 text-red-300 border border-red-800' :
                                log.severity === 'HIGH' ? 'bg-amber-950 text-amber-300 border border-amber-800' :
                                'bg-slate-800 text-slate-300'
                              }`}>
                                {log.severity}
                              </span>
                            </td>
                            <td className="py-3 px-3 font-mono">
                              {log.threat_score}/100
                            </td>
                            <td className="py-3 px-3">
                              <span className={`px-2 py-0.5 rounded text-[10px] font-bold inline-flex items-center gap-1 ${
                                isDelivered ? 'bg-emerald-950 text-emerald-300 border border-emerald-800' :
                                isSkipped ? 'bg-slate-800 text-slate-400' :
                                'bg-red-950 text-red-300 border border-red-800'
                              }`}>
                                {isDelivered ? <CheckCircle2 className="w-3 h-3 text-emerald-400" /> : <AlertTriangle className="w-3 h-3" />}
                                {log.status}
                              </span>
                            </td>
                            <td className="py-3 px-3 font-mono text-slate-400">
                              {log.status_code || (isSkipped ? 'N/A' : '500')}
                            </td>
                            <td className="py-3 px-3 text-right">
                              <button
                                onClick={() => setExpandedPayloadId(isExpanded ? null : log.id)}
                                className="p-1 rounded hover:bg-slate-800 text-slate-400 hover:text-slate-200"
                                title="Inspect Block Kit payload"
                              >
                                {isExpanded ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
                              </button>
                            </td>
                          </tr>
                          {isExpanded && (
                            <tr>
                              <td colSpan={7} className="p-4 bg-slate-950/80 border-b border-slate-800">
                                <div className="space-y-2">
                                  <div className="flex items-center justify-between text-[11px] font-mono text-slate-400">
                                    <span className="flex items-center gap-1.5">
                                      <Code2 className="w-3.5 h-3.5 text-emerald-400" />
                                      Block Kit Payload Preview ({log.webhook_url_masked})
                                    </span>
                                    {log.error && <span className="text-red-400">{log.error}</span>}
                                  </div>
                                  <pre className="p-3 rounded-lg bg-slate-900 border border-slate-800 text-[10px] font-mono text-emerald-300 overflow-x-auto max-h-48">
                                    {JSON.stringify(log.payload_preview, null, 2)}
                                  </pre>
                                </div>
                              </td>
                            </tr>
                          )}
                        </React.Fragment>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

