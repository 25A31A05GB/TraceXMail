import React, { useEffect, useState, useCallback } from 'react';
import {
  Globe,
  Radio,
  Server,
  Activity,
  ArrowDownUp,
  RefreshCw,
  Copy,
  Check,
  AlertCircle,
  Info,
  Layers,
  MapPin,
  Building2,
  Cpu
} from 'lucide-react';
import { forensicApi, NetworkInfoData } from '../lib/api';

interface NetworkIntelligenceCardProps {
  className?: string;
  compact?: boolean;
}

export function NetworkIntelligenceCard({ className = '', compact = false }: NetworkIntelligenceCardProps) {
  const [networkInfo, setNetworkInfo] = useState<NetworkInfoData | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  // Latency state
  const [latencyMs, setLatencyMs] = useState<number | null>(null);
  const [isPinging, setIsPinging] = useState<boolean>(false);

  // Bandwidth state
  const [bandwidth, setBandwidth] = useState<{ mbps: number; durationMs: number; bytes: number } | null>(null);
  const [isTestingBandwidth, setIsTestingBandwidth] = useState<boolean>(false);
  const [bandwidthError, setBandwidthError] = useState<string | null>(null);

  // Copy feedback
  const [copiedIp, setCopiedIp] = useState<boolean>(false);

  // Fetch Network Info
  const fetchNetworkInfo = useCallback(async (forceRefresh = false) => {
    setLoading(true);
    setError(null);
    try {
      const data = await forensicApi.getNetworkInfo(forceRefresh);
      setNetworkInfo(data);
    } catch (err: any) {
      console.warn('[NetworkIntelligence] Failed to fetch telemetry:', err);
      setError('Network information unavailable');
    } finally {
      setLoading(false);
    }
  }, []);

  // Measure Latency via /api/network/ping
  const measureLatency = useCallback(async () => {
    setIsPinging(true);
    try {
      const rtt = await forensicApi.measureLatency();
      setLatencyMs(rtt);
    } catch (err) {
      console.warn('[NetworkIntelligence] Latency ping failed:', err);
      setLatencyMs(null);
    } finally {
      setIsPinging(false);
    }
  }, []);

  // Measure Bandwidth via controlled 512 KB payload
  const runBandwidthTest = async () => {
    setIsTestingBandwidth(true);
    setBandwidthError(null);
    try {
      const result = await forensicApi.measureBandwidth();
      setBandwidth(result);
    } catch (err: any) {
      console.warn('[NetworkIntelligence] Bandwidth measurement error:', err);
      setBandwidthError('Bandwidth measurement unavailable');
    } finally {
      setIsTestingBandwidth(false);
    }
  };

  // Initial load
  useEffect(() => {
    fetchNetworkInfo();
    measureLatency();
  }, [fetchNetworkInfo, measureLatency]);

  // Handle Copy IP
  const handleCopyIp = async () => {
    if (!networkInfo?.ip || networkInfo.ip === 'Unavailable') return;
    try {
      await navigator.clipboard.writeText(networkInfo.ip);
      setCopiedIp(true);
      setTimeout(() => setCopiedIp(false), 2000);
    } catch (err) {
      console.warn('Clipboard copy failed:', err);
    }
  };

  // Formatted location string
  const formatLocation = (info: NetworkInfoData | null) => {
    if (!info) return 'Unavailable';
    const parts = [info.city, info.region, info.country].filter(
      p => p && p !== 'Unavailable' && p !== 'Unknown'
    );
    return parts.length > 0 ? parts.join(', ') : 'Unavailable';
  };

  // Latency quality color
  const getLatencyColor = (ms: number | null) => {
    if (ms === null) return 'text-slate-400';
    if (ms < 100) return 'text-emerald-400';
    if (ms < 250) return 'text-amber-400';
    return 'text-rose-400';
  };

  const getLatencyBadgeBg = (ms: number | null) => {
    if (ms === null) return 'bg-slate-800 border-slate-700 text-slate-400';
    if (ms < 100) return 'bg-emerald-950/60 border-emerald-700/50 text-emerald-300';
    if (ms < 250) return 'bg-amber-950/60 border-amber-700/50 text-amber-300';
    return 'bg-rose-950/60 border-rose-700/50 text-rose-300';
  };

  return (
    <div
      id="network-intelligence-card"
      className={`bg-slate-900/90 border border-slate-800 rounded-xl p-5 shadow-lg relative overflow-hidden transition-all ${className}`}
    >
      {/* Background ambient glow */}
      <div className="absolute top-0 right-0 w-64 h-32 bg-blue-600/5 rounded-full blur-3xl pointer-events-none" />

      {/* Header with Visual Distinction for Session Telemetry vs. Investigated Email */}
      <div className="flex items-start justify-between gap-3 border-b border-slate-800/80 pb-4 mb-4">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-lg bg-blue-950/80 border border-blue-700/40 flex items-center justify-center text-blue-400 shadow-inner">
            <Globe className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-sm font-bold text-slate-100 uppercase tracking-wider font-mono">
                Network Intelligence
              </h2>
              <span className="text-[10px] uppercase font-mono px-2 py-0.5 rounded bg-blue-950 border border-blue-800/80 text-blue-300 font-semibold tracking-wide">
                Analyst Session
              </span>
            </div>
            <p className="text-[11px] text-slate-400 mt-0.5">
              Workstation connection telemetry — isolated from analyzed email threat evidence
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          {/* Re-ping button */}
          <button
            id="btn-reping"
            onClick={measureLatency}
            disabled={isPinging}
            title="Measure round-trip API ping latency"
            className="px-2.5 py-1 text-xs font-mono bg-slate-800/80 hover:bg-slate-700/80 border border-slate-700 rounded text-slate-300 flex items-center gap-1.5 transition-colors disabled:opacity-50 cursor-pointer"
          >
            <Activity className={`w-3.5 h-3.5 text-blue-400 ${isPinging ? 'animate-pulse' : ''}`} />
            <span>{isPinging ? 'Pinging...' : 'Ping'}</span>
          </button>

          {/* Refresh Network Info button */}
          <button
            id="btn-refresh-network"
            onClick={() => fetchNetworkInfo(true)}
            disabled={loading}
            title="Refresh network intelligence"
            className="p-1.5 text-slate-400 hover:text-slate-200 bg-slate-800/80 hover:bg-slate-700/80 border border-slate-700 rounded transition-colors disabled:opacity-50 cursor-pointer"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin text-blue-400' : ''}`} />
          </button>
        </div>
      </div>

      {/* Loading Skeleton */}
      {loading && !networkInfo && (
        <div className="space-y-3 animate-pulse py-2">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            {[1, 2, 3, 4].map(i => (
              <div key={i} className="h-14 bg-slate-800/50 rounded-lg" />
            ))}
          </div>
          <div className="h-20 bg-slate-800/40 rounded-lg" />
        </div>
      )}

      {/* API Failure State */}
      {!loading && error && !networkInfo && (
        <div className="py-6 text-center">
          <div className="w-10 h-10 mx-auto mb-2 rounded-full bg-rose-950/50 border border-rose-800/60 flex items-center justify-center text-rose-400">
            <AlertCircle className="w-5 h-5" />
          </div>
          <p className="text-xs font-semibold text-rose-300 uppercase tracking-wide">
            Network information unavailable
          </p>
          <p className="text-[11px] text-slate-400 max-w-sm mx-auto mt-1">
            Could not retrieve public IP telemetry from public services. Your connection remains active.
          </p>
          <button
            onClick={() => fetchNetworkInfo(true)}
            className="mt-3 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 border border-slate-700 text-xs font-mono text-slate-200 rounded transition-colors cursor-pointer"
          >
            Retry Telemetry Fetch
          </button>
        </div>
      )}

      {/* Main Network Telemetry Grid */}
      {networkInfo && (
        <div className="space-y-4">
          {/* Primary Metrics Grid */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
            {/* Connection: IPv4 or IPv6 */}
            <div className="p-3 bg-slate-950/60 border border-slate-800 rounded-lg flex flex-col justify-between">
              <div className="flex items-center justify-between text-slate-400 mb-1">
                <span className="text-[10.5px] font-semibold uppercase tracking-wider text-slate-400">
                  Connection
                </span>
                <Radio className="w-3.5 h-3.5 text-blue-400" />
              </div>
              <div className="flex items-center gap-2 mt-1">
                <span
                  id="metric-connection-version"
                  className="px-2 py-0.5 rounded text-xs font-mono font-bold bg-blue-950/90 border border-blue-600/50 text-blue-300"
                >
                  {networkInfo.ipVersion || 'Unknown'}
                </span>
                <span className="text-[11px] text-slate-400 font-mono">
                  {networkInfo.ipVersion === 'IPv6' ? 'Native IPv6' : 'Standard IPv4'}
                </span>
              </div>
            </div>

            {/* Public IP */}
            <div className="p-3 bg-slate-950/60 border border-slate-800 rounded-lg flex flex-col justify-between">
              <div className="flex items-center justify-between text-slate-400 mb-1">
                <span className="text-[10.5px] font-semibold uppercase tracking-wider text-slate-400">
                  Public IP
                </span>
                <button
                  onClick={handleCopyIp}
                  title="Copy IP Address"
                  className="text-slate-400 hover:text-slate-200 transition-colors cursor-pointer"
                >
                  {copiedIp ? (
                    <Check className="w-3.5 h-3.5 text-emerald-400" />
                  ) : (
                    <Copy className="w-3.5 h-3.5" />
                  )}
                </button>
              </div>
              <div className="mt-1 flex items-baseline justify-between gap-1 overflow-hidden">
                <span
                  id="metric-public-ip"
                  className="text-xs font-mono font-bold text-slate-100 truncate"
                  title={networkInfo.ip}
                >
                  {networkInfo.ip || 'Unavailable'}
                </span>
                {copiedIp && (
                  <span className="text-[10px] font-mono text-emerald-400 shrink-0">Copied</span>
                )}
              </div>
            </div>

            {/* Approx. Location */}
            <div className="p-3 bg-slate-950/60 border border-slate-800 rounded-lg flex flex-col justify-between">
              <div className="flex items-center justify-between text-slate-400 mb-1">
                <span className="text-[10.5px] font-semibold uppercase tracking-wider text-slate-400">
                  Approx. Location
                </span>
                <MapPin className="w-3.5 h-3.5 text-amber-400" />
              </div>
              <div
                id="metric-approx-location"
                className="text-xs font-bold text-slate-100 truncate mt-1"
                title={formatLocation(networkInfo)}
              >
                {formatLocation(networkInfo)}
              </div>
            </div>

            {/* Network Latency */}
            <div className="p-3 bg-slate-950/60 border border-slate-800 rounded-lg flex flex-col justify-between">
              <div className="flex items-center justify-between text-slate-400 mb-1">
                <span className="text-[10.5px] font-semibold uppercase tracking-wider text-slate-400">
                  Latency (RTT)
                </span>
                <Activity className="w-3.5 h-3.5 text-blue-400" />
              </div>
              <div className="flex items-center gap-2 mt-1">
                <div
                  className={`w-2 h-2 rounded-full ${
                    latencyMs === null
                      ? 'bg-slate-500'
                      : latencyMs < 100
                      ? 'bg-emerald-400 animate-pulse'
                      : latencyMs < 250
                      ? 'bg-amber-400'
                      : 'bg-rose-400'
                  }`}
                />
                <span
                  id="metric-latency-val"
                  className={`text-xs font-mono font-bold ${getLatencyColor(latencyMs)}`}
                >
                  {latencyMs !== null ? `${latencyMs} ms` : 'Measuring...'}
                </span>
                <span className="text-[10px] text-slate-500 font-mono">browser-to-API</span>
              </div>
            </div>
          </div>

          {/* Infrastructure Details Row */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            {/* Network / ISP */}
            <div className="p-3 bg-slate-950/60 border border-slate-800 rounded-lg">
              <div className="flex items-center gap-1.5 text-slate-400 mb-1">
                <Building2 className="w-3.5 h-3.5 text-slate-400" />
                <span className="text-[10.5px] font-semibold uppercase tracking-wider">
                  Network / ISP
                </span>
              </div>
              <div
                id="metric-network-isp"
                className="text-xs font-semibold text-slate-200 truncate"
                title={networkInfo.organization}
              >
                {networkInfo.organization || 'Unavailable'}
              </div>
            </div>

            {/* ASN */}
            <div className="p-3 bg-slate-950/60 border border-slate-800 rounded-lg">
              <div className="flex items-center gap-1.5 text-slate-400 mb-1">
                <Layers className="w-3.5 h-3.5 text-purple-400" />
                <span className="text-[10.5px] font-semibold uppercase tracking-wider">
                  ASN
                </span>
              </div>
              <div className="flex items-center gap-2">
                <span
                  id="metric-asn-val"
                  className="text-xs font-mono font-bold text-purple-300"
                >
                  {networkInfo.asn || 'Unavailable'}
                </span>
                {networkInfo.asn && networkInfo.asn !== 'Unavailable' && (
                  <span className="text-[10px] text-slate-500 font-mono">Autonomous System</span>
                )}
              </div>
            </div>

            {/* Server Location */}
            <div className="p-3 bg-slate-950/60 border border-slate-800 rounded-lg">
              <div className="flex items-center gap-1.5 text-slate-400 mb-1">
                <Server className="w-3.5 h-3.5 text-emerald-400" />
                <span className="text-[10.5px] font-semibold uppercase tracking-wider">
                  Server
                </span>
              </div>
              <div
                id="metric-server-location"
                className="text-xs font-semibold text-slate-200 truncate"
                title={networkInfo.serverLocation}
              >
                {networkInfo.serverLocation || 'Unavailable'}
              </div>
            </div>
          </div>

          {/* Optional Bandwidth Measurement Section */}
          <div className="p-3 bg-slate-950/40 border border-slate-800/80 rounded-lg flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
            <div>
              <div className="flex items-center gap-2">
                <ArrowDownUp className="w-4 h-4 text-blue-400" />
                <span className="text-xs font-bold text-slate-200 uppercase tracking-wide">
                  Bandwidth Measurement (Estimate)
                </span>
                {bandwidth && (
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-950 border border-emerald-800 text-emerald-300 font-bold">
                    {bandwidth.mbps} Mbps (Estimated)
                  </span>
                )}
              </div>
              <p className="text-[11px] text-slate-400 mt-0.5">
                {bandwidth
                  ? `Transferred ${(bandwidth.bytes / 1024).toFixed(0)} KB in ${bandwidth.durationMs} ms. Controlled single-stream estimation.`
                  : 'On-demand download test. Performs a controlled ~512 KB payload transfer to estimate client-to-backend throughput.'}
              </p>
              {bandwidthError && (
                <p className="text-[11px] text-rose-400 mt-1 flex items-center gap-1">
                  <AlertCircle className="w-3 h-3" />
                  {bandwidthError}
                </p>
              )}
            </div>

            <div className="flex items-center gap-2 shrink-0">
              <button
                id="btn-test-bandwidth"
                onClick={runBandwidthTest}
                disabled={isTestingBandwidth}
                className="px-3 py-1.5 text-xs font-mono font-semibold bg-blue-600 hover:bg-blue-500 disabled:bg-slate-800 disabled:text-slate-500 text-white rounded-lg shadow transition-colors flex items-center gap-1.5 cursor-pointer"
              >
                {isTestingBandwidth ? (
                  <>
                    <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                    <span>Measuring...</span>
                  </>
                ) : (
                  <>
                    <ArrowDownUp className="w-3.5 h-3.5" />
                    <span>{bandwidth ? 'Retest Bandwidth' : 'Test Bandwidth'}</span>
                  </>
                )}
              </button>
            </div>
          </div>

          {/* Mandatory Jury-Friendly Disclaimer & Data Hygiene Note */}
          <div className="flex items-start gap-2 pt-1 text-[11px] text-slate-400 border-t border-slate-800/60">
            <Info className="w-3.5 h-3.5 text-amber-400 shrink-0 mt-0.5" />
            <div className="leading-relaxed">
              <span className="font-semibold text-slate-300">
                IP-based location is approximate and may not represent the user's exact location.
              </span>{' '}
              Geolocation is derived via public ASN registry mappings ({networkInfo.source}) and does not reflect GPS or physical coordinates.
              {networkInfo.cached && (
                <span className="ml-1 text-[10px] text-slate-500 font-mono">(cached for session)</span>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
