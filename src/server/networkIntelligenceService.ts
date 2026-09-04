/**
 * TraceXMail Network Intelligence Service
 * 
 * Provides client and session network telemetry:
 * - Public IP and IP version (IPv4/IPv6) detection behind production reverse proxies
 * - Approximate geolocation, ISP/Organization, and ASN via free public intelligence providers (ipwho.is / ip-api.com)
 * - Server backend location reporting
 * - Dedicated latency ping endpoint
 * - Controlled bandwidth throughput test payload
 * 
 * Security & Reliability:
 * - Strict SSRF prevention (no arbitrary user URLs allowed)
 * - Input sanitization for IP parameters
 * - Request timeouts (AbortController) to prevent hanging
 * - Rate limit and failure resilience with graceful "Unavailable" degradation
 * - In-memory TTL caching to minimize third-party requests
 * - No user IP logging to preserve privacy
 */

import express from 'express';
import crypto from 'crypto';

export interface NetworkInfoResponse {
  ip: string;
  ipVersion: 'IPv4' | 'IPv6' | 'Unknown';
  city: string;
  region: string;
  country: string;
  organization: string;
  asn: string;
  serverLocation: string;
  source: string;
  isApproximate: boolean;
  disclaimer: string;
  cached?: boolean;
}

// 512 KB payload for controlled on-demand client bandwidth testing
export const BANDWIDTH_PAYLOAD_BYTES = 512 * 1024;
const BANDWIDTH_TEST_BUFFER = crypto.randomBytes(BANDWIDTH_PAYLOAD_BYTES);

// In-memory cache for IP intelligence to avoid redundant external calls (10-minute TTL)
interface CacheEntry {
  data: NetworkInfoResponse;
  expiresAt: number;
}
const networkInfoCache = new Map<string, CacheEntry>();
const CACHE_TTL_MS = 10 * 60 * 1000; // 10 minutes

// Cached server location
let cachedServerLocation: string | null = null;

/**
 * Cleanly extracts client IP taking into account reverse proxy configurations
 */
export function extractClientIp(req: express.Request): string {
  let ip = '';
  
  // When 'trust proxy' is configured in Express, req.ips holds the client + proxy hop chain
  if (Array.isArray(req.ips) && req.ips.length > 0) {
    ip = req.ips[0];
  } else if (req.ip) {
    ip = req.ip;
  } else if (req.socket && req.socket.remoteAddress) {
    ip = req.socket.remoteAddress;
  }

  // Strip IPv6-mapped IPv4 prefix (e.g. ::ffff:192.0.2.1 -> 192.0.2.1)
  if (ip && ip.startsWith('::ffff:')) {
    ip = ip.replace('::ffff:', '');
  }

  // Normalize IPv6 loopback
  if (ip === '::1') {
    ip = '127.0.0.1';
  }

  // Remove port if present (e.g., 192.168.1.1:12345)
  if (ip && ip.includes(':') && !ip.includes('::') && ip.split(':').length === 2) {
    ip = ip.split(':')[0];
  }

  return ip ? ip.trim() : '';
}

/**
 * Determines whether an IP is IPv4 or IPv6
 */
export function detectIpVersion(ip: string): 'IPv4' | 'IPv6' | 'Unknown' {
  if (!ip || ip === 'Unavailable') return 'Unknown';
  if (ip.includes(':')) return 'IPv6';
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) return 'IPv4';
  return 'Unknown';
}

/**
 * Checks if an IP is private, link-local, loopback, or reserved
 */
export function isPrivateOrReservedIp(ip: string): boolean {
  if (!ip) return true;
  if (ip === '127.0.0.1' || ip === '::1' || ip === 'localhost') return true;
  
  // RFC 1918 & RFC 3927 (IPv4 private and link-local ranges)
  if (/^(10\.|127\.|169\.254\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.)/.test(ip)) return true;
  
  // RFC 4193 & RFC 4291 (IPv6 unique-local and link-local ranges)
  if (/^(fc00:|fe80:|::1)/i.test(ip)) return true;
  
  return false;
}

/**
 * Resolves the hosting backend environment/location
 */
export function getServerLocation(): string {
  if (cachedServerLocation) {
    return cachedServerLocation;
  }

  // Check Cloud Run environment indicators
  if (process.env.K_SERVICE || process.env.CLOUD_RUN_JOB) {
    cachedServerLocation = 'Singapore (asia-southeast1, Google Cloud Run)';
    return cachedServerLocation;
  }

  if (process.env.NODE_ENV === 'production') {
    cachedServerLocation = 'Cloud Production Instance';
  } else {
    cachedServerLocation = 'Local Development Server (port 3000)';
  }

  return cachedServerLocation;
}

/**
 * Sets the detected server location (e.g., discovered during startup)
 */
export function setServerLocation(loc: string): void {
  cachedServerLocation = loc;
}

/**
 * Safely sanitizes and validates an IP string before passing to queries
 */
export function isValidIp(ip: string): boolean {
  if (!ip) return false;
  // IPv4 regex
  const ipv4Regex = /^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$/;
  if (ipv4Regex.test(ip)) return true;
  
  // IPv6 regex
  const ipv6Regex = /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::$|^::1$|^([0-9a-fA-F]{1,4}:){1,7}:$|^([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}$/;
  return ipv6Regex.test(ip);
}

/**
 * Queries the primary free IP geolocation provider (ipwho.is)
 */
async function queryIpWhoIs(targetIp?: string): Promise<Partial<NetworkInfoResponse> | null> {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 4000);

  try {
    const url = targetIp && isValidIp(targetIp)
      ? `https://ipwho.is/${encodeURIComponent(targetIp)}`
      : 'https://ipwho.is/';

    const response = await fetch(url, {
      signal: controller.signal,
      headers: {
        'Accept': 'application/json',
        'User-Agent': 'TraceXMail-Forensics-Engine/1.0'
      }
    });

    clearTimeout(timeoutId);

    if (!response.ok) {
      return null;
    }

    const data = await response.json();
    if (!data || data.success === false) {
      return null;
    }

    const ip = typeof data.ip === 'string' ? data.ip : '';
    const ipType = data.type === 'IPv6' ? 'IPv6' : (data.type === 'IPv4' ? 'IPv4' : detectIpVersion(ip));
    
    // Format ASN
    let asnStr = 'Unavailable';
    if (data.connection?.asn) {
      asnStr = typeof data.connection.asn === 'number'
        ? `AS${data.connection.asn}`
        : String(data.connection.asn).startsWith('AS')
          ? String(data.connection.asn)
          : `AS${data.connection.asn}`;
    }

    return {
      ip: ip || 'Unavailable',
      ipVersion: ipType,
      city: data.city || 'Unavailable',
      region: data.region || 'Unavailable',
      country: data.country || 'Unavailable',
      organization: data.connection?.org || data.connection?.isp || 'Unavailable',
      asn: asnStr,
      source: 'ipwho.is'
    };
  } catch {
    clearTimeout(timeoutId);
    return null;
  }
}

/**
 * Queries fallback free provider (ip-api.com)
 */
async function queryIpApiFallback(targetIp?: string): Promise<Partial<NetworkInfoResponse> | null> {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 4000);

  try {
    const url = targetIp && isValidIp(targetIp)
      ? `http://ip-api.com/json/${encodeURIComponent(targetIp)}`
      : 'http://ip-api.com/json/';

    const response = await fetch(url, {
      signal: controller.signal,
      headers: {
        'Accept': 'application/json',
        'User-Agent': 'TraceXMail-Forensics-Engine/1.0'
      }
    });

    clearTimeout(timeoutId);

    if (!response.ok) {
      return null;
    }

    const data = await response.json();
    if (!data || data.status !== 'success') {
      return null;
    }

    const ip = typeof data.query === 'string' ? data.query : '';
    const asn = typeof data.as === 'string' ? data.as.split(' ')[0] : 'Unavailable';

    return {
      ip: ip || 'Unavailable',
      ipVersion: detectIpVersion(ip),
      city: data.city || 'Unavailable',
      region: data.regionName || 'Unavailable',
      country: data.country || 'Unavailable',
      organization: data.org || data.isp || 'Unavailable',
      asn: asn || 'Unavailable',
      source: 'ip-api.com'
    };
  } catch {
    clearTimeout(timeoutId);
    return null;
  }
}

/**
 * Main Network Information Resolver
 * Fetches dynamic public network intelligence for the current request
 */
export async function resolveNetworkInfo(req: express.Request): Promise<NetworkInfoResponse> {
  const clientIp = extractClientIp(req);
  const isPrivate = isPrivateOrReservedIp(clientIp);
  const cacheKey = (!isPrivate && clientIp) ? clientIp : '__session_egress__';
  const forceRefresh = req.query.force_refresh === 'true';

  // Check cache
  if (!forceRefresh) {
    const cached = networkInfoCache.get(cacheKey);
    if (cached && cached.expiresAt > Date.now()) {
      return { ...cached.data, cached: true };
    }
  }

  // Attempt resolution via primary provider (ipwho.is)
  // If the client is on a private network/localhost, query without IP to detect the public gateway
  const queryIp = (!isPrivate && isValidIp(clientIp)) ? clientIp : undefined;
  let resolved = await queryIpWhoIs(queryIp);

  // If primary fails or is rate-limited, try fallback provider
  if (!resolved) {
    resolved = await queryIpApiFallback(queryIp);
  }

  const serverLoc = getServerLocation();
  const disclaimer = 'IP-based location is approximate and may not represent the user\'s exact location.';

  // If resolution succeeded:
  if (resolved && resolved.ip && resolved.ip !== 'Unavailable') {
    const result: NetworkInfoResponse = {
      ip: resolved.ip,
      ipVersion: resolved.ipVersion || detectIpVersion(resolved.ip),
      city: resolved.city || 'Unavailable',
      region: resolved.region || 'Unavailable',
      country: resolved.country || 'Unavailable',
      organization: resolved.organization || 'Unavailable',
      asn: resolved.asn || 'Unavailable',
      serverLocation: serverLoc,
      source: resolved.source || 'ipwho.is',
      isApproximate: true,
      disclaimer,
      cached: false
    };

    // Cache result
    networkInfoCache.set(cacheKey, {
      data: result,
      expiresAt: Date.now() + CACHE_TTL_MS
    });

    return result;
  }

  // Graceful degradation when external services are unavailable or in an isolated test environment
  const fallbackResult: NetworkInfoResponse = {
    ip: clientIp || 'Unavailable',
    ipVersion: detectIpVersion(clientIp),
    city: 'Unavailable',
    region: 'Unavailable',
    country: 'Unavailable',
    organization: isPrivate ? 'Local / Private Network' : 'Unavailable',
    asn: 'Unavailable',
    serverLocation: serverLoc,
    source: 'unavailable',
    isApproximate: true,
    disclaimer,
    cached: false
  };

  return fallbackResult;
}

/**
 * Express Route Handler: GET /api/network-info
 */
export async function handleGetNetworkInfo(req: express.Request, res: express.Response): Promise<void> {
  try {
    const info = await resolveNetworkInfo(req);
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
    res.json(info);
  } catch (err: any) {
    // Under no circumstances should this endpoint crash
    const fallback: NetworkInfoResponse = {
      ip: extractClientIp(req) || 'Unavailable',
      ipVersion: 'Unknown',
      city: 'Unavailable',
      region: 'Unavailable',
      country: 'Unavailable',
      organization: 'Unavailable',
      asn: 'Unavailable',
      serverLocation: getServerLocation(),
      source: 'unavailable',
      isApproximate: true,
      disclaimer: 'IP-based location is approximate and may not represent the user\'s exact location.'
    };
    res.json(fallback);
  }
}

/**
 * Express Route Handler: GET /api/network/ping
 * Returns a tiny payload with timestamp for client-side round-trip time (RTT) latency measurement
 */
export function handlePingNetwork(req: express.Request, res: express.Response): void {
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
  res.json({
    status: 'ok',
    timestamp: Date.now()
  });
}

/**
 * Express Route Handler: GET /api/network/bandwidth-payload
 * Returns a controlled 512 KB payload for on-demand download throughput measurement
 */
export function handleGetBandwidthPayload(req: express.Request, res: express.Response): void {
  res.setHeader('Content-Type', 'application/octet-stream');
  res.setHeader('Content-Length', String(BANDWIDTH_PAYLOAD_BYTES));
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
  res.setHeader('Content-Disposition', 'inline; filename="bandwidth-test.bin"');
  res.send(BANDWIDTH_TEST_BUFFER);
}
