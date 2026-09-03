import { IntelligenceCache } from './cache';
import { createProvenanceMetadata } from './provenance';
import { 
  IntelligenceLookupStatus, 
  ProvenanceMetadata,
  VirusTotalAnalysisStats,
  VirusTotalUrlResult,
  VirusTotalFileResult
} from './types';

// ============================================================================
// VirusTotal API v3 TypeScript Interfaces & Models
// ============================================================================

export interface VirusTotalEnrichmentResponse {
  status: 'success' | 'unconfigured' | 'unavailable' | 'error';
  vt_active: boolean;
  is_configured: boolean;
  message: string;
  scanned_count: number;
  flagged_count: number;
  api_status: {
    configured: boolean;
    provider: string;
    endpoint: string;
    message: string;
  };
  urls: Array<{
    url: string;
    defangedUrl?: string;
    domain?: string;
    status: 'MALICIOUS' | 'SUSPICIOUS' | 'CLEAN' | 'UNKNOWN';
    virustotalScore?: string;
    category?: string;
    positives?: number;
    total_engines?: number;
    last_analysis_stats?: VirusTotalAnalysisStats;
    vt_active?: boolean;
    vt_status?: IntelligenceLookupStatus;
  }>;
  attachments: Array<{
    filename?: string;
    name?: string;
    hash?: string;
    sha256?: string;
    md5?: string;
    size?: string | number;
    status: 'MALICIOUS' | 'SUSPICIOUS' | 'CLEAN' | 'UNKNOWN';
    vtDetection?: string;
    positives?: number;
    total_engines?: number;
    last_analysis_stats?: VirusTotalAnalysisStats;
    vt_active?: boolean;
    vt_status?: IntelligenceLookupStatus;
  }>;
  logs: Array<{
    id: string;
    timestamp: string;
    tag: string;
    message: string;
    highlight?: boolean;
  }>;
  new_vt_logs: Array<{
    id: string;
    timestamp: string;
    tag: string;
    message: string;
    highlight?: boolean;
  }>;
}

// ============================================================================
// In-Memory Caches with 1-hour TTL & LRU eviction
// ============================================================================

export const vtUrlLookupCache = new IntelligenceCache<VirusTotalUrlResult>({
  ttlMs: 60 * 60 * 1000, // 1 Hour TTL
  maxEntries: 2000
});

export const vtFileLookupCache = new IntelligenceCache<VirusTotalFileResult>({
  ttlMs: 60 * 60 * 1000, // 1 Hour TTL
  maxEntries: 2000
});

// Helper to base64url encode URLs without padding per RFC 4648 §5
export function encodeVirusTotalUrlId(rawUrl: string): string {
  return Buffer.from(rawUrl.trim()).toString('base64url');
}

/**
 * Checks if VirusTotal API is configured in the environment
 */
export function isVirusTotalConfigured(): boolean {
  const key = (process.env.VIRUSTOTAL_API_KEY || '').trim();
  return key.length > 0 && !key.includes('placeholder') && !key.includes('your_');
}

/**
 * Retrieves the current operational status of the VirusTotal integration
 */
export function getVirusTotalStatus() {
  const configured = isVirusTotalConfigured();
  return {
    configured,
    active: configured,
    provider: 'VirusTotal API v3',
    endpoint: 'https://www.virustotal.com/api/v3',
    message: configured
      ? 'VirusTotal API v3 key is active and ready for live multi-engine reputation queries.'
      : 'VIRUSTOTAL_API_KEY is not configured in server environment. IOC queries return unconfigured status.',
    cacheStats: {
      cachedUrls: vtUrlLookupCache.size(),
      cachedFiles: vtFileLookupCache.size()
    }
  };
}

/**
 * Real VirusTotal v3 URL Reputation Lookup
 */
export async function lookupVirusTotalUrl(
  rawUrl: string,
  options?: { forceRefresh?: boolean }
): Promise<VirusTotalUrlResult> {
  const normalized = rawUrl.trim();
  const nowIso = new Date().toISOString();
  const apiKey = (process.env.VIRUSTOTAL_API_KEY || '').trim();
  const urlId = encodeVirusTotalUrlId(normalized);

  // Check cache unless forceRefresh requested
  if (!options?.forceRefresh) {
    const cached = vtUrlLookupCache.get(normalized);
    if (cached) {
      return { ...cached, cached: true };
    }
  }

  // Handle Unconfigured API Key (Honest zero-fabrication return)
  if (!isVirusTotalConfigured()) {
    const unconfiguredResult: VirusTotalUrlResult = {
      url: normalized,
      urlId,
      lookupStatus: 'unavailable',
      isConfigured: false,
      isMalicious: false,
      isSuspicious: false,
      positives: 0,
      totalEngines: 0,
      scoreString: 'VT Inactive (No Key)',
      category: 'Uninspected Link (VT Unconfigured)',
      lastAnalysisStats: { malicious: 0, suspicious: 0, harmless: 0, undetected: 0 },
      tags: [],
      retrievedAt: nowIso,
      cached: false,
      provenance: createProvenanceMetadata({
        evidenceType: 'ENRICHED',
        provider: 'VirusTotal v3 Gateway',
        source: 'https://www.virustotal.com/api/v3/urls',
        status: 'unavailable',
        reason: 'VIRUSTOTAL_API_KEY is not configured in server environment'
      })
    };
    return unconfiguredResult;
  }

  const endpoint = `https://www.virustotal.com/api/v3/urls/${urlId}`;

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 8000);

    const response = await fetch(endpoint, {
      method: 'GET',
      headers: {
        'x-apikey': apiKey,
        'Accept': 'application/json'
      },
      signal: controller.signal
    });
    clearTimeout(timeout);

    // 404: Not indexed yet in VirusTotal database
    if (response.status === 404) {
      const notFoundResult: VirusTotalUrlResult = {
        url: normalized,
        urlId,
        lookupStatus: 'unavailable',
        isConfigured: true,
        isMalicious: false,
        isSuspicious: false,
        positives: 0,
        totalEngines: 0,
        scoreString: '0/0 (Unindexed URL)',
        category: 'Unindexed Link',
        lastAnalysisStats: { malicious: 0, suspicious: 0, harmless: 0, undetected: 0 },
        tags: [],
        retrievedAt: nowIso,
        cached: false,
        provenance: createProvenanceMetadata({
          evidenceType: 'ENRICHED',
          provider: 'VirusTotal v3',
          source: endpoint,
          status: 'unavailable',
          reason: 'URL not currently indexed in VirusTotal database'
        })
      };
      vtUrlLookupCache.set(normalized, notFoundResult, 5 * 60 * 1000); // 5 min TTL for 404
      return notFoundResult;
    }

    // 429: Rate limited
    if (response.status === 429) {
      const rateLimitResult: VirusTotalUrlResult = {
        url: normalized,
        urlId,
        lookupStatus: 'rate_limited',
        isConfigured: true,
        isMalicious: false,
        isSuspicious: false,
        positives: 0,
        totalEngines: 0,
        scoreString: 'Rate Limited',
        category: 'Query Throttled',
        lastAnalysisStats: { malicious: 0, suspicious: 0, harmless: 0, undetected: 0 },
        tags: [],
        retrievedAt: nowIso,
        cached: false,
        provenance: createProvenanceMetadata({
          evidenceType: 'ENRICHED',
          provider: 'VirusTotal v3',
          source: endpoint,
          status: 'rate_limited',
          reason: 'VirusTotal v3 API rate limit exceeded'
        })
      };
      return rateLimitResult;
    }

    if (!response.ok) {
      console.warn(`[VirusTotal API v3] URL lookup error (${response.status}): ${response.statusText}`);
      return {
        url: normalized,
        urlId,
        lookupStatus: 'error',
        isConfigured: true,
        isMalicious: false,
        isSuspicious: false,
        positives: 0,
        totalEngines: 0,
        scoreString: `Error (${response.status})`,
        category: 'Lookup Error',
        lastAnalysisStats: { malicious: 0, suspicious: 0, harmless: 0, undetected: 0 },
        tags: [],
        retrievedAt: nowIso,
        cached: false,
        provenance: createProvenanceMetadata({
          evidenceType: 'ENRICHED',
          provider: 'VirusTotal v3',
          source: endpoint,
          status: 'error',
          reason: `HTTP ${response.status} ${response.statusText}`
        })
      };
    }

    const payload = await response.json();
    const attrs = payload?.data?.attributes || {};
    const stats: VirusTotalAnalysisStats = {
      malicious: Number(attrs.last_analysis_stats?.malicious || 0),
      suspicious: Number(attrs.last_analysis_stats?.suspicious || 0),
      harmless: Number(attrs.last_analysis_stats?.harmless || 0),
      undetected: Number(attrs.last_analysis_stats?.undetected || 0),
      timeout: Number(attrs.last_analysis_stats?.timeout || 0)
    };

    const positives = stats.malicious + stats.suspicious;
    const total = stats.malicious + stats.suspicious + stats.harmless + stats.undetected;
    const isMalicious = stats.malicious > 0;
    const isSuspicious = !isMalicious && stats.suspicious > 0;

    const categories = attrs.categories || {};
    const categoryName = Object.values(categories)[0] as string | undefined || (isMalicious ? 'Malicious Destination' : 'General Web Endpoint');

    const result: VirusTotalUrlResult = {
      url: normalized,
      urlId,
      lookupStatus: 'success',
      isConfigured: true,
      isMalicious,
      isSuspicious,
      positives,
      totalEngines: total || 88,
      scoreString: `${positives}/${total || 88} Engines${isMalicious ? ' (Malicious)' : ''}`,
      category: categoryName,
      reputation: attrs.reputation,
      lastAnalysisStats: stats,
      tags: Array.isArray(attrs.tags) ? attrs.tags : [],
      firstSubmissionDate: attrs.first_submission_date ? new Date(attrs.first_submission_date * 1000).toISOString() : undefined,
      lastAnalysisDate: attrs.last_analysis_date ? new Date(attrs.last_analysis_date * 1000).toISOString() : undefined,
      retrievedAt: nowIso,
      cached: false,
      provenance: createProvenanceMetadata({
        evidenceType: 'ENRICHED',
        provider: 'VirusTotal v3 Multi-Engine Gateway',
        source: endpoint,
        status: 'success'
      })
    };

    vtUrlLookupCache.set(normalized, result);
    return result;
  } catch (err: any) {
    console.warn(`[VirusTotal API v3] URL fetch exception for ${normalized}:`, err?.message);
    return {
      url: normalized,
      urlId,
      lookupStatus: 'unavailable',
      isConfigured: true,
      isMalicious: false,
      isSuspicious: false,
      positives: 0,
      totalEngines: 0,
      scoreString: 'VT Service Unavailable',
      category: 'Lookup Unavailable',
      lastAnalysisStats: { malicious: 0, suspicious: 0, harmless: 0, undetected: 0 },
      tags: [],
      retrievedAt: nowIso,
      cached: false,
      provenance: createProvenanceMetadata({
        evidenceType: 'ENRICHED',
        provider: 'VirusTotal v3',
        source: endpoint,
        status: 'unavailable',
        reason: err?.message || 'Network timeout / unreachable endpoint'
      })
    };
  }
}

/**
 * Real VirusTotal v3 File Hash Reputation Lookup (SHA256, SHA1, MD5)
 */
export async function lookupVirusTotalFileHash(
  hash: string,
  options?: { forceRefresh?: boolean }
): Promise<VirusTotalFileResult> {
  const normalizedHash = hash.trim().toLowerCase();
  const nowIso = new Date().toISOString();
  const apiKey = (process.env.VIRUSTOTAL_API_KEY || '').trim();

  let hashType: 'sha256' | 'sha1' | 'md5' | 'unknown' = 'unknown';
  if (/^[a-f0-9]{64}$/i.test(normalizedHash)) {
    hashType = 'sha256';
  } else if (/^[a-f0-9]{40}$/i.test(normalizedHash)) {
    hashType = 'sha1';
  } else if (/^[a-f0-9]{32}$/i.test(normalizedHash)) {
    hashType = 'md5';
  }

  // Check cache unless forceRefresh requested
  if (!options?.forceRefresh) {
    const cached = vtFileLookupCache.get(normalizedHash);
    if (cached) {
      return { ...cached, cached: true };
    }
  }

  // Handle Unconfigured API Key
  if (!isVirusTotalConfigured()) {
    const unconfiguredResult: VirusTotalFileResult = {
      hash: normalizedHash,
      hashType,
      lookupStatus: 'unavailable',
      isConfigured: false,
      isMalicious: false,
      isSuspicious: false,
      positives: 0,
      totalEngines: 0,
      scoreString: 'VT Inactive (No Key)',
      meaningfulName: 'Uninspected File (VT Unconfigured)',
      typeDescription: 'Unscanned Artifact',
      lastAnalysisStats: { malicious: 0, suspicious: 0, harmless: 0, undetected: 0 },
      tags: [],
      retrievedAt: nowIso,
      cached: false,
      provenance: createProvenanceMetadata({
        evidenceType: 'ENRICHED',
        provider: 'VirusTotal v3 Gateway',
        source: 'https://www.virustotal.com/api/v3/files',
        status: 'unavailable',
        reason: 'VIRUSTOTAL_API_KEY is not configured in server environment'
      })
    };
    return unconfiguredResult;
  }

  const endpoint = `https://www.virustotal.com/api/v3/files/${normalizedHash}`;

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 8000);

    const response = await fetch(endpoint, {
      method: 'GET',
      headers: {
        'x-apikey': apiKey,
        'Accept': 'application/json'
      },
      signal: controller.signal
    });
    clearTimeout(timeout);

    // 404: Not indexed yet in VirusTotal database
    if (response.status === 404) {
      const notFoundResult: VirusTotalFileResult = {
        hash: normalizedHash,
        hashType,
        lookupStatus: 'unavailable',
        isConfigured: true,
        isMalicious: false,
        isSuspicious: false,
        positives: 0,
        totalEngines: 0,
        scoreString: '0/0 (Unindexed Hash)',
        meaningfulName: 'Unindexed File Hash',
        typeDescription: 'Unrecognized Artifact',
        lastAnalysisStats: { malicious: 0, suspicious: 0, harmless: 0, undetected: 0 },
        tags: [],
        retrievedAt: nowIso,
        cached: false,
        provenance: createProvenanceMetadata({
          evidenceType: 'ENRICHED',
          provider: 'VirusTotal v3',
          source: endpoint,
          status: 'unavailable',
          reason: 'File hash not currently indexed in VirusTotal database'
        })
      };
      vtFileLookupCache.set(normalizedHash, notFoundResult, 5 * 60 * 1000);
      return notFoundResult;
    }

    if (response.status === 429) {
      return {
        hash: normalizedHash,
        hashType,
        lookupStatus: 'rate_limited',
        isConfigured: true,
        isMalicious: false,
        isSuspicious: false,
        positives: 0,
        totalEngines: 0,
        scoreString: 'Rate Limited',
        meaningfulName: 'Throttled Request',
        typeDescription: 'Rate Limited',
        lastAnalysisStats: { malicious: 0, suspicious: 0, harmless: 0, undetected: 0 },
        tags: [],
        retrievedAt: nowIso,
        cached: false,
        provenance: createProvenanceMetadata({
          evidenceType: 'ENRICHED',
          provider: 'VirusTotal v3',
          source: endpoint,
          status: 'rate_limited',
          reason: 'VirusTotal v3 API rate limit exceeded'
        })
      };
    }

    if (!response.ok) {
      console.warn(`[VirusTotal API v3] File hash lookup error (${response.status}): ${response.statusText}`);
      return {
        hash: normalizedHash,
        hashType,
        lookupStatus: 'error',
        isConfigured: true,
        isMalicious: false,
        isSuspicious: false,
        positives: 0,
        totalEngines: 0,
        scoreString: `Error (${response.status})`,
        meaningfulName: 'Lookup Failure',
        typeDescription: 'Error',
        lastAnalysisStats: { malicious: 0, suspicious: 0, harmless: 0, undetected: 0 },
        tags: [],
        retrievedAt: nowIso,
        cached: false,
        provenance: createProvenanceMetadata({
          evidenceType: 'ENRICHED',
          provider: 'VirusTotal v3',
          source: endpoint,
          status: 'error',
          reason: `HTTP ${response.status} ${response.statusText}`
        })
      };
    }

    const payload = await response.json();
    const attrs = payload?.data?.attributes || {};
    const stats: VirusTotalAnalysisStats = {
      malicious: Number(attrs.last_analysis_stats?.malicious || 0),
      suspicious: Number(attrs.last_analysis_stats?.suspicious || 0),
      harmless: Number(attrs.last_analysis_stats?.harmless || 0),
      undetected: Number(attrs.last_analysis_stats?.undetected || 0),
      timeout: Number(attrs.last_analysis_stats?.timeout || 0)
    };

    const positives = stats.malicious + stats.suspicious;
    const total = stats.malicious + stats.suspicious + stats.harmless + stats.undetected;
    const isMalicious = stats.malicious > 0;
    const isSuspicious = !isMalicious && stats.suspicious > 0;

    const result: VirusTotalFileResult = {
      hash: normalizedHash,
      hashType,
      lookupStatus: 'success',
      isConfigured: true,
      isMalicious,
      isSuspicious,
      positives,
      totalEngines: total || 72,
      scoreString: `${positives}/${total || 72} Engines${isMalicious ? ' (Malicious)' : ''}`,
      meaningfulName: attrs.meaningful_name || attrs.type_description || 'Binary File',
      typeDescription: attrs.type_description,
      sizeBytes: attrs.size,
      reputation: attrs.reputation,
      lastAnalysisStats: stats,
      tags: Array.isArray(attrs.tags) ? attrs.tags : [],
      firstSubmissionDate: attrs.first_submission_date ? new Date(attrs.first_submission_date * 1000).toISOString() : undefined,
      lastAnalysisDate: attrs.last_analysis_date ? new Date(attrs.last_analysis_date * 1000).toISOString() : undefined,
      retrievedAt: nowIso,
      cached: false,
      provenance: createProvenanceMetadata({
        evidenceType: 'ENRICHED',
        provider: 'VirusTotal v3 Multi-Engine Gateway',
        source: endpoint,
        status: 'success'
      })
    };

    vtFileLookupCache.set(normalizedHash, result);
    return result;
  } catch (err: any) {
    console.warn(`[VirusTotal API v3] File hash fetch exception for ${normalizedHash}:`, err?.message);
    return {
      hash: normalizedHash,
      hashType,
      lookupStatus: 'unavailable',
      isConfigured: true,
      isMalicious: false,
      isSuspicious: false,
      positives: 0,
      totalEngines: 0,
      scoreString: 'VT Service Unavailable',
      meaningfulName: 'Lookup Unavailable',
      typeDescription: 'Unavailable',
      lastAnalysisStats: { malicious: 0, suspicious: 0, harmless: 0, undetected: 0 },
      tags: [],
      retrievedAt: nowIso,
      cached: false,
      provenance: createProvenanceMetadata({
        evidenceType: 'ENRICHED',
        provider: 'VirusTotal v3',
        source: endpoint,
        status: 'unavailable',
        reason: err?.message || 'Network timeout / unreachable endpoint'
      })
    };
  }
}

/**
 * Main Composite VirusTotal Enrichment Service Handler
 */
export async function enrichWithVirusTotal(params: {
  urls?: any[];
  attachments?: any[];
  existingLogs?: any[];
}): Promise<VirusTotalEnrichmentResponse> {
  const isConfigured = isVirusTotalConfigured();
  const rawUrls = params.urls || [];
  const rawAttachments = params.attachments || [];
  const nowIso = new Date().toISOString();
  const statusInfo = getVirusTotalStatus();

  // If no API key configured, return explicit unconfigured state with zero fake verdicts
  if (!isConfigured) {
    const unconfLog = {
      id: `vt-unconf-${Date.now()}`,
      timestamp: nowIso,
      tag: 'VT_STATUS',
      message: 'VirusTotal API v3 is inactive (VIRUSTOTAL_API_KEY not configured in environment). Live IOC multi-engine scans are dormant.',
      highlight: false
    };

    return {
      status: 'unconfigured',
      vt_active: false,
      is_configured: false,
      message: 'VirusTotal API key (VIRUSTOTAL_API_KEY) is not configured in server environment. IOC live multi-engine queries are dormant.',
      scanned_count: 0,
      flagged_count: 0,
      api_status: {
        configured: false,
        provider: statusInfo.provider,
        endpoint: statusInfo.endpoint,
        message: statusInfo.message
      },
      urls: rawUrls.map(u => ({
        ...u,
        status: u.status === 'MALICIOUS' ? 'MALICIOUS' : (u.status || 'UNKNOWN'),
        virustotalScore: u.virustotalScore || 'VT Inactive (No Key)',
        category: u.category || 'Uninspected (VT Dormant)',
        vt_active: false,
        vt_status: 'unavailable'
      })),
      attachments: rawAttachments.map(a => ({
        ...a,
        status: a.status === 'MALICIOUS' ? 'MALICIOUS' : (a.status || 'UNKNOWN'),
        vtDetection: a.vtDetection || 'VT Inactive (No Key)',
        vt_active: false,
        vt_status: 'unavailable'
      })),
      logs: [...(params.existingLogs || []), unconfLog],
      new_vt_logs: [unconfLog]
    };
  }

  let scannedCount = 0;
  let flaggedCount = 0;
  const newLogs: Array<{ id: string; timestamp: string; tag: string; message: string; highlight?: boolean }> = [];

  // 1. Process URLs
  const enrichedUrls = await Promise.all(
    rawUrls.map(async (u) => {
      const urlStr = u.url || u.defangedUrl || '';
      if (!urlStr) return u;

      scannedCount++;
      const vtRes = await lookupVirusTotalUrl(urlStr);
      if (vtRes.lookupStatus === 'success') {
        if (vtRes.isMalicious || vtRes.isSuspicious) {
          flaggedCount++;
        }
        return {
          ...u,
          status: vtRes.isMalicious ? 'MALICIOUS' : (vtRes.isSuspicious ? 'SUSPICIOUS' : 'CLEAN'),
          virustotalScore: vtRes.scoreString,
          category: vtRes.category || u.category,
          positives: vtRes.positives,
          total_engines: vtRes.totalEngines,
          last_analysis_stats: vtRes.lastAnalysisStats,
          vt_active: true,
          vt_status: vtRes.lookupStatus
        };
      }

      return {
        ...u,
        status: u.status || 'UNKNOWN',
        virustotalScore: vtRes.scoreString || 'Lookup Unavailable',
        category: u.category || 'Unchecked Link',
        vt_active: true,
        vt_status: vtRes.lookupStatus
      };
    })
  );

  // 2. Process Attachments
  const enrichedAttachments = await Promise.all(
    rawAttachments.map(async (att) => {
      const hash = att.hash || att.sha256 || att.md5 || '';
      if (!hash) return att;

      scannedCount++;
      const vtRes = await lookupVirusTotalFileHash(hash);
      if (vtRes.lookupStatus === 'success') {
        if (vtRes.isMalicious || vtRes.isSuspicious) {
          flaggedCount++;
        }
        return {
          ...att,
          status: vtRes.isMalicious ? 'MALICIOUS' : (vtRes.isSuspicious ? 'SUSPICIOUS' : 'CLEAN'),
          vtDetection: vtRes.scoreString,
          positives: vtRes.positives,
          total_engines: vtRes.totalEngines,
          last_analysis_stats: vtRes.lastAnalysisStats,
          vt_active: true,
          vt_status: vtRes.lookupStatus
        };
      }

      return {
        ...att,
        status: att.status || 'UNKNOWN',
        vtDetection: vtRes.scoreString || 'Hash Lookup Unavailable',
        vt_active: true,
        vt_status: vtRes.lookupStatus
      };
    })
  );

  const scanLog = {
    id: `vt-res-${Date.now()}`,
    timestamp: nowIso,
    tag: 'VT_API',
    message: `VirusTotal v3 multi-engine query completed: ${scannedCount} artifact(s) evaluated, ${flaggedCount} flagged with positive detections.`,
    highlight: flaggedCount > 0
  };
  newLogs.push(scanLog);

  return {
    status: 'success',
    vt_active: true,
    is_configured: true,
    message: 'VirusTotal API v3 multi-engine query completed successfully.',
    scanned_count: scannedCount,
    flagged_count: flaggedCount,
    api_status: {
      configured: true,
      provider: statusInfo.provider,
      endpoint: statusInfo.endpoint,
      message: statusInfo.message
    },
    urls: enrichedUrls,
    attachments: enrichedAttachments,
    logs: [...(params.existingLogs || []), ...newLogs],
    new_vt_logs: newLogs
  };
}
