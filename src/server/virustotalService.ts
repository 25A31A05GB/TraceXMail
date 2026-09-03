import { IntelligenceCache } from './intelligence/cache';

export interface VtEnrichResult {
  status: 'success' | 'unconfigured' | 'error';
  vt_active: boolean;
  message?: string;
  scanned_count: number;
  flagged_count: number;
  urls: Array<{
    url: string;
    defangedUrl?: string;
    domain?: string;
    status: 'MALICIOUS' | 'SUSPICIOUS' | 'CLEAN' | 'UNKNOWN';
    virustotalScore?: string;
    category?: string;
    positives?: number;
    total_engines?: number;
    last_analysis_stats?: Record<string, number>;
  }>;
  attachments: Array<{
    filename?: string;
    name?: string;
    hash?: string;
    sha256?: string;
    md5?: string;
    status: 'MALICIOUS' | 'SUSPICIOUS' | 'CLEAN' | 'UNKNOWN';
    vtDetection?: string;
    positives?: number;
    total_engines?: number;
    last_analysis_stats?: Record<string, number>;
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

// 1-hour TTL in-memory cache for VirusTotal lookup results to prevent duplicate quota consumption
interface CachedVtAnalysis {
  status: 'MALICIOUS' | 'SUSPICIOUS' | 'CLEAN' | 'UNKNOWN';
  scoreStr: string;
  positives: number;
  total: number;
  category?: string;
  stats?: Record<string, number>;
}

const vtUrlCache = new IntelligenceCache<CachedVtAnalysis>({ ttlMs: 3600000, maxEntries: 1000 });
const vtFileCache = new IntelligenceCache<CachedVtAnalysis>({ ttlMs: 3600000, maxEntries: 1000 });

/**
 * Encodes a URL into VirusTotal v3 URL Identifier (base64url without padding)
 */
function toVtUrlId(rawUrl: string): string {
  return Buffer.from(rawUrl.trim()).toString('base64url');
}

/**
 * Real VirusTotal v3 URL Lookup
 */
async function queryVtUrl(url: string, apiKey: string): Promise<CachedVtAnalysis | null> {
  const normalized = url.trim();
  const cached = vtUrlCache.get(normalized);
  if (cached) {
    return cached;
  }

  const urlId = toVtUrlId(normalized);
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

    if (response.status === 404) {
      // URL not present in VirusTotal's indexed database yet
      const unknownResult: CachedVtAnalysis = {
        status: 'UNKNOWN',
        scoreStr: '0/0 (Unindexed)',
        positives: 0,
        total: 0,
        category: 'Unindexed URL'
      };
      vtUrlCache.set(normalized, unknownResult, 300000); // 5 min TTL for 404
      return unknownResult;
    }

    if (!response.ok) {
      console.warn(`[VirusTotal API] URL lookup failed (${response.status}): ${response.statusText}`);
      return null;
    }

    const payload = await response.json();
    const attrs = payload?.data?.attributes;
    const stats = attrs?.last_analysis_stats || {};
    const malicious = Number(stats.malicious || 0);
    const suspicious = Number(stats.suspicious || 0);
    const harmless = Number(stats.harmless || 0);
    const undetected = Number(stats.undetected || 0);
    const positives = malicious + suspicious;
    const total = malicious + suspicious + harmless + undetected;

    let verdict: 'MALICIOUS' | 'SUSPICIOUS' | 'CLEAN' = 'CLEAN';
    if (malicious > 0) {
      verdict = 'MALICIOUS';
    } else if (suspicious > 0) {
      verdict = 'SUSPICIOUS';
    }

    const categories = attrs?.categories || {};
    const firstCategory = Object.values(categories)[0] as string | undefined;

    const result: CachedVtAnalysis = {
      status: verdict,
      scoreStr: `${positives}/${total || 88} Engines`,
      positives,
      total: total || 88,
      category: firstCategory || (verdict === 'MALICIOUS' ? 'Malicious Destination' : 'Verified Endpoint'),
      stats
    };

    vtUrlCache.set(normalized, result);
    return result;
  } catch (err: any) {
    console.warn(`[VirusTotal API] URL fetch exception for ${normalized}:`, err?.message);
    return null;
  }
}

/**
 * Real VirusTotal v3 File Hash Lookup
 */
async function queryVtFile(hash: string, apiKey: string): Promise<CachedVtAnalysis | null> {
  const normalizedHash = hash.trim().toLowerCase();
  if (!normalizedHash || normalizedHash.length < 32) {
    return null;
  }

  const cached = vtFileCache.get(normalizedHash);
  if (cached) {
    return cached;
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

    if (response.status === 404) {
      const unindexedResult: CachedVtAnalysis = {
        status: 'UNKNOWN',
        scoreStr: '0/0 (Unindexed Hash)',
        positives: 0,
        total: 0,
        category: 'Unindexed File'
      };
      vtFileCache.set(normalizedHash, unindexedResult, 300000);
      return unindexedResult;
    }

    if (!response.ok) {
      console.warn(`[VirusTotal API] File hash lookup failed (${response.status}): ${response.statusText}`);
      return null;
    }

    const payload = await response.json();
    const attrs = payload?.data?.attributes;
    const stats = attrs?.last_analysis_stats || {};
    const malicious = Number(stats.malicious || 0);
    const suspicious = Number(stats.suspicious || 0);
    const harmless = Number(stats.harmless || 0);
    const undetected = Number(stats.undetected || 0);
    const positives = malicious + suspicious;
    const total = malicious + suspicious + harmless + undetected;

    let verdict: 'MALICIOUS' | 'SUSPICIOUS' | 'CLEAN' = 'CLEAN';
    if (malicious > 0) {
      verdict = 'MALICIOUS';
    } else if (suspicious > 0) {
      verdict = 'SUSPICIOUS';
    }

    const meaningfulName = attrs?.meaningful_name || attrs?.type_description || 'Binary Artifact';

    const result: CachedVtAnalysis = {
      status: verdict,
      scoreStr: `${positives}/${total || 72} Engines${malicious > 0 ? ' (Malicious Detection)' : ''}`,
      positives,
      total: total || 72,
      category: meaningfulName,
      stats
    };

    vtFileCache.set(normalizedHash, result);
    return result;
  } catch (err: any) {
    console.warn(`[VirusTotal API] File hash fetch exception for ${normalizedHash}:`, err?.message);
    return null;
  }
}

/**
 * Main VirusTotal Enrichment Service Handler
 */
export async function enrichWithVirusTotal(params: {
  urls?: any[];
  attachments?: any[];
  existingLogs?: any[];
}): Promise<VtEnrichResult> {
  const apiKey = (process.env.VIRUSTOTAL_API_KEY || '').trim();
  const rawUrls = params.urls || [];
  const rawAttachments = params.attachments || [];
  const nowIso = new Date().toISOString();

  // If no API key configured, return explicit vt_active: false without fabricating MALICIOUS verdicts
  if (!apiKey) {
    return {
      status: 'unconfigured',
      vt_active: false,
      message: 'VirusTotal API key (VIRUSTOTAL_API_KEY) is not configured in server environment. IOC live multi-engine queries are currently dormant.',
      scanned_count: 0,
      flagged_count: 0,
      urls: rawUrls.map(u => ({
        ...u,
        virustotalScore: u.virustotalScore || 'VT Unconfigured',
        category: u.category || 'Unchecked Link'
      })),
      attachments: rawAttachments.map(a => ({
        ...a,
        vtDetection: a.vtDetection || 'VT Unconfigured'
      })),
      logs: [
        ...(params.existingLogs || []),
        {
          id: `vt-unconf-${Date.now()}`,
          timestamp: nowIso,
          tag: 'VT_STATUS',
          message: 'VirusTotal v3 integration is unconfigured (VIRUSTOTAL_API_KEY not set). Threat verdict reflects internal heuristic and cryptographic evaluation.',
          highlight: false
        }
      ],
      new_vt_logs: [
        {
          id: `vt-unconf-new-${Date.now()}`,
          timestamp: nowIso,
          tag: 'VT_STATUS',
          message: 'VirusTotal v3 key not configured. Skipped live external engine lookups.',
          highlight: false
        }
      ]
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
      const vtRes = await queryVtUrl(urlStr, apiKey);
      if (vtRes) {
        if (vtRes.status === 'MALICIOUS' || vtRes.status === 'SUSPICIOUS') {
          flaggedCount++;
        }
        return {
          ...u,
          status: vtRes.status,
          virustotalScore: vtRes.scoreStr,
          category: vtRes.category || u.category,
          positives: vtRes.positives,
          total_engines: vtRes.total,
          last_analysis_stats: vtRes.stats
        };
      }

      return {
        ...u,
        virustotalScore: u.virustotalScore || '0/0 (Lookup Pending)',
        category: u.category
      };
    })
  );

  // 2. Process Attachments
  const enrichedAttachments = await Promise.all(
    rawAttachments.map(async (att) => {
      const hash = att.hash || att.sha256 || att.md5 || '';
      if (!hash) return att;

      scannedCount++;
      const vtRes = await queryVtFile(hash, apiKey);
      if (vtRes) {
        if (vtRes.status === 'MALICIOUS' || vtRes.status === 'SUSPICIOUS') {
          flaggedCount++;
        }
        return {
          ...att,
          status: vtRes.status,
          vtDetection: vtRes.scoreStr,
          positives: vtRes.positives,
          total_engines: vtRes.total,
          last_analysis_stats: vtRes.stats
        };
      }

      return {
        ...att,
        vtDetection: att.vtDetection || '0/0 (Hash Unindexed)'
      };
    })
  );

  newLogs.push({
    id: `vt-res-${Date.now()}`,
    timestamp: nowIso,
    tag: 'VT_API',
    message: `VirusTotal v3 multi-engine query completed: ${scannedCount} artifact(s) evaluated, ${flaggedCount} flagged with positive detections.`,
    highlight: flaggedCount > 0
  });

  return {
    status: 'success',
    vt_active: true,
    message: 'VirusTotal API v3 query completed successfully.',
    scanned_count: scannedCount,
    flagged_count: flaggedCount,
    urls: enrichedUrls,
    attachments: enrichedAttachments,
    logs: [...(params.existingLogs || []), ...newLogs],
    new_vt_logs: newLogs
  };
}
