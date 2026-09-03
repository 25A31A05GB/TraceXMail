import dns from 'dns';
import { dnsCache } from './cache';
import { createProvenanceMetadata } from './provenance';
import { DnsResolutionResult, IntelligenceLookupStatus } from './types';

const dnsPromises = dns.promises;

// Timeout wrapper for DNS queries
async function withTimeout<T>(promise: Promise<T>, timeoutMs: number = 4000, fallbackVal: T): Promise<T> {
  let timer: NodeJS.Timeout;
  const timeoutPromise = new Promise<T>((resolve) => {
    timer = setTimeout(() => resolve(fallbackVal), timeoutMs);
  });
  return Promise.race([
    promise.then((res) => {
      clearTimeout(timer);
      return res;
    }).catch(() => {
      clearTimeout(timer);
      return fallbackVal;
    }),
    timeoutPromise
  ]);
}

export async function resolveDns(domain: string): Promise<DnsResolutionResult> {
  const cleanDomain = domain.toLowerCase().trim().replace(/^\.+|\.+$/g, '');

  if (!cleanDomain || cleanDomain.includes('/') || cleanDomain.includes(' ')) {
    return {
      domain: cleanDomain,
      lookupStatus: 'unavailable',
      reason: 'invalid_domain_format',
      a: [],
      aaaa: [],
      mx: [],
      ns: [],
      txt: [],
      cname: [],
      retrievedAt: new Date().toISOString(),
      cached: false,
      provenance: createProvenanceMetadata({
        evidenceType: 'OBSERVED',
        provider: 'System DNS Resolver',
        source: 'dns.promises',
        status: 'unavailable',
        reason: 'Malformed domain string'
      })
    };
  }

  const cacheKey = `dns:${cleanDomain}`;
  const cached = dnsCache.get(cacheKey);
  if (cached) {
    return { ...cached, cached: true };
  }

  return dnsCache.getOrFetch(cacheKey, async () => {
    return await executeDnsLookup(cleanDomain);
  }).then(r => r.value);
}

async function executeDnsLookup(domain: string): Promise<DnsResolutionResult> {
  const now = new Date().toISOString();

  // Concurrent DNS record resolutions with timeout
  const [aRecords, aaaaRecords, mxRecords, nsRecords, txtRecords, dmarcRecords] = await Promise.all([
    withTimeout(dnsPromises.resolve4(domain).catch(() => []), 3500, []),
    withTimeout(dnsPromises.resolve6(domain).catch(() => []), 3500, []),
    withTimeout(dnsPromises.resolveMx(domain).catch(() => []), 3500, []),
    withTimeout(dnsPromises.resolveNs(domain).catch(() => []), 3500, []),
    withTimeout(dnsPromises.resolveTxt(domain).catch(() => []), 3500, []),
    withTimeout(dnsPromises.resolveTxt(`_dmarc.${domain}`).catch(() => []), 3500, [])
  ]);

  const flattenedTxt = txtRecords.map(chunk => (Array.isArray(chunk) ? chunk.join('') : chunk));
  const flattenedDmarc = dmarcRecords.map(chunk => (Array.isArray(chunk) ? chunk.join('') : chunk));

  // Determine lookup status based on whether domain resolved
  let lookupStatus: IntelligenceLookupStatus = 'success';
  let reason: string | undefined = undefined;

  const totalRecords = aRecords.length + aaaaRecords.length + mxRecords.length + nsRecords.length + flattenedTxt.length;

  if (totalRecords === 0) {
    // Attempt single SOA or base check to differentiate NXDOMAIN from timeout
    try {
      await dnsPromises.resolveSoa(domain);
      lookupStatus = 'success'; // Exists in DNS zone even if no A/MX
    } catch (soaErr: any) {
      if (soaErr.code === 'ENOTFOUND' || soaErr.code === 'ENODATA') {
        lookupStatus = 'nxdomain';
        reason = 'Domain does not exist in authoritative DNS (NXDOMAIN)';
      } else if (soaErr.code === 'ETIMEOUT') {
        lookupStatus = 'timeout';
        reason = 'DNS query timed out';
      } else if (soaErr.code === 'SERVFAIL') {
        lookupStatus = 'servfail';
        reason = 'Authoritative nameserver returned SERVFAIL';
      } else {
        lookupStatus = 'unavailable';
        reason = soaErr.message || 'DNS resolution failed';
      }
    }
  }

  // Parse SPF
  const spfRecord = flattenedTxt.find(t => t.toLowerCase().startsWith('v=spf1')) || null;
  let spfQualifier: string | null = null;
  let isSpfEnforced = false;
  if (spfRecord) {
    if (spfRecord.includes('-all')) {
      spfQualifier = 'HardFail (-all)';
      isSpfEnforced = true;
    } else if (spfRecord.includes('~all')) {
      spfQualifier = 'SoftFail (~all)';
      isSpfEnforced = false;
    } else if (spfRecord.includes('?all')) {
      spfQualifier = 'Neutral (?all)';
      isSpfEnforced = false;
    } else if (spfRecord.includes('+all')) {
      spfQualifier = 'Pass (+all)';
      isSpfEnforced = false;
    }
  }

  // Parse DMARC
  const dmarcRecord = flattenedDmarc.find(t => t.toLowerCase().startsWith('v=dmarc1')) || null;
  let dmarcPolicy: string | null = null;
  let dmarcSubdomainPolicy: string | null = null;
  let dmarcPct: number | null = null;

  if (dmarcRecord) {
    const pMatch = dmarcRecord.match(/p=([a-zA-Z]+)/i);
    if (pMatch) dmarcPolicy = pMatch[1].toLowerCase();

    const spMatch = dmarcRecord.match(/sp=([a-zA-Z]+)/i);
    if (spMatch) dmarcSubdomainPolicy = spMatch[1].toLowerCase();

    const pctMatch = dmarcRecord.match(/pct=(\d+)/i);
    if (pctMatch) dmarcPct = parseInt(pctMatch[1], 10);
  }

  const formattedMx = (mxRecords || []).map(m => ({
    priority: m.priority,
    host: m.exchange
  })).sort((a, b) => a.priority - b.priority);

  return {
    domain,
    lookupStatus,
    reason,
    a: aRecords || [],
    aaaa: aaaaRecords || [],
    mx: formattedMx,
    ns: nsRecords || [],
    txt: flattenedTxt,
    cname: [],
    spf: spfRecord ? {
      record: spfRecord,
      qualifier: spfQualifier,
      isEnforced: isSpfEnforced
    } : undefined,
    dmarc: dmarcRecord ? {
      record: dmarcRecord,
      policy: dmarcPolicy,
      subdomainPolicy: dmarcSubdomainPolicy,
      pct: dmarcPct
    } : undefined,
    retrievedAt: now,
    cached: false,
    provenance: createProvenanceMetadata({
      evidenceType: 'ENRICHED',
      provider: 'Authoritative DNS',
      source: 'Node.js dns.promises',
      status: lookupStatus,
      reason,
      limitation: 'Reflects authoritative DNS records at query time; subject to TTL propagation delays'
    })
  };
}
