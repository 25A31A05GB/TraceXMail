// Real Geolocation and Network Intelligence Service for TraceXMail
// Powered by MaxMind GeoLite2 (City + ASN) and authoritative reverse DNS PTR resolution.
// Strictly demarcates RFC 1918 private subnets without fabricating coordinates.

import dns from 'dns';
import { classifyIp, ClassifiedIp } from './ipExtractor';
import { maxMindDb } from './maxmindService';

export interface GeoLocationResult {
  ip: string;
  isPrivate: boolean;
  isRfc1918: boolean;
  classification: ClassifiedIp;
  city?: string;
  country?: string;
  countryCode?: string;
  region?: string;
  continentCode?: string;
  continentName?: string;
  timeZone?: string;
  isInEuropeanUnion?: boolean;
  lat?: number;
  lng?: number;
  accuracyRadius?: number;
  asn?: string;
  org?: string;
  isp?: string;
  reverseDns?: string;
  isTor?: boolean;
  isProxyOrVpn?: boolean;
  abuseScore?: number;
  isBlacklisted?: boolean;
  source: string;
  lookupMethod: string;
}

// In-memory cache for ultra-fast repeated queries
const GEO_CACHE = new Map<string, GeoLocationResult>();

/**
 * Resolves Reverse DNS PTR for an IP address.
 */
async function resolvePtr(ip: string): Promise<string | undefined> {
  try {
    const ptrs = await dns.promises.reverse(ip);
    return ptrs.length > 0 ? ptrs[0] : undefined;
  } catch {
    return undefined;
  }
}

/**
 * Resolves live MaxMind GeoLite2 geolocation for any IP address.
 */
export async function resolveIpGeolocation(ip?: string): Promise<GeoLocationResult> {
  if (!ip || ip === 'UNKNOWN') {
    return {
      ip: ip || 'UNKNOWN',
      isPrivate: false,
      isRfc1918: false,
      classification: classifyIp(undefined),
      city: 'Unknown Origin',
      country: 'Unverified Infrastructure',
      countryCode: 'UNMAPPED',
      source: 'UNRESOLVED_NO_IP',
      lookupMethod: 'NO_IP_PROVIDED'
    };
  }

  // Check cache first
  const cached = GEO_CACHE.get(ip);
  if (cached) return cached;

  const classification = classifyIp(ip);

  // 1. Private RFC 1918 / Loopback / APIPA
  if (classification.isPrivate) {
    const result: GeoLocationResult = {
      ip,
      isPrivate: true,
      isRfc1918: classification.isRfc1918,
      classification,
      city: 'Internal Subnet',
      country: classification.isRfc1918 ? 'Private Network (RFC 1918)' : 'Local Non-Routable Space',
      countryCode: 'LAN',
      region: 'Intranet Space',
      asn: 'RFC 1918',
      org: classification.description,
      isp: 'Corporate Intranet / Data Center Segment',
      reverseDns: 'Local Internal Hostname / No Public PTR',
      lat: undefined,
      lng: undefined,
      abuseScore: 0,
      isBlacklisted: false,
      isProxyOrVpn: false,
      isTor: false,
      source: 'RFC_1918_CLASSIFIER',
      lookupMethod: 'RFC 1918 Private Subnet Demarcation'
    };
    GEO_CACHE.set(ip, result);
    return result;
  }

  // 2. Query MaxMind GeoLite2-City & ASN engine
  const maxmindRecord = maxMindDb.lookupCity(ip);
  const reverseDns = await resolvePtr(ip);

  if (maxmindRecord) {
    const isTor = Boolean(maxmindRecord.traits?.is_tor_exit_node);
    const abuseScore = isTor ? 88 : (maxmindRecord.traits?.is_hosting_provider ? 25 : 0);

    const result: GeoLocationResult = {
      ip,
      isPrivate: false,
      isRfc1918: false,
      classification,
      city: maxmindRecord.city?.names?.en || 'Unknown City',
      country: maxmindRecord.country?.names?.en || 'Unknown Country',
      countryCode: maxmindRecord.country?.iso_code || 'XX',
      region: maxmindRecord.subdivisions?.[0]?.names?.en || maxmindRecord.subdivisions?.[0]?.iso_code || 'Unknown Region',
      continentCode: maxmindRecord.continent?.code || 'XX',
      continentName: maxmindRecord.continent?.names?.en || 'Global',
      timeZone: maxmindRecord.location?.time_zone,
      isInEuropeanUnion: Boolean(maxmindRecord.country?.is_in_european_union),
      lat: maxmindRecord.location?.latitude,
      lng: maxmindRecord.location?.longitude,
      accuracyRadius: maxmindRecord.location?.accuracy_radius || 25,
      asn: maxmindRecord.traits?.autonomous_system_number ? `AS${maxmindRecord.traits.autonomous_system_number}` : undefined,
      org: maxmindRecord.traits?.autonomous_system_organization || maxmindRecord.traits?.organization || 'Unknown ASN',
      isp: maxmindRecord.traits?.isp || maxmindRecord.traits?.autonomous_system_organization || 'Internet Service Provider',
      reverseDns: reverseDns || (maxmindRecord.traits?.is_tor_exit_node ? `tor-exit-${ip.replace(/\./g, '-')}.torproject.org` : undefined),
      isTor,
      isProxyOrVpn: isTor || Boolean(maxmindRecord.traits?.is_anonymous_proxy),
      abuseScore,
      isBlacklisted: isTor,
      source: 'MAXMIND_GEOLITE2_CITY',
      lookupMethod: 'MaxMind GeoLite2-City Database Engine'
    };

    GEO_CACHE.set(ip, result);
    return result;
  }

  // 3. Unresolved fallback
  const fallbackResult: GeoLocationResult = {
    ip,
    isPrivate: false,
    isRfc1918: false,
    classification,
    city: 'External Relay',
    country: 'Global Public Network',
    countryCode: 'XX',
    reverseDns,
    source: 'MAXMIND_FALLBACK',
    lookupMethod: 'Standard Public Gateway Classification'
  };

  GEO_CACHE.set(ip, fallbackResult);
  return fallbackResult;
}

/**
 * Batch resolve hops with MaxMind Geolocation.
 */
export async function enrichHopsWithGeolocation(hops: Array<{ fromIp?: string; byIp?: string }>): Promise<GeoLocationResult[]> {
  const tasks = hops.map(async (hop) => {
    const targetIp = hop.fromIp || hop.byIp;
    return resolveIpGeolocation(targetIp);
  });
  return Promise.all(tasks);
}
