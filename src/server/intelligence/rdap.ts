import axios from 'axios';
import { rdapCache } from './cache';
import { createProvenanceMetadata } from './provenance';
import { IntelligenceLookupStatus, RdapResult } from './types';

export async function resolveRdap(domain: string): Promise<RdapResult> {
  const cleanDomain = domain.toLowerCase().trim().replace(/^\.+|\.+$/g, '');

  if (!cleanDomain || cleanDomain.includes('/') || cleanDomain.includes(' ')) {
    return {
      domain: cleanDomain,
      lookupStatus: 'unavailable',
      reason: 'invalid_domain_format',
      handle: null,
      registrar: null,
      registrarIanaId: null,
      registeredDate: null,
      updatedDate: null,
      expirationDate: null,
      domainAgeDays: null,
      isNewlyRegistered: false,
      nameservers: [],
      status: [],
      retrievedAt: new Date().toISOString(),
      cached: false,
      provenance: createProvenanceMetadata({
        evidenceType: 'ENRICHED',
        provider: 'ICANN RDAP',
        source: 'rdap.org',
        status: 'unavailable',
        reason: 'Invalid domain syntax'
      })
    };
  }

  const cacheKey = `rdap:${cleanDomain}`;
  const cached = rdapCache.get(cacheKey);
  if (cached) {
    return { ...cached, cached: true };
  }

  return rdapCache.getOrFetch(cacheKey, async () => {
    return await executeRdapLookup(cleanDomain);
  }).then(r => r.value);
}

async function executeRdapLookup(domain: string): Promise<RdapResult> {
  const now = new Date().toISOString();

  // Try official RDAP aggregators with strict 4500ms timeout
  const rdapUrls = [
    `https://rdap.org/domain/${domain}`,
    `https://rdap.verisign.com/com/v1/domain/${domain}`
  ];

  let rawData: any = null;
  let lastError: string | null = null;

  for (const url of rdapUrls) {
    try {
      const resp = await axios.get(url, {
        timeout: 4500,
        headers: {
          'Accept': 'application/rdap+json, application/json',
          'User-Agent': 'TraceXMail-Forensic-Auditor/1.0'
        },
        maxRedirects: 3
      });
      if (resp.data && (resp.data.ldhName || resp.data.handle || resp.data.events)) {
        rawData = resp.data;
        break;
      }
    } catch (err: any) {
      lastError = err.response?.status === 404 ? 'Domain not found in registry (404)' : err.message;
      if (err.response?.status === 404) break; // Domain genuinely not registered
    }
  }

  if (!rawData) {
    const is404 = lastError?.includes('404');
    const status: IntelligenceLookupStatus = is404 ? 'nxdomain' : 'unavailable';

    return {
      domain,
      lookupStatus: status,
      reason: lastError || 'RDAP service unreachable or unregistered',
      handle: null,
      registrar: null,
      registrarIanaId: null,
      registeredDate: null,
      updatedDate: null,
      expirationDate: null,
      domainAgeDays: null,
      isNewlyRegistered: false,
      nameservers: [],
      status: [],
      retrievedAt: now,
      cached: false,
      provenance: createProvenanceMetadata({
        evidenceType: 'ENRICHED',
        provider: 'ICANN RDAP',
        source: 'rdap.org',
        status,
        reason: lastError || 'RDAP query failed',
        limitation: 'Some ccTLD registries do not publish public RDAP endpoints'
      })
    };
  }

  // Parse Events
  let registeredDate: string | null = null;
  let updatedDate: string | null = null;
  let expirationDate: string | null = null;

  if (Array.isArray(rawData.events)) {
    for (const ev of rawData.events) {
      if (ev.eventAction === 'registration') {
        registeredDate = ev.eventDate || null;
      } else if (ev.eventAction === 'last changed' || ev.eventAction === 'last update') {
        updatedDate = ev.eventDate || null;
      } else if (ev.eventAction === 'expiration') {
        expirationDate = ev.eventDate || null;
      }
    }
  }

  // Calculate domain age in days
  let domainAgeDays: number | null = null;
  let isNewlyRegistered = false;
  if (registeredDate) {
    const createdTimestamp = new Date(registeredDate).getTime();
    if (!isNaN(createdTimestamp)) {
      domainAgeDays = Math.max(0, Math.floor((Date.now() - createdTimestamp) / (1000 * 60 * 60 * 24)));
      isNewlyRegistered = domainAgeDays <= 30;
    }
  }

  // Parse Registrar Entity
  let registrarName: string | null = null;
  let registrarIanaId: string | null = null;

  if (Array.isArray(rawData.entities)) {
    const registrarEntity = rawData.entities.find((e: any) =>
      Array.isArray(e.roles) && e.roles.includes('registrar')
    );
    if (registrarEntity) {
      if (registrarEntity.vcardArray && Array.isArray(registrarEntity.vcardArray[1])) {
        const fnEntry = registrarEntity.vcardArray[1].find((prop: any) => prop[0] === 'fn');
        if (fnEntry && typeof fnEntry[3] === 'string') {
          registrarName = fnEntry[3].trim();
        }
      }
      if (!registrarName && registrarEntity.handle) {
        registrarName = registrarEntity.handle;
      }
      if (Array.isArray(registrarEntity.publicIds)) {
        const ianaId = registrarEntity.publicIds.find((id: any) => id.type === 'IANA Registrar ID');
        if (ianaId) registrarIanaId = String(ianaId.identifier);
      }
    }
  }

  // Parse Nameservers
  const nameservers: string[] = [];
  if (Array.isArray(rawData.nameservers)) {
    for (const ns of rawData.nameservers) {
      if (ns.ldhName) nameservers.push(ns.ldhName.toLowerCase());
    }
  }

  const statusList = Array.isArray(rawData.status) ? rawData.status : [];

  return {
    domain,
    lookupStatus: 'success',
    handle: rawData.handle || null,
    registrar: registrarName,
    registrarIanaId,
    registeredDate,
    updatedDate,
    expirationDate,
    domainAgeDays,
    isNewlyRegistered,
    nameservers,
    status: statusList,
    retrievedAt: now,
    cached: false,
    provenance: createProvenanceMetadata({
      evidenceType: 'ENRICHED',
      provider: 'ICANN RDAP Protocol (RFC 7480)',
      source: 'Authoritative TLD Registry',
      status: 'success',
      limitation: 'Registrant identity fields may be redacted pursuant to ICANN Registration Data Policy / GDPR'
    })
  };
}
