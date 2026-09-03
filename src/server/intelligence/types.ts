// TraceXMail Intelligence Layer Data Models and Contracts

export type IntelligenceLookupStatus =
  | 'success'
  | 'unavailable'
  | 'not_applicable'
  | 'rate_limited'
  | 'nxdomain'
  | 'servfail'
  | 'timeout'
  | 'error';

export type EvidenceProvenanceType =
  | 'OBSERVED'
  | 'ENRICHED'
  | 'MODEL'
  | 'INFERENCE';

export interface ProvenanceMetadata {
  evidenceType: EvidenceProvenanceType;
  provider: string;
  source: string;
  retrievedAt: string;
  cached: boolean;
  status: IntelligenceLookupStatus;
  reason?: string;
  limitation?: string;
  copyright?: string;
  license?: string;
}

export interface IpValidationResult {
  ip: string;
  isValid: boolean;
  isIpv4: boolean;
  isIpv6: boolean;
  isPublic: boolean;
  isPrivate: boolean;
  isRfc1918: boolean;
  isLoopback: boolean;
  isLinkLocal: boolean;
  isCarrierNat: boolean;
  isReserved: boolean;
  isMulticast: boolean;
  scope:
    | 'PRIVATE_RFC1918'
    | 'PRIVATE_LAN'
    | 'PUBLIC_ROUTABLE'
    | 'PUBLIC_INTERNET'
    | 'LOOPBACK_RFC1122'
    | 'LOOPBACK'
    | 'LINK_LOCAL_RFC3927'
    | 'LINK_LOCAL'
    | 'SHARED_CGNAT_RFC6598'
    | 'CARRIER_NAT'
    | 'RESERVED'
    | 'MULTICAST'
    | 'INVALID_SYNTAX'
    | 'UNMAPPED';
  subnetType: string;
  cidr: string;
  description: string;
  lookupStatus: 'valid' | 'not_applicable' | 'invalid';
  reason?: string;
}

export interface GeoIpResult {
  ip: string;
  isPublic: boolean;
  lookupStatus: IntelligenceLookupStatus;
  reason?: string;
  country: string | null;
  countryCode: string | null;
  region: string | null;
  city: string | null;
  postalCode: string | null;
  latitude: number | null;
  longitude: number | null;
  accuracyRadius: number | null;
  timeZone: string | null;
  isInEuropeanUnion: boolean | null;
  isAnonymousProxy?: boolean | null;
  isSatelliteProvider?: boolean | null;
  source: string;
  provider: string;
  lookupMethod: string;
  retrievedAt: string;
  cached: boolean;
  copyrightNotice?: string;
  licenseNotice?: string;
  provenance: ProvenanceMetadata;
}

export interface AsnResult {
  ip: string;
  isPublic: boolean;
  lookupStatus: IntelligenceLookupStatus;
  reason?: string;
  asn: string | null; // e.g., "AS200548"
  autonomousSystemNumber: number | null;
  autonomousSystemOrganization: string | null;
  isp: string | null;
  source: string;
  provider: string;
  retrievedAt: string;
  cached: boolean;
  provenance: ProvenanceMetadata;
}

export interface DnsMxRecord {
  priority: number;
  host: string;
}

export interface DnsResolutionResult {
  domain: string;
  lookupStatus: IntelligenceLookupStatus;
  reason?: string;
  a: string[];
  aaaa: string[];
  mx: DnsMxRecord[];
  ns: string[];
  txt: string[];
  cname: string[];
  spf?: {
    record: string | null;
    qualifier: string | null;
    isEnforced: boolean;
  };
  dmarc?: {
    record: string | null;
    policy: string | null;
    subdomainPolicy: string | null;
    pct: number | null;
  };
  retrievedAt: string;
  cached: boolean;
  provenance: ProvenanceMetadata;
}

export interface RdapResult {
  domain: string;
  lookupStatus: IntelligenceLookupStatus;
  reason?: string;
  handle: string | null;
  registrar: string | null;
  registrarIanaId: string | null;
  registeredDate: string | null;
  updatedDate: string | null;
  expirationDate: string | null;
  domainAgeDays: number | null;
  isNewlyRegistered: boolean;
  nameservers: string[];
  status: string[];
  retrievedAt: string;
  cached: boolean;
  provenance: ProvenanceMetadata;
}

export interface TyposquattingAnalysis {
  isTyposquat: boolean;
  targetBrand: string | null;
  distance: number;
  similarityScore: number;
  technique: string | null;
  reasons: string[];
}

export interface DomainIntelligenceResult {
  domain: string;
  status: IntelligenceLookupStatus;
  error?: string;
  retrievedAt: string;
  cached: boolean;
  dns: DnsResolutionResult;
  rdap: RdapResult;
  typosquatting: TyposquattingAnalysis;
  correlatedIps: Array<{
    ip: string;
    geo: GeoIpResult;
    asn: AsnResult;
  }>;
  provenance: ProvenanceMetadata;
}

export interface IpEnrichmentResult {
  ip: string;
  validation: IpValidationResult;
  geo: GeoIpResult;
  asn: AsnResult;
  reverseDns: {
    found: boolean;
    ptr: string | null;
    note: string;
  };
  threat: {
    lookupStatus: IntelligenceLookupStatus;
    abuseConfidenceScore: number | null;
    isTor: boolean;
    isProxyOrVpn: boolean;
    isBlacklisted: boolean;
    source: string;
    reason?: string;
  };
  provenance: ProvenanceMetadata;
}

export interface VirusTotalAnalysisStats {
  malicious: number;
  suspicious: number;
  harmless: number;
  undetected: number;
  timeout?: number;
}

export interface VirusTotalUrlResult {
  url: string;
  urlId: string;
  lookupStatus: IntelligenceLookupStatus;
  isConfigured: boolean;
  isMalicious: boolean;
  isSuspicious: boolean;
  positives: number;
  totalEngines: number;
  scoreString: string;
  category: string;
  reputation?: number;
  lastAnalysisStats: VirusTotalAnalysisStats;
  tags: string[];
  firstSubmissionDate?: string;
  lastAnalysisDate?: string;
  retrievedAt: string;
  cached: boolean;
  provenance: ProvenanceMetadata;
}

export interface VirusTotalFileResult {
  hash: string;
  hashType: 'sha256' | 'sha1' | 'md5' | 'unknown';
  lookupStatus: IntelligenceLookupStatus;
  isConfigured: boolean;
  isMalicious: boolean;
  isSuspicious: boolean;
  positives: number;
  totalEngines: number;
  scoreString: string;
  meaningfulName?: string;
  typeDescription?: string;
  sizeBytes?: number;
  reputation?: number;
  lastAnalysisStats: VirusTotalAnalysisStats;
  tags: string[];
  firstSubmissionDate?: string;
  lastAnalysisDate?: string;
  retrievedAt: string;
  cached: boolean;
  provenance: ProvenanceMetadata;
}
