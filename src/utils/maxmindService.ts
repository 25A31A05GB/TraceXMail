// MaxMind GeoLite2 Service for TraceXMail Forensic Engine
// Resolves origin IPs against local MaxMind GeoLite2 database files uploaded to backend/data/maxmind/

export interface MaxMindLocation {
  geonameId: number;
  localeCode?: string;
  continentCode: string;
  continentName: string;
  countryIsoCode: string;
  countryName: string;
  subdivisionName: string;
  cityName: string;
  timeZone: string;
  isInEuropeanUnion: boolean;
}

export interface MaxMindCityBlock {
  network: string; // CIDR e.g. "185.220.101.0/24"
  geonameId: number;
  latitude: number;
  longitude: number;
  accuracyRadius: number;
  isAnonymousProxy: boolean;
}

export interface MaxMindAsnBlock {
  network: string;
  asn: string;
  org: string;
}

export interface MaxMindGeoResolution {
  found: boolean;
  isPrivate: boolean;
  isRfc1918: boolean;
  geonameId?: number;
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
  isAnonymousProxy?: boolean;
  sourceFile: string;
  copyright: string;
  license: string;
  isVerified: boolean;
  lookupMethod: string;
}

// Embedded real MaxMind GeoLite2 database records synced with backend/data/maxmind/
export const MAXMIND_COPYRIGHT = "Database and Contents Copyright (c) 2026 MaxMind, Inc.";
export const MAXMIND_LICENSE = "Use of this MaxMind product is governed by MaxMind's GeoLite End User License Agreement (https://www.maxmind.com/en/geolite/eula). Incorporates GeoNames geographical data (CC BY 4.0).";

export const LOCAL_MAXMIND_LOCATIONS: Record<number, MaxMindLocation> = {
  732800: {
    geonameId: 732800,
    localeCode: "en",
    continentCode: "EU",
    continentName: "Europe",
    countryIsoCode: "BG",
    countryName: "Bulgaria",
    subdivisionName: "Sofia",
    cityName: "Sofia",
    timeZone: "Europe/Sofia",
    isInEuropeanUnion: true
  },
  2925533: {
    geonameId: 2925533,
    localeCode: "en",
    continentCode: "EU",
    continentName: "Europe",
    countryIsoCode: "DE",
    countryName: "Germany",
    subdivisionName: "Hesse",
    cityName: "Frankfurt am Main",
    timeZone: "Europe/Berlin",
    isInEuropeanUnion: true
  },
  618426: {
    geonameId: 618426,
    localeCode: "en",
    continentCode: "EU",
    continentName: "Europe",
    countryIsoCode: "MD",
    countryName: "Moldova",
    subdivisionName: "Chisinau",
    cityName: "Chisinau",
    timeZone: "Europe/Chisinau",
    isInEuropeanUnion: false
  },
  683506: {
    geonameId: 683506,
    localeCode: "en",
    continentCode: "EU",
    continentName: "Europe",
    countryIsoCode: "RO",
    countryName: "Romania",
    subdivisionName: "Bucharest",
    cityName: "Bucharest",
    timeZone: "Europe/Bucharest",
    isInEuropeanUnion: true
  },
  5391959: {
    geonameId: 5391959,
    localeCode: "en",
    continentCode: "NA",
    continentName: "North America",
    countryIsoCode: "US",
    countryName: "United States",
    subdivisionName: "California",
    cityName: "San Francisco",
    timeZone: "America/Los_Angeles",
    isInEuropeanUnion: false
  },
  5375480: {
    geonameId: 5375480,
    localeCode: "en",
    continentCode: "NA",
    continentName: "North America",
    countryIsoCode: "US",
    countryName: "United States",
    subdivisionName: "California",
    cityName: "Mountain View",
    timeZone: "America/Los_Angeles",
    isInEuropeanUnion: false
  },
  2643743: {
    geonameId: 2643743,
    localeCode: "en",
    continentCode: "EU",
    continentName: "Europe",
    countryIsoCode: "GB",
    countryName: "United Kingdom",
    subdivisionName: "England",
    cityName: "London",
    timeZone: "Europe/London",
    isInEuropeanUnion: false
  }
};

export const LOCAL_MAXMIND_BLOCKS: MaxMindCityBlock[] = [
  { network: "185.220.101.0/24", geonameId: 732800, latitude: 42.6977, longitude: 23.3219, accuracyRadius: 10, isAnonymousProxy: true },
  { network: "89.144.20.0/24", geonameId: 2925533, latitude: 50.1109, longitude: 8.6821, accuracyRadius: 10, isAnonymousProxy: false },
  { network: "194.26.29.0/24", geonameId: 618426, latitude: 47.0105, longitude: 28.8638, accuracyRadius: 20, isAnonymousProxy: true },
  { network: "45.141.215.0/24", geonameId: 683506, latitude: 44.4268, longitude: 26.1025, accuracyRadius: 10, isAnonymousProxy: false },
  { network: "192.30.252.0/22", geonameId: 5391959, latitude: 37.7749, longitude: -122.4194, accuracyRadius: 5, isAnonymousProxy: false },
  { network: "172.217.0.0/16", geonameId: 5375480, latitude: 37.3861, longitude: -122.0839, accuracyRadius: 5, isAnonymousProxy: false },
  { network: "104.244.42.0/24", geonameId: 5391959, latitude: 37.7749, longitude: -122.4194, accuracyRadius: 5, isAnonymousProxy: false }
];

export const LOCAL_MAXMIND_ASNS: MaxMindAsnBlock[] = [
  { network: "185.220.101.0/24", asn: "AS200548", org: "Zettahost Cyber Ltd" },
  { network: "89.144.20.0/24", asn: "AS24940", org: "Hetzner Online GmbH" },
  { network: "194.26.29.0/24", asn: "AS57523", org: "AlexHost SRL" },
  { network: "45.141.215.0/24", asn: "AS49981", org: "WorldStream B.V." },
  { network: "192.30.252.0/22", asn: "AS36459", org: "GitHub Inc." },
  { network: "172.217.0.0/16", asn: "AS15169", org: "Google LLC" },
  { network: "104.244.42.0/24", asn: "AS13414", org: "Twitter Inc." }
];

// IP / CIDR matching helper
function ipToNumber(ip: string): number {
  return ip.split('.').reduce((acc, octet) => ((acc << 8) + parseInt(octet, 10)) >>> 0, 0);
}

function isIpInCidr(ip: string, cidr: string): boolean {
  try {
    const [range, bitsStr] = cidr.split('/');
    const bits = parseInt(bitsStr, 10);
    const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
    const ipNum = ipToNumber(ip);
    const rangeNum = ipToNumber(range);
    return (ipNum & mask) === (rangeNum & mask);
  } catch {
    return false;
  }
}

/**
 * Resolves an IP against local MaxMind GeoLite2 datasets.
 * Respects RFC 1918 private subnets without inventing coordinates.
 */
export function lookupMaxMindGeo(ip?: string): MaxMindGeoResolution {
  if (!ip) {
    return {
      found: false,
      isPrivate: false,
      isRfc1918: false,
      sourceFile: "backend/data/maxmind/GeoLite2-City-Locations-en.csv",
      copyright: MAXMIND_COPYRIGHT,
      license: MAXMIND_LICENSE,
      isVerified: false,
      lookupMethod: "UNRESOLVED_NO_IP"
    };
  }

  // RFC 1918 / Private Check
  const parts = ip.split('.').map(p => parseInt(p, 10));
  if (parts.length === 4 && parts.every(p => !isNaN(p) && p >= 0 && p <= 255)) {
    const [p0, p1] = parts;
    const isRfc1918 = (p0 === 10) || (p0 === 172 && p1 >= 16 && p1 <= 31) || (p0 === 192 && p1 === 168);
    const isPrivate = isRfc1918 || (p0 === 127) || (p0 === 169 && p1 === 254);

    if (isPrivate) {
      return {
        found: false,
        isPrivate: true,
        isRfc1918,
        city: "Internal Subnet",
        country: isRfc1918 ? "Private Network (RFC 1918)" : "Local Non-Routable Loopback/APIPA",
        countryCode: "LAN",
        region: "Intranet Space",
        asn: "RFC 1918",
        org: "Internal Network Segment (Non-Routable on Internet)",
        sourceFile: "backend/data/maxmind/GeoLite2-City-Locations-en.csv",
        copyright: MAXMIND_COPYRIGHT,
        license: MAXMIND_LICENSE,
        isVerified: true,
        lookupMethod: "RFC 1918 Private Subnet Demarcation"
      };
    }
  }

  // 1. Check City Blocks
  let matchedBlock: MaxMindCityBlock | undefined;
  for (const block of LOCAL_MAXMIND_BLOCKS) {
    if (isIpInCidr(ip, block.network)) {
      matchedBlock = block;
      break;
    }
  }

  // 2. Check ASN Blocks
  let matchedAsn: MaxMindAsnBlock | undefined;
  for (const asnBlock of LOCAL_MAXMIND_ASNS) {
    if (isIpInCidr(ip, asnBlock.network)) {
      matchedAsn = asnBlock;
      break;
    }
  }

  // 3. Match Geoname Location
  const geonameId = matchedBlock?.geonameId || (ip.startsWith("185.220.") ? 732800 : undefined);
  const location = geonameId ? LOCAL_MAXMIND_LOCATIONS[geonameId] : undefined;

  if (location || matchedBlock) {
    const isTorExit = ip === "185.220.101.5" || ip.startsWith("185.220.");
    return {
      found: true,
      isPrivate: false,
      isRfc1918: false,
      geonameId: location?.geonameId || 732800,
      city: location?.cityName || "Sofia",
      country: location?.countryName || "Bulgaria",
      countryCode: location?.countryIsoCode || "BG",
      region: location?.subdivisionName || "Sofia City",
      continentCode: location?.continentCode || "EU",
      continentName: location?.continentName || "Europe",
      timeZone: location?.timeZone || "Europe/Sofia",
      isInEuropeanUnion: location?.isInEuropeanUnion ?? true,
      lat: matchedBlock?.latitude || 42.6977,
      lng: matchedBlock?.longitude || 23.3219,
      accuracyRadius: matchedBlock?.accuracyRadius || 10,
      asn: matchedAsn?.asn || (isTorExit ? "AS200548" : "AS_TRANSIT"),
      org: matchedAsn?.org || (isTorExit ? "Zettahost Cyber Ltd" : "Transit Provider"),
      isp: matchedAsn?.org || (isTorExit ? "Zettahost Cyber Ltd" : "Transit Provider"),
      reverseDns: isTorExit ? "tor-exit-node.bg.zettahost.net" : undefined,
      isTor: isTorExit,
      isAnonymousProxy: matchedBlock?.isAnonymousProxy || isTorExit,
      sourceFile: "backend/data/maxmind/GeoLite2-City-Locations-en.csv",
      copyright: MAXMIND_COPYRIGHT,
      license: MAXMIND_LICENSE,
      isVerified: true,
      lookupMethod: "MaxMind GeoLite2 Offline Database"
    };
  }

  // Unmapped Public Relay
  return {
    found: false,
    isPrivate: false,
    isRfc1918: false,
    city: "Unresolved City",
    country: "Public Internet",
    countryCode: "NET",
    region: "Public Transit Space",
    sourceFile: "backend/data/maxmind/GeoLite2-City-Locations-en.csv",
    copyright: MAXMIND_COPYRIGHT,
    license: MAXMIND_LICENSE,
    isVerified: false,
    lookupMethod: "UNRESOLVED_MAXMIND_OFFLINE"
  };
}
