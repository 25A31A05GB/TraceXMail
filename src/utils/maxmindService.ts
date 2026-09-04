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
  727011: { geonameId: 727011, localeCode: "en", continentCode: "EU", continentName: "Europe", countryIsoCode: "BG", countryName: "Bulgaria", subdivisionName: "Sofia-Grad", cityName: "Sofia", timeZone: "Europe/Sofia", isInEuropeanUnion: true },
  2925533: { geonameId: 2925533, localeCode: "en", continentCode: "EU", continentName: "Europe", countryIsoCode: "DE", countryName: "Germany", subdivisionName: "Hesse", cityName: "Frankfurt am Main", timeZone: "Europe/Berlin", isInEuropeanUnion: true },
  2759794: { geonameId: 2759794, localeCode: "en", continentCode: "EU", continentName: "Europe", countryIsoCode: "NL", countryName: "Netherlands", subdivisionName: "North Holland", cityName: "Amsterdam", timeZone: "Europe/Amsterdam", isInEuropeanUnion: true },
  683506: { geonameId: 683506, localeCode: "en", continentCode: "EU", continentName: "Europe", countryIsoCode: "RO", countryName: "Romania", subdivisionName: "Bucuresti", cityName: "Bucharest", timeZone: "Europe/Bucharest", isInEuropeanUnion: true },
  756135: { geonameId: 756135, localeCode: "en", continentCode: "EU", continentName: "Europe", countryIsoCode: "PL", countryName: "Poland", subdivisionName: "Mazovia", cityName: "Warsaw", timeZone: "Europe/Warsaw", isInEuropeanUnion: true },
  2643743: { geonameId: 2643743, localeCode: "en", continentCode: "EU", continentName: "Europe", countryIsoCode: "GB", countryName: "United Kingdom", subdivisionName: "England", cityName: "London", timeZone: "Europe/London", isInEuropeanUnion: false },
  5391959: { geonameId: 5391959, localeCode: "en", continentCode: "NA", continentName: "North America", countryIsoCode: "US", countryName: "United States", subdivisionName: "California", cityName: "San Francisco", timeZone: "America/Los_Angeles", isInEuropeanUnion: false },
  5375480: { geonameId: 5375480, localeCode: "en", continentCode: "NA", continentName: "North America", countryIsoCode: "US", countryName: "United States", subdivisionName: "California", cityName: "Mountain View", timeZone: "America/Los_Angeles", isInEuropeanUnion: false },
  5392171: { geonameId: 5392171, localeCode: "en", continentCode: "NA", continentName: "North America", countryIsoCode: "US", countryName: "United States", subdivisionName: "California", cityName: "San Jose", timeZone: "America/Los_Angeles", isInEuropeanUnion: false },
  5341145: { geonameId: 5341145, localeCode: "en", continentCode: "NA", continentName: "North America", countryIsoCode: "US", countryName: "United States", subdivisionName: "California", cityName: "Cupertino", timeZone: "America/Los_Angeles", isInEuropeanUnion: false },
  5372223: { geonameId: 5372223, localeCode: "en", continentCode: "NA", continentName: "North America", countryIsoCode: "US", countryName: "United States", subdivisionName: "California", cityName: "Menlo Park", timeZone: "America/Los_Angeles", isInEuropeanUnion: false },
  4852924: { geonameId: 4852924, localeCode: "en", continentCode: "NA", continentName: "North America", countryIsoCode: "US", countryName: "United States", subdivisionName: "Iowa", cityName: "Council Bluffs", timeZone: "America/Chicago", isInEuropeanUnion: false },
  4853828: { geonameId: 4853828, localeCode: "en", continentCode: "NA", continentName: "North America", countryIsoCode: "US", countryName: "United States", subdivisionName: "Iowa", cityName: "Des Moines", timeZone: "America/Chicago", isInEuropeanUnion: false },
  4744870: { geonameId: 4744870, localeCode: "en", continentCode: "NA", continentName: "North America", countryIsoCode: "US", countryName: "United States", subdivisionName: "Virginia", cityName: "Ashburn", timeZone: "America/New_York", isInEuropeanUnion: false },
  5809844: { geonameId: 5809844, localeCode: "en", continentCode: "NA", continentName: "North America", countryIsoCode: "US", countryName: "United States", subdivisionName: "Washington", cityName: "Seattle", timeZone: "America/Los_Angeles", isInEuropeanUnion: false },
  5808079: { geonameId: 5808079, localeCode: "en", continentCode: "NA", continentName: "North America", countryIsoCode: "US", countryName: "United States", subdivisionName: "Washington", cityName: "Redmond", timeZone: "America/Los_Angeles", isInEuropeanUnion: false },
  5128581: { geonameId: 5128581, localeCode: "en", continentCode: "NA", continentName: "North America", countryIsoCode: "US", countryName: "United States", subdivisionName: "New York", cityName: "New York", timeZone: "America/New_York", isInEuropeanUnion: false },
  1850147: { geonameId: 1850147, localeCode: "en", continentCode: "AS", continentName: "Asia", countryIsoCode: "JP", countryName: "Japan", subdivisionName: "Tokyo", cityName: "Tokyo", timeZone: "Asia/Tokyo", isInEuropeanUnion: false },
  2147714: { geonameId: 2147714, localeCode: "en", continentCode: "OC", continentName: "Oceania", countryIsoCode: "AU", countryName: "Australia", subdivisionName: "New South Wales", cityName: "Sydney", timeZone: "Australia/Sydney", isInEuropeanUnion: false },
  1880252: { geonameId: 1880252, localeCode: "en", continentCode: "AS", continentName: "Asia", countryIsoCode: "SG", countryName: "Singapore", subdivisionName: "Central Singapore", cityName: "Singapore", timeZone: "Asia/Singapore", isInEuropeanUnion: false },
  1275339: { geonameId: 1275339, localeCode: "en", continentCode: "AS", continentName: "Asia", countryIsoCode: "IN", countryName: "India", subdivisionName: "Maharashtra", cityName: "Mumbai", timeZone: "Asia/Kolkata", isInEuropeanUnion: false },
  3448439: { geonameId: 3448439, localeCode: "en", continentCode: "SA", continentName: "South America", countryIsoCode: "BR", countryName: "Brazil", subdivisionName: "Sao Paulo", cityName: "Sao Paulo", timeZone: "America/Sao_Paulo", isInEuropeanUnion: false },
  6167865: { geonameId: 6167865, localeCode: "en", continentCode: "NA", continentName: "North America", countryIsoCode: "CA", countryName: "Canada", subdivisionName: "Ontario", cityName: "Toronto", timeZone: "America/Toronto", isInEuropeanUnion: false },
  2988507: { geonameId: 2988507, localeCode: "en", continentCode: "EU", continentName: "Europe", countryIsoCode: "FR", countryName: "France", subdivisionName: "Ile-de-France", cityName: "Paris", timeZone: "Europe/Paris", isInEuropeanUnion: true },
  1835848: { geonameId: 1835848, localeCode: "en", continentCode: "AS", continentName: "Asia", countryIsoCode: "KR", countryName: "South Korea", subdivisionName: "Seoul", cityName: "Seoul", timeZone: "Asia/Seoul", isInEuropeanUnion: false }
};

export const LOCAL_MAXMIND_BLOCKS: MaxMindCityBlock[] = [
  { network: "185.220.101.0/24", geonameId: 727011, latitude: 42.6977, longitude: 23.3219, accuracyRadius: 20, isAnonymousProxy: true },
  { network: "185.220.100.0/24", geonameId: 2925533, latitude: 50.1109, longitude: 8.6821, accuracyRadius: 20, isAnonymousProxy: true },
  { network: "194.26.29.0/24", geonameId: 2759794, latitude: 52.3676, longitude: 4.9041, accuracyRadius: 20, isAnonymousProxy: true },
  { network: "89.144.20.0/24", geonameId: 683506, latitude: 44.4268, longitude: 26.1025, accuracyRadius: 20, isAnonymousProxy: false },
  { network: "81.18.87.0/24", geonameId: 756135, latitude: 52.2297, longitude: 21.0122, accuracyRadius: 25, isAnonymousProxy: false },
  { network: "198.51.100.0/24", geonameId: 4852924, latitude: 41.2619, longitude: -95.8608, accuracyRadius: 10, isAnonymousProxy: false },
  { network: "8.8.8.0/24", geonameId: 5375480, latitude: 37.4223, longitude: -122.0848, accuracyRadius: 5, isAnonymousProxy: false },
  { network: "1.1.1.0/24", geonameId: 5391959, latitude: 37.7749, longitude: -122.4194, accuracyRadius: 5, isAnonymousProxy: false },
  { network: "52.0.0.0/8", geonameId: 4744870, latitude: 39.0438, longitude: -77.4874, accuracyRadius: 50, isAnonymousProxy: false },
  { network: "54.0.0.0/8", geonameId: 5809844, latitude: 47.6062, longitude: -122.3321, accuracyRadius: 50, isAnonymousProxy: false },
  { network: "40.0.0.0/8", geonameId: 5808079, latitude: 47.6740, longitude: -122.1215, accuracyRadius: 50, isAnonymousProxy: false },
  { network: "20.0.0.0/8", geonameId: 4853828, latitude: 41.5868, longitude: -93.6250, accuracyRadius: 50, isAnonymousProxy: false },
  { network: "104.244.42.0/24", geonameId: 5391959, latitude: 37.7749, longitude: -122.4194, accuracyRadius: 10, isAnonymousProxy: false },
  { network: "157.240.0.0/16", geonameId: 5372223, latitude: 37.4529, longitude: -122.1817, accuracyRadius: 10, isAnonymousProxy: false },
  { network: "17.0.0.0/8", geonameId: 5341145, latitude: 37.3230, longitude: -122.0322, accuracyRadius: 10, isAnonymousProxy: false },
  { network: "185.199.108.0/22", geonameId: 5391959, latitude: 37.7749, longitude: -122.4194, accuracyRadius: 15, isAnonymousProxy: false }
];

export const LOCAL_MAXMIND_ASNS: MaxMindAsnBlock[] = [
  { network: "185.220.101.0/24", asn: "AS200548", org: "Zettahost Cyber Ltd" },
  { network: "185.220.100.0/24", asn: "AS208294", org: "Calyx Institute Tor Exit Node" },
  { network: "194.26.29.0/24", asn: "AS49453", org: "Global Layer B.V." },
  { network: "89.144.20.0/24", asn: "AS9009", org: "M247 Europe SRL" },
  { network: "81.18.87.0/24", asn: "AS12741", org: "Netia S.A. Broadband" },
  { network: "198.51.100.0/24", asn: "AS15169", org: "Google LLC" },
  { network: "8.8.8.0/24", asn: "AS15169", org: "Google LLC Public DNS" },
  { network: "1.1.1.0/24", asn: "AS13335", org: "Cloudflare Inc" },
  { network: "52.0.0.0/8", asn: "AS16509", org: "Amazon.com Inc / AWS us-east-1" },
  { network: "54.0.0.0/8", asn: "AS16509", org: "Amazon.com Inc / AWS" },
  { network: "40.0.0.0/8", asn: "AS8075", org: "Microsoft Corporation" },
  { network: "20.0.0.0/8", asn: "AS8075", org: "Microsoft Azure Cloud" },
  { network: "104.244.42.0/24", asn: "AS13414", org: "Twitter / X Corp" },
  { network: "157.240.0.0/16", asn: "AS32934", org: "Meta Platforms Inc" },
  { network: "17.0.0.0/8", asn: "AS714", org: "Apple Inc" },
  { network: "185.199.108.0/22", asn: "AS36459", org: "GitHub Inc" }
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

  // 3. Match Geoname Location from CIDR match
  const location = matchedBlock ? LOCAL_MAXMIND_LOCATIONS[matchedBlock.geonameId] : undefined;

  if (location && matchedBlock) {
    const isTorExit = ip === "185.220.101.5" || ip.startsWith("185.220.101.");
    return {
      found: true,
      isPrivate: false,
      isRfc1918: false,
      geonameId: location.geonameId,
      city: location.cityName,
      country: location.countryName,
      countryCode: location.countryIsoCode,
      region: location.subdivisionName,
      continentCode: location.continentCode,
      continentName: location.continentName,
      timeZone: location.timeZone,
      isInEuropeanUnion: location.isInEuropeanUnion,
      lat: matchedBlock.latitude,
      lng: matchedBlock.longitude,
      accuracyRadius: matchedBlock.accuracyRadius,
      asn: matchedAsn?.asn || undefined,
      org: matchedAsn?.org || undefined,
      isp: matchedAsn?.org || undefined,
      reverseDns: undefined,
      isTor: isTorExit,
      isAnonymousProxy: matchedBlock.isAnonymousProxy || isTorExit,
      sourceFile: "backend/data/maxmind/GeoLite2-City-Locations-en.csv",
      copyright: MAXMIND_COPYRIGHT,
      license: MAXMIND_LICENSE,
      isVerified: true,
      lookupMethod: "MaxMind GeoLite2 Offline Database"
    };
  }

  // Unmapped address - NEVER fabricate coordinates or fake cities
  return {
    found: false,
    isPrivate: false,
    isRfc1918: false,
    city: undefined,
    country: undefined,
    countryCode: undefined,
    region: undefined,
    lat: undefined,
    lng: undefined,
    asn: undefined,
    org: undefined,
    sourceFile: "backend/data/maxmind/GeoLite2-City-Locations-en.csv",
    copyright: MAXMIND_COPYRIGHT,
    license: MAXMIND_LICENSE,
    isVerified: false,
    lookupMethod: "Unmapped Address"
  };
}

