// IP & Email Hop Forensic Extraction Engine for TraceXMail
// RFC-compliant Trust Boundary Demarcation & Verifiable Upstream Infrastructure Analyzer
// Traverses Received headers from configured trusted gateway perimeter backwards to determine origin.

export interface ClassifiedIp {
  isPrivate: boolean;
  isRfc1918: boolean;
  subnetType: string;
  cidr: string;
  scope: 'PRIVATE_LAN' | 'PUBLIC_INTERNET' | 'LOOPBACK' | 'LINK_LOCAL' | 'UNMAPPED';
  description: string;
}

export interface ExtractedHopCandidate {
  hopNumber: number;
  fromHost?: string;
  fromIp?: string;
  byHost?: string;
  byIp?: string;
  protocol?: string;
  timestamp?: string;
  delaySec?: number;
  rawHeader?: string;
  isTrustBoundary?: boolean;
  isVerifiableOrigin?: boolean;
  isUpstreamUntrusted?: boolean;
  isInternalRelay?: boolean;
  classification: ClassifiedIp;
}

export interface TrustBoundaryConfig {
  trustedGateways?: string[]; // e.g. ["10.0.0.0/8", "192.168.0.0/16", "*.company.internal", "*.protection.outlook.com"]
  trustedSubnets?: string[];
  customInternalHosts?: string[];
}

/**
 * Accurately classifies an IPv4 or IPv6 string into RFC 1918, Loopback, Link-Local,
 * or Public Internet scopes.
 */
export function classifyIp(ip?: string): ClassifiedIp {
  if (!ip || ip === 'UNKNOWN') {
    return {
      isPrivate: false,
      isRfc1918: false,
      subnetType: 'Unmapped',
      cidr: 'N/A',
      scope: 'UNMAPPED',
      description: 'Unmapped Relay Node / No IP Extracted'
    };
  }

  // IPv6 check
  if (ip.includes(':')) {
    const cleanIpv6 = ip.toLowerCase();
    if (cleanIpv6 === '::1' || cleanIpv6.startsWith('fe80:')) {
      return {
        isPrivate: true,
        isRfc1918: false,
        subnetType: cleanIpv6 === '::1' ? 'IPv6 Loopback' : 'IPv6 Link-Local',
        cidr: cleanIpv6 === '::1' ? '::1/128' : 'fe80::/10',
        scope: cleanIpv6 === '::1' ? 'LOOPBACK' : 'LINK_LOCAL',
        description: 'Non-routable IPv6 local address'
      };
    }
    if (cleanIpv6.startsWith('fc00:') || cleanIpv6.startsWith('fd00:')) {
      return {
        isPrivate: true,
        isRfc1918: true,
        subnetType: 'IPv6 Unique Local Address (ULA)',
        cidr: 'fc00::/7',
        scope: 'PRIVATE_LAN',
        description: 'Private IPv6 Intranet Address'
      };
    }
    return {
      isPrivate: false,
      isRfc1918: false,
      subnetType: 'Public IPv6',
      cidr: 'Public IPv6',
      scope: 'PUBLIC_INTERNET',
      description: 'Public Routable IPv6 Internet Space'
    };
  }

  // IPv4 check
  const parts = ip.split('.').map((p) => parseInt(p, 10));
  if (parts.length === 4 && parts.every((p) => !isNaN(p) && p >= 0 && p <= 255)) {
    const [p0, p1] = parts;
    if (p0 === 10) {
      return {
        isPrivate: true,
        isRfc1918: true,
        subnetType: 'RFC 1918 Class A',
        cidr: '10.0.0.0/8',
        scope: 'PRIVATE_LAN',
        description: 'Enterprise Intranet / Datacenter LAN (Non-Routable)'
      };
    }
    if (p0 === 172 && p1 >= 16 && p1 <= 31) {
      return {
        isPrivate: true,
        isRfc1918: true,
        subnetType: 'RFC 1918 Class B',
        cidr: '172.16.0.0/12',
        scope: 'PRIVATE_LAN',
        description: 'Corporate DMZ / Virtual Private Cloud (Non-Routable)'
      };
    }
    if (p0 === 192 && p1 === 168) {
      return {
        isPrivate: true,
        isRfc1918: true,
        subnetType: 'RFC 1918 Class C',
        cidr: '192.168.0.0/16',
        scope: 'PRIVATE_LAN',
        description: 'Local Area Network (LAN) / Office Subnet (Non-Routable)'
      };
    }
    if (p0 === 127) {
      return {
        isPrivate: true,
        isRfc1918: false,
        subnetType: 'Loopback Interface',
        cidr: '127.0.0.0/8',
        scope: 'LOOPBACK',
        description: 'Localhost / Internal System Mailer Loopback'
      };
    }
    if (p0 === 169 && p1 === 254) {
      return {
        isPrivate: true,
        isRfc1918: false,
        subnetType: 'Link-Local APIPA',
        cidr: '169.254.0.0/16',
        scope: 'LINK_LOCAL',
        description: 'Automatic Private IP Addressing (APIPA)'
      };
    }
    return {
      isPrivate: false,
      isRfc1918: false,
      subnetType: 'Public Internet',
      cidr: 'Public IPv4',
      scope: 'PUBLIC_INTERNET',
      description: 'Public Routable Internet Space'
    };
  }

  return {
    isPrivate: false,
    isRfc1918: false,
    subnetType: 'Unmapped',
    cidr: 'N/A',
    scope: 'UNMAPPED',
    description: 'Non-standard / Unmapped IP format'
  };
}

/**
 * Validates whether a candidate string is a strictly valid IPv4 address.
 */
export function isValidIpv4(candidate: string): boolean {
  if (!/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(candidate)) return false;
  const octets = candidate.split('.').map(o => parseInt(o, 10));
  return octets.length === 4 && octets.every(o => !isNaN(o) && o >= 0 && o <= 255);
}

/**
 * Extracts IP addresses from a Received header line.
 */
export function extractIpFromReceivedHeader(receivedLine: string): { fromIp?: string; byIp?: string } {
  // 1. Bracketed IPs e.g. [198.51.100.24]
  const bracketMatches = Array.from(receivedLine.matchAll(/\[(?:IPv6:)?([a-fA-F0-9.:]+)\]/g)).map(m => m[1]);
  const validBracketIps = bracketMatches.filter(ip => isValidIpv4(ip) || ip.includes(':'));

  // 2. Parenthesized IPs e.g. (198.51.100.24)
  const parenMatches = Array.from(receivedLine.matchAll(/\(((?:[a-zA-Z0-9.-]+\s+)?(?:\[)?([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})(?:\])?)\)/g)).map(m => m[2]);
  const validParenIps = parenMatches.filter(isValidIpv4);

  // 3. Fallback raw IPv4 patterns
  const allIps = (receivedLine.match(/\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/g) || []).filter(isValidIpv4);

  let fromIp: string | undefined = undefined;
  if (validBracketIps.length > 0) {
    fromIp = validBracketIps[0];
  } else if (validParenIps.length > 0) {
    fromIp = validParenIps[0];
  } else if (allIps.length > 0) {
    fromIp = allIps[0];
  }

  let byIp: string | undefined = undefined;
  if (validBracketIps.length > 1) {
    byIp = validBracketIps[1];
  }

  return { fromIp, byIp };
}

/**
 * Checks if a host/domain or IP is part of trusted internal gateway infrastructure.
 */
function isTrustedInfrastructure(hostOrIp?: string, config?: TrustBoundaryConfig): boolean {
  if (!hostOrIp) return false;
  const lower = hostOrIp.toLowerCase();

  // Internal RFC1918 / Loopback IPs are always internal
  const classification = classifyIp(hostOrIp);
  if (classification.isPrivate) return true;

  // Standard corporate mail gateway patterns
  const standardTrusted = [
    'protection.outlook.com',
    'mail.protection.outlook.com',
    'google.com',
    'googlemail.com',
    'mx.google.com',
    'pphosted.com',
    'mimecast.com',
    'internal.corp',
    'localhost',
    'mx-ingress'
  ];

  if (standardTrusted.some(pattern => lower.includes(pattern))) {
    return true;
  }

  if (config?.customInternalHosts?.some(h => lower.includes(h.toLowerCase()))) {
    return true;
  }

  return false;
}

/**
 * Parses a single Received header line into a structured candidate hop.
 */
export function parseSingleReceivedHeader(received: string, hopIndex: number): ExtractedHopCandidate {
  const { fromIp, byIp } = extractIpFromReceivedHeader(received);

  const fromMatch = received.match(/\bfrom\s+([^\s;()\[\]]+)/i);
  let fromHost = fromMatch ? fromMatch[1].trim() : undefined;
  if (fromHost && (fromHost === '[' || fromHost === '(')) fromHost = undefined;

  const byMatch = received.match(/\bby\s+([^\s;()\[\]]+)/i);
  let byHost = byMatch ? byMatch[1].trim() : undefined;

  const protoMatch = received.match(/\bwith\s+([a-zA-Z0-9_-]+)/i);
  const protocol = protoMatch ? protoMatch[1].toUpperCase() : 'ESMTP';

  let timestamp: string | undefined = undefined;
  const semiColonIdx = received.lastIndexOf(';');
  if (semiColonIdx !== -1) {
    const rawDateStr = received.substring(semiColonIdx + 1).trim();
    const d = new Date(rawDateStr);
    if (!isNaN(d.getTime())) {
      timestamp = d.toUTCString();
    } else {
      timestamp = rawDateStr;
    }
  }

  const classification = classifyIp(fromIp);

  return {
    hopNumber: hopIndex + 1,
    fromHost: fromHost || (fromIp ? `host-${fromIp.replace(/[.:]/g, '-')}` : 'unknown-relay'),
    fromIp,
    byHost: byHost || 'mx-ingress',
    byIp,
    protocol,
    timestamp: timestamp || new Date().toUTCString(),
    delaySec: 0,
    rawHeader: received,
    classification
  };
}

/**
 * Full Trust Boundary & Verifiable Origin Ingress Extractor
 * Traversal logic:
 * Received headers -> Configured trusted gateway -> Trust boundary -> Earliest verifiable upstream infrastructure -> Origin candidate
 */
export function extractHopsAndOriginIp(
  rawEmlOrHeaders: string,
  config?: TrustBoundaryConfig
): {
  hops: ExtractedHopCandidate[];
  originIp: string;
  originIpSource: string;
  receivedHeadersCount: number;
  trustBoundaryIndex: number;
  trustBoundaryEstablished: boolean;
  trustBoundaryGateway?: string;
} {
  const lines = rawEmlOrHeaders.split(/\r?\n/);
  const receivedHeaders: string[] = [];
  const auxiliaryHeaders: Record<string, string> = {};

  let currentKey = '';
  let currentValue = '';

  for (const line of lines) {
    if (line.trim() === '' && !currentKey) break;

    if (/^[A-Za-z0-9-_]+:/.test(line)) {
      if (currentKey) {
        if (currentKey.toLowerCase() === 'received') {
          receivedHeaders.push(currentValue);
        } else {
          auxiliaryHeaders[currentKey.toLowerCase()] = currentValue;
        }
      }
      const colonIdx = line.indexOf(':');
      currentKey = line.substring(0, colonIdx).trim();
      currentValue = line.substring(colonIdx + 1).trim();
    } else if (/^\s+/.test(line) && currentKey) {
      currentValue += ' ' + line.trim();
    }
  }

  if (currentKey) {
    if (currentKey.toLowerCase() === 'received') {
      receivedHeaders.push(currentValue);
    } else {
      auxiliaryHeaders[currentKey.toLowerCase()] = currentValue;
    }
  }

  // Reverse headers so Hop 1 is the earliest recorded hop, and Hop N is recipient mailbox
  const orderedReceived = [...receivedHeaders].reverse();
  const hops: ExtractedHopCandidate[] = [];

  for (let i = 0; i < orderedReceived.length; i++) {
    const hop = parseSingleReceivedHeader(orderedReceived[i], i);
    hops.push(hop);
  }

  // Compute transmission delays
  for (let i = 1; i < hops.length; i++) {
    const prevTime = new Date(hops[i - 1].timestamp || '').getTime();
    const currTime = new Date(hops[i].timestamp || '').getTime();
    if (!isNaN(prevTime) && !isNaN(currTime) && currTime >= prevTime) {
      hops[i].delaySec = Math.round((currTime - prevTime) / 1000);
    } else {
      hops[i].delaySec = 1;
    }
  }

  // ==========================================
  // TRUST BOUNDARY ALGORITHM
  // Traversal from Recipient Ingress (top of header stack / end of hops array) backward
  // ==========================================
  let trustBoundaryIndex = -1;
  let trustBoundaryGateway: string | undefined = undefined;
  let originIp: string = 'UNKNOWN';
  let originIpSource: string = 'NONE';
  let trustBoundaryEstablished = false;

  // Traverse from newest hop (last element) backward to find the boundary where
  // a trusted gateway received the transmission from an untrusted public upstream
  for (let i = hops.length - 1; i >= 0; i--) {
    const hop = hops[i];
    const isByTrusted = isTrustedInfrastructure(hop.byHost, config) || isTrustedInfrastructure(hop.byIp, config);
    const isFromPrivate = hop.classification.isPrivate;

    if (isByTrusted && hop.fromIp && !isFromPrivate) {
      // Found the perimeter handoff!
      trustBoundaryIndex = i;
      trustBoundaryGateway = hop.byHost || hop.byIp;
      hop.isTrustBoundary = true;
      hop.isVerifiableOrigin = true;
      originIp = hop.fromIp;
      originIpSource = `TRUST_BOUNDARY_INGRESS (Hop ${i + 1}: ${hop.byHost || 'Gateway'})`;
      trustBoundaryEstablished = true;
      break;
    }
  }

  // If no trusted boundary transition was found, check for earliest verifiable public hop
  if (!trustBoundaryEstablished) {
    // Check if Hop 0 is a valid public IP
    const earliestPublicHopIndex = hops.findIndex(h => h.fromIp && !h.classification.isPrivate);
    if (earliestPublicHopIndex !== -1) {
      const hop = hops[earliestPublicHopIndex];
      hop.isVerifiableOrigin = true;
      hop.isTrustBoundary = true;
      originIp = hop.fromIp!;
      originIpSource = `EARLIEST_VERIFIABLE_PUBLIC_RELAY (Hop ${earliestPublicHopIndex + 1})`;
      trustBoundaryIndex = earliestPublicHopIndex;
      trustBoundaryEstablished = true;
    }
  }

  // Mark all hops upstream from the trust boundary as unverified / untrusted
  if (trustBoundaryIndex > 0) {
    for (let i = 0; i < trustBoundaryIndex; i++) {
      hops[i].isUpstreamUntrusted = true;
    }
  }

  // Fallback to authenticated auxiliary headers (SPF client-ip / Authentication-Results) if no Received IP
  if (originIp === 'UNKNOWN') {
    const authResults = auxiliaryHeaders['authentication-results'] || auxiliaryHeaders['received-spf'];
    if (authResults) {
      const match = authResults.match(/(?:client-ip|sender-ip|ip)=([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})/i);
      if (match && isValidIpv4(match[1]) && !classifyIp(match[1]).isPrivate) {
        originIp = match[1];
        originIpSource = 'AUTHENTICATION_RESULTS_INGRESS';
        trustBoundaryEstablished = true;
      }
    }
  }

  return {
    hops,
    originIp,
    originIpSource,
    receivedHeadersCount: receivedHeaders.length,
    trustBoundaryIndex,
    trustBoundaryEstablished,
    trustBoundaryGateway
  };
}
