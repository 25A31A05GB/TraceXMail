// IP & Email Hop Forensic Extraction Engine for TraceXMail
// Accurately extracts client submission IPs, envelope relays, RFC 1918 demarcation,
// and chronological relay hops according to RFC 5321 and RFC 5322.

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
  isOrigin?: boolean;
  isPublicGateway?: boolean;
  classification: ClassifiedIp;
}

/**
 * Accurately classifies an IPv4 or IPv6 string into RFC 1918, Loopback, Link-Local,
 * or Public Internet scopes.
 */
export function classifyIp(ip?: string): ClassifiedIp {
  if (!ip) {
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
 * Extracts all IP addresses from a Received header with priority given to
 * bracketed client IPs: e.g. from mail.host.com (rdns.host.com [198.51.100.24])
 */
export function extractIpFromReceivedHeader(receivedLine: string): { fromIp?: string; byIp?: string } {
  // 1. Check for standard RFC bracketed IPs e.g. [192.0.2.1] or [IPv6:2001:db8::1]
  const bracketMatches = Array.from(receivedLine.matchAll(/\[(?:IPv6:)?([a-fA-F0-9.:]+)\]/g)).map(m => m[1]);
  const validBracketIps = bracketMatches.filter(ip => isValidIpv4(ip) || ip.includes(':'));

  // 2. Check for parenthesized IPs e.g. (192.0.2.1) or (rdns 192.0.2.1)
  const parenMatches = Array.from(receivedLine.matchAll(/\(((?:[a-zA-Z0-9.-]+\s+)?(?:\[)?([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})(?:\])?)\)/g)).map(m => m[2]);
  const validParenIps = parenMatches.filter(isValidIpv4);

  // 3. Fallback to any IPv4 address
  const allIps = (receivedLine.match(/\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/g) || []).filter(isValidIpv4);

  // Determine candidate fromIp (the transmitting client)
  let fromIp: string | undefined = undefined;

  // The 'from' clause IP is almost always the first bracketed or parenthesized IP in Received
  if (validBracketIps.length > 0) {
    fromIp = validBracketIps[0];
  } else if (validParenIps.length > 0) {
    fromIp = validParenIps[0];
  } else if (allIps.length > 0) {
    fromIp = allIps[0];
  }

  // If there's a second bracketed IP after 'by', it's the receiver (byIp)
  let byIp: string | undefined = undefined;
  if (validBracketIps.length > 1) {
    byIp = validBracketIps[1];
  }

  return { fromIp, byIp };
}

/**
 * Extracts metadata from a single Received header line:
 * fromHost, fromIp, byHost, protocol, timestamp
 */
export function parseSingleReceivedHeader(received: string, hopIndex: number): ExtractedHopCandidate {
  const { fromIp, byIp } = extractIpFromReceivedHeader(received);

  // Extract fromHost: 'from <host>'
  const fromMatch = received.match(/\bfrom\s+([^\s;()\[\]]+)/i);
  let fromHost = fromMatch ? fromMatch[1].trim() : undefined;
  if (fromHost && (fromHost === '[' || fromHost === '(')) fromHost = undefined;

  // Extract byHost: 'by <host>'
  const byMatch = received.match(/\bby\s+([^\s;()\[\]]+)/i);
  let byHost = byMatch ? byMatch[1].trim() : undefined;

  // Extract protocol: 'with <protocol>'
  const protoMatch = received.match(/\bwith\s+([a-zA-Z0-9_-]+)/i);
  const protocol = protoMatch ? protoMatch[1].toUpperCase() : 'ESMTP';

  // Extract timestamp: date string after the semicolon ';'
  let timestamp: string | undefined = undefined;
  let parsedDate: Date | null = null;
  const semiColonIdx = received.lastIndexOf(';');
  if (semiColonIdx !== -1) {
    const rawDateStr = received.substring(semiColonIdx + 1).trim();
    const d = new Date(rawDateStr);
    if (!isNaN(d.getTime())) {
      parsedDate = d;
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
 * Comprehensive parser that unfolds RFC 822 email headers and extracts
 * chronological relay hops and fallback envelope originating IPs.
 */
export function extractHopsAndOriginIp(rawEmlOrHeaders: string): {
  hops: ExtractedHopCandidate[];
  originIp?: string;
  originIpSource: string;
  receivedHeadersCount: number;
} {
  const lines = rawEmlOrHeaders.split(/\r?\n/);
  const receivedHeaders: string[] = [];
  const auxiliaryHeaders: Record<string, string> = {};

  let currentKey = '';
  let currentValue = '';

  for (const line of lines) {
    // End of headers
    if (line.trim() === '' && !currentKey) {
      break;
    }

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
      // Continuation line (RFC 2822 §2.2.3)
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

  // Received headers are written newest (top) to oldest (bottom).
  // Chronological traversal requires reversing them: Hop 1 (client origin) -> Hop N (recipient)
  const orderedReceived = [...receivedHeaders].reverse();
  const hops: ExtractedHopCandidate[] = [];

  for (let i = 0; i < orderedReceived.length; i++) {
    const hop = parseSingleReceivedHeader(orderedReceived[i], i);
    hops.push(hop);
  }

  // Calculate delays between chronological hops if dates are valid
  for (let i = 1; i < hops.length; i++) {
    const prevTime = new Date(hops[i - 1].timestamp || '').getTime();
    const currTime = new Date(hops[i].timestamp || '').getTime();
    if (!isNaN(prevTime) && !isNaN(currTime) && currTime >= prevTime) {
      hops[i].delaySec = Math.round((currTime - prevTime) / 1000);
    } else {
      hops[i].delaySec = 1;
    }
  }

  // Identify Origin Hop (Hop 1 or earliest public hop)
  let originIp: string | undefined = undefined;
  let originIpSource = 'NONE';

  if (hops.length > 0) {
    hops[0].isOrigin = true;
    originIp = hops[0].fromIp;
    originIpSource = 'RECEIVED_HEADER_ORIGIN';

    // Demarcate first public gateway
    const firstPublicHop = hops.find(h => !h.classification.isPrivate && h.fromIp);
    if (firstPublicHop && !firstPublicHop.isOrigin) {
      firstPublicHop.isPublicGateway = true;
    }
  }

  // Check auxiliary headers if originIp is still missing or private
  if (!originIp || classifyIp(originIp).isPrivate) {
    // 1. Check X-Originating-IP
    const xOrig = auxiliaryHeaders['x-originating-ip'];
    if (xOrig) {
      const match = xOrig.match(/(?:\[)?((?:[0-9]{1,3}\.){3}[0-9]{1,3})(?:\])?/);
      if (match && isValidIpv4(match[1])) {
        originIp = match[1];
        originIpSource = 'X-ORIGINATING-IP';
      }
    }

    // 2. Check X-Sender-IP
    if (!originIp) {
      const xSender = auxiliaryHeaders['x-sender-ip'];
      if (xSender) {
        const match = xSender.match(/(?:\[)?((?:[0-9]{1,3}\.){3}[0-9]{1,3})(?:\])?/);
        if (match && isValidIpv4(match[1])) {
          originIp = match[1];
          originIpSource = 'X-SENDER-IP';
        }
      }
    }

    // 3. Check Received-SPF client-ip
    if (!originIp) {
      const spf = auxiliaryHeaders['received-spf'];
      if (spf) {
        const match = spf.match(/client-ip=([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})/i);
        if (match && isValidIpv4(match[1])) {
          originIp = match[1];
          originIpSource = 'RECEIVED-SPF_CLIENT-IP';
        }
      }
    }

    // 4. Check Authentication-Results sender-ip
    if (!originIp) {
      const auth = auxiliaryHeaders['authentication-results'];
      if (auth) {
        const match = auth.match(/(?:sender-ip|ip)=([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})/i);
        if (match && isValidIpv4(match[1])) {
          originIp = match[1];
          originIpSource = 'AUTHENTICATION-RESULTS_IP';
        }
      }
    }

    // 5. Check X-Real-IP / X-Forwarded-For
    if (!originIp) {
      const xReal = auxiliaryHeaders['x-real-ip'] || auxiliaryHeaders['x-forwarded-for'];
      if (xReal) {
        const match = xReal.match(/([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})/);
        if (match && isValidIpv4(match[1])) {
          originIp = match[1];
          originIpSource = 'X-REAL-IP';
        }
      }
    }

    // If an auxiliary header yielded a public IP, attach or update the origin hop
    if (originIp && hops.length > 0 && hops[0].isOrigin && !hops[0].fromIp) {
      hops[0].fromIp = originIp;
      hops[0].classification = classifyIp(originIp);
    } else if (originIp && hops.length === 0) {
      // Create a single truthful hop representing the client submission
      hops.push({
        hopNumber: 1,
        fromHost: auxiliaryHeaders['from'] || 'client-origin',
        fromIp: originIp,
        byHost: 'mail-gateway',
        protocol: 'ESMTP',
        timestamp: auxiliaryHeaders['date'] || new Date().toUTCString(),
        delaySec: 0,
        isOrigin: true,
        classification: classifyIp(originIp)
      });
    }
  }

  return {
    hops,
    originIp,
    originIpSource,
    receivedHeadersCount: receivedHeaders.length
  };
}
