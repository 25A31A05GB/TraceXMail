/**
 * TraceXMail RFC 8601 / RFC 7208 / RFC 6376 / RFC 7489 Authentication Parser
 * Handles SPF, DKIM, DMARC, and ARC header parsing, alignment checking, and DNS policy fallback.
 */

export interface ParsedSpf {
  status: 'PASS' | 'FAIL' | 'SOFTFAIL' | 'NEUTRAL' | 'NONE' | 'TEMPERROR' | 'PERMERROR';
  record?: string;
  ip?: string;
  domain?: string;
  details?: string;
  sender?: string;
  helo?: string;
}

export interface ParsedDkim {
  status: 'PASS' | 'FAIL' | 'NONE' | 'INVALID' | 'NEUTRAL' | 'TEMPERROR' | 'PERMERROR';
  selector?: string;
  domain?: string;
  identity?: string;
  details?: string;
  algorithm?: string;
}

export interface ParsedDmarc {
  status: 'PASS' | 'FAIL' | 'QUARANTINE' | 'REJECT' | 'NONE' | 'TEMPERROR' | 'PERMERROR';
  policy?: 'none' | 'quarantine' | 'reject';
  domain?: string;
  details?: string;
  disposition?: string;
  subdomainPolicy?: string;
}

export interface ParsedArc {
  status: 'PASS' | 'FAIL' | 'NONE';
  instance?: number;
  details?: string;
}

export interface ComprehensiveAuthResults {
  spf: ParsedSpf;
  dkim: ParsedDkim;
  dmarc: ParsedDmarc;
  arc: ParsedArc;
  rawAuthHeaders: string[];
}

/**
 * Normalizes SPF status strings according to RFC 7208
 */
export function normalizeSpfStatus(raw?: string): ParsedSpf['status'] {
  if (!raw) return 'NONE';
  const s = raw.trim().toUpperCase();
  if (s === 'PASS' || s === 'PASSED') return 'PASS';
  if (s === 'FAIL' || s === 'FAILED' || s === 'HARDFAIL') return 'FAIL';
  if (s === 'SOFTFAIL' || s === 'SOFT_FAIL' || s === 'SOFT-FAIL') return 'SOFTFAIL';
  if (s === 'NEUTRAL') return 'NEUTRAL';
  if (s === 'NONE' || s === 'NO_RECORD') return 'NONE';
  if (s.includes('TEMP')) return 'TEMPERROR';
  if (s.includes('PERM')) return 'PERMERROR';
  return 'NONE';
}

/**
 * Normalizes DKIM status strings according to RFC 6376
 */
export function normalizeDkimStatus(raw?: string): ParsedDkim['status'] {
  if (!raw) return 'NONE';
  const s = raw.trim().toUpperCase();
  if (s === 'PASS' || s === 'PASSED' || s === 'VERIFIED') return 'PASS';
  if (s === 'FAIL' || s === 'FAILED' || s === 'BAD' || s === 'BADSIG') return 'FAIL';
  if (s === 'INVALID' || s === 'SYNTAX_ERROR') return 'INVALID';
  if (s === 'NEUTRAL') return 'NEUTRAL';
  if (s === 'NONE' || s === 'NO_SIGNATURE') return 'NONE';
  if (s.includes('TEMP')) return 'TEMPERROR';
  if (s.includes('PERM')) return 'PERMERROR';
  return 'NONE';
}

/**
 * Normalizes DMARC status strings according to RFC 7489
 */
export function normalizeDmarcStatus(raw?: string): ParsedDmarc['status'] {
  if (!raw) return 'NONE';
  const s = raw.trim().toUpperCase();
  if (s === 'PASS' || s === 'PASSED' || s === 'BESTGUESSPASS') return 'PASS';
  if (s === 'REJECT' || s === 'REJECTED') return 'REJECT';
  if (s === 'QUARANTINE' || s === 'QUARANTINED') return 'QUARANTINE';
  if (s === 'FAIL' || s === 'FAILED') return 'FAIL';
  if (s === 'NONE' || s === 'NO_POLICY') return 'NONE';
  if (s.includes('TEMP')) return 'TEMPERROR';
  if (s.includes('PERM')) return 'PERMERROR';
  return 'NONE';
}

/**
 * Normalizes ARC status strings according to RFC 8617
 */
export function normalizeArcStatus(raw?: string): ParsedArc['status'] {
  if (!raw) return 'NONE';
  const s = raw.trim().toUpperCase();
  if (s === 'PASS' || s === 'PASSED') return 'PASS';
  if (s === 'FAIL' || s === 'FAILED') return 'FAIL';
  return 'NONE';
}

/**
 * Helper to determine if an auth status is definitive (non-NONE)
 */
function isDefinitive(status: string): boolean {
  return status !== 'NONE' && status !== '';
}

/**
 * Parses all authentication headers (Authentication-Results, Received-SPF, DKIM-Signature, ARC, vendor headers)
 * from a header map or raw text stream.
 */
export function parseAuthenticationHeaders(
  headers: Record<string, string | string[] | undefined>,
  context?: {
    fromDomain?: string;
    fromEmail?: string;
    originIp?: string;
    domainDns?: {
      spf?: string;
      spf_qualifier?: string;
      dmarc?: string;
      dmarc_policy?: string;
      dmarc_enforcement?: string;
    };
    isNxdomain?: boolean;
  }
): ComprehensiveAuthResults {
  const fromDomain = context?.fromDomain || (context?.fromEmail ? context.fromEmail.split('@')[1] : undefined);
  const rawAuthHeaders: string[] = [];

  // Gather all matching header lines case-insensitively, handling string[] or single strings
  const getHeaderValues = (key: string): string[] => {
    const results: string[] = [];
    const lowerKey = key.toLowerCase();
    for (const [k, v] of Object.entries(headers)) {
      if (k.toLowerCase() === lowerKey) {
        if (Array.isArray(v)) {
          for (const item of v) {
            if (typeof item === 'string' && item.trim()) results.push(item.trim());
          }
        } else if (typeof v === 'string' && v.trim()) {
          results.push(v.trim());
        }
      }
    }
    return results;
  };

  const authResultsHeaders = [
    ...getHeaderValues('Authentication-Results'),
    ...getHeaderValues('X-Authentication-Results'),
    ...getHeaderValues('ARC-Authentication-Results')
  ];
  const receivedSpfHeaders = [
    ...getHeaderValues('Received-SPF'),
    ...getHeaderValues('X-Received-SPF'),
    ...getHeaderValues('X-SPF-Result'),
    ...getHeaderValues('X-Spf-Result')
  ];
  const dkimSigHeaders = [
    ...getHeaderValues('DKIM-Signature'),
    ...getHeaderValues('X-DKIM-Signature')
  ];
  const arcAuthHeaders = getHeaderValues('ARC-Authentication-Results');
  const dmarcFilterHeaders = [
    ...getHeaderValues('DMARC-Filter'),
    ...getHeaderValues('X-DMARC-Result'),
    ...getHeaderValues('X-Dmarc-Result')
  ];
  const xDkimHeaders = [
    ...getHeaderValues('X-DKIM-Result'),
    ...getHeaderValues('X-Dkim-Result'),
    ...getHeaderValues('X-DKIM')
  ];

  rawAuthHeaders.push(
    ...authResultsHeaders,
    ...receivedSpfHeaders,
    ...dkimSigHeaders,
    ...arcAuthHeaders,
    ...dmarcFilterHeaders,
    ...xDkimHeaders
  );

  // Initialize defaults
  let parsedSpf: ParsedSpf = {
    status: context?.isNxdomain ? 'FAIL' : 'NONE',
    record: context?.domainDns?.spf,
    ip: context?.originIp,
    domain: fromDomain,
    details: context?.isNxdomain
      ? 'Authoritative DNS lookup returned NXDOMAIN'
      : (context?.domainDns?.spf ? `SPF DNS record: ${context.domainDns.spf}` : 'No SPF authentication evaluated')
  };

  let parsedDkim: ParsedDkim = {
    status: 'NONE',
    domain: fromDomain,
    details: 'No DKIM signature verified'
  };

  let parsedDmarc: ParsedDmarc = {
    status: 'NONE',
    policy: (context?.domainDns?.dmarc_policy as any) || 'none',
    domain: fromDomain,
    details: context?.domainDns?.dmarc_enforcement || (context?.domainDns?.dmarc ? `DMARC record: ${context.domainDns.dmarc}` : 'No DMARC policy evaluated')
  };

  let parsedArc: ParsedArc = {
    status: 'NONE',
    details: 'No ARC authentication evaluated'
  };

  // -------------------------------------------------------------
  // 1. Parse Authentication-Results (RFC 8601 / RFC 7601 / RFC 5451)
  // -------------------------------------------------------------
  for (const ar of authResultsHeaders) {
    // Parse SPF inside Authentication-Results
    // Examples:
    // spf=pass (google.com: domain designates 1.2.3.4) smtp.mailfrom=user@domain.com
    // spf=softfail (mx.domain.com: transitioning...) smtp.mailfrom=...
    // spf=pass smtp.mailfrom=domain.com
    const spfMatch = ar.match(/\bspf\s*=\s*([a-zA-Z0-9_-]+)(?:\s*\(([^)]*)\))?/i);
    if (spfMatch) {
      const status = normalizeSpfStatus(spfMatch[1]);
      const comment = spfMatch[2]?.trim();
      const mailfromMatch = ar.match(/smtp\.mailfrom\s*=\s*<?([^\s;>]+)>?/i) || ar.match(/envelope-from\s*=\s*<?([^\s;>]+)>?/i);
      const heloMatch = ar.match(/smtp\.helo\s*=\s*([^\s;]+)/i);
      const clientIpMatch = ar.match(/smtp\.client-ip\s*=\s*([0-9a-fA-F:.]+)/i) || ar.match(/client-ip\s*=\s*([0-9a-fA-F:.]+)/i);

      // Prioritize definitive results over NONE
      if (!isDefinitive(parsedSpf.status) || isDefinitive(status)) {
        parsedSpf = {
          status,
          record: parsedSpf.record || context?.domainDns?.spf,
          ip: clientIpMatch ? clientIpMatch[1] : (context?.originIp || parsedSpf.ip),
          domain: mailfromMatch ? (mailfromMatch[1].includes('@') ? mailfromMatch[1].split('@')[1] : mailfromMatch[1]) : parsedSpf.domain,
          sender: mailfromMatch ? mailfromMatch[1] : parsedSpf.sender,
          helo: heloMatch ? heloMatch[1] : parsedSpf.helo,
          details: comment || `SPF evaluated as ${status}${mailfromMatch ? ` for ${mailfromMatch[1]}` : ''}`
        };
      }
    }

    // Parse DKIM inside Authentication-Results
    // Examples:
    // dkim=pass (2048-bit key; unprotected) header.d=stripe.com header.i=@stripe.com header.b="K8zF2a="
    // dkim=fail (bad signature) header.d=example.com
    // dkim=pass header.i=@domain.com header.s=s1
    const dkimMatches = Array.from(ar.matchAll(/\bdkim\s*=\s*([a-zA-Z0-9_-]+)(?:\s*\(([^)]*)\))?/gi));
    for (const dm of dkimMatches) {
      const status = normalizeDkimStatus(dm[1]);
      const comment = dm[2]?.trim();
      const iMatch = ar.match(/header\.(?:i|d)\s*=\s*<?@?([^\s;>]+)>?/i);
      const sMatch = ar.match(/header\.s\s*=\s*([^\s;]+)/i);
      const aMatch = ar.match(/header\.a\s*=\s*([^\s;]+)/i);

      if (!isDefinitive(parsedDkim.status) || isDefinitive(status)) {
        parsedDkim = {
          status,
          selector: sMatch ? sMatch[1] : parsedDkim.selector,
          domain: iMatch ? iMatch[1].replace(/^@/, '') : parsedDkim.domain,
          identity: iMatch ? iMatch[1] : parsedDkim.identity,
          algorithm: aMatch ? aMatch[1] : parsedDkim.algorithm,
          details: comment || `DKIM signature evaluated as ${status}${iMatch ? ` for ${iMatch[1]}` : ''}`
        };
      }
    }

    // Parse DMARC inside Authentication-Results
    // Examples:
    // dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=stripe.com
    // dmarc=fail (p=REJECT dis=QUARANTINE) header.from=docusign-envelope-review.net
    // dmarc=pass action=none header.from=domain.com
    // dmarc=reject
    const dmarcMatch = ar.match(/\bdmarc\s*=\s*([a-zA-Z0-9_-]+)(?:\s*\(([^)]*)\))?/i);
    if (dmarcMatch) {
      const status = normalizeDmarcStatus(dmarcMatch[1]);
      const comment = dmarcMatch[2]?.trim();
      const fromMatch = ar.match(/header\.from\s*=\s*([^\s;]+)/i);
      const policyMatch = ar.match(/\bp\s*=\s*([a-zA-Z]+)/i);
      const spMatch = ar.match(/\bsp\s*=\s*([a-zA-Z]+)/i);
      const disMatch = ar.match(/\bdis\s*=\s*([a-zA-Z]+)/i) || ar.match(/\baction\s*=\s*([a-zA-Z]+)/i);

      let effectivePolicy: ParsedDmarc['policy'] = parsedDmarc.policy || 'none';
      if (policyMatch) {
        const p = policyMatch[1].toLowerCase();
        if (p === 'reject' || p === 'quarantine' || p === 'none') {
          effectivePolicy = p;
        }
      } else if (status === 'REJECT') {
        effectivePolicy = 'reject';
      } else if (status === 'QUARANTINE') {
        effectivePolicy = 'quarantine';
      }

      if (!isDefinitive(parsedDmarc.status) || isDefinitive(status)) {
        parsedDmarc = {
          status,
          policy: effectivePolicy,
          domain: fromMatch ? fromMatch[1] : parsedDmarc.domain,
          subdomainPolicy: spMatch ? spMatch[1].toLowerCase() : parsedDmarc.subdomainPolicy,
          disposition: disMatch ? disMatch[1] : parsedDmarc.disposition,
          details: comment || `DMARC evaluated as ${status}${effectivePolicy ? ` (policy: ${effectivePolicy})` : ''}`
        };
      }
    }

    // Parse ARC inside Authentication-Results
    const arcMatch = ar.match(/\barc\s*=\s*([a-zA-Z0-9_-]+)(?:\s*\(([^)]*)\))?/i);
    if (arcMatch) {
      const arcStat = normalizeArcStatus(arcMatch[1]);
      if (!isDefinitive(parsedArc.status) || isDefinitive(arcStat)) {
        parsedArc = {
          status: arcStat,
          details: arcMatch[2]?.trim() || `ARC status: ${arcStat}`
        };
      }
    }
  }

  // -------------------------------------------------------------
  // 2. Parse Received-SPF headers (RFC 7208) as secondary/fallback
  // -------------------------------------------------------------
  for (const rawRcvSpf of receivedSpfHeaders) {
    // If SPF is still NONE or if this header provides a definitive result:
    if (!isDefinitive(parsedSpf.status)) {
      // Remove optional leading "Received-SPF:" prefix
      const cleaned = rawRcvSpf.replace(/^Received-SPF:\s*/i, '').trim();
      const match = cleaned.match(/^([a-zA-Z0-9_-]+)(?:\s*\(([^)]*)\))?/i) || cleaned.match(/\b([a-zA-Z0-9_-]+)(?:\s*\(([^)]*)\))?/i);
      if (match) {
        const status = normalizeSpfStatus(match[1]);
        if (status !== 'NONE') {
          const comment = match[2]?.trim();
          const clientIpMatch = cleaned.match(/client-ip\s*=\s*([0-9a-fA-F:.]+)/i);
          const envFromMatch = cleaned.match(/envelope-from\s*=\s*<?([^\s;>"]+)>?/i) || cleaned.match(/smtp\.mailfrom\s*=\s*<?([^\s;>"]+)>?/i);
          const heloMatch = cleaned.match(/helo\s*=\s*([^\s;]+)/i);

          parsedSpf = {
            status,
            record: parsedSpf.record || context?.domainDns?.spf,
            ip: clientIpMatch ? clientIpMatch[1] : (context?.originIp || parsedSpf.ip),
            domain: envFromMatch ? (envFromMatch[1].includes('@') ? envFromMatch[1].split('@')[1] : envFromMatch[1]) : parsedSpf.domain,
            sender: envFromMatch ? envFromMatch[1] : parsedSpf.sender,
            helo: heloMatch ? heloMatch[1] : parsedSpf.helo,
            details: comment || `Received-SPF: ${status}`
          };
          break;
        }
      }
    }
  }

  // -------------------------------------------------------------
  // 3. Parse DKIM-Signature headers (RFC 6376)
  // -------------------------------------------------------------
  for (const sig of dkimSigHeaders) {
    const dMatch = sig.match(/\bd\s*=\s*([a-zA-Z0-9.-]+)/i);
    const sMatch = sig.match(/\bs\s*=\s*([a-zA-Z0-9._-]+)/i);
    const aMatch = sig.match(/\ba\s*=\s*([a-zA-Z0-9-]+)/i);
    const iMatch = sig.match(/\bi\s*=\s*([^\s;]+)/i);

    if (dMatch && !parsedDkim.domain) {
      parsedDkim.domain = dMatch[1];
    }
    if (sMatch && !parsedDkim.selector) {
      parsedDkim.selector = sMatch[1];
    }
    if (aMatch && !parsedDkim.algorithm) {
      parsedDkim.algorithm = aMatch[1];
    }
    if (iMatch && !parsedDkim.identity) {
      parsedDkim.identity = iMatch[1];
    }

    if (parsedDkim.status === 'NONE') {
      parsedDkim.details = `DKIM signature present (s=${parsedDkim.selector || sMatch?.[1] || 'unknown'}, d=${parsedDkim.domain || dMatch?.[1] || 'unknown'})`;
    }
  }

  // -------------------------------------------------------------
  // 4. Vendor DKIM / DMARC Header Fallbacks (X-DKIM-Result, DMARC-Filter)
  // -------------------------------------------------------------
  for (const xd of xDkimHeaders) {
    if (!isDefinitive(parsedDkim.status)) {
      const st = normalizeDkimStatus(xd);
      if (st !== 'NONE') {
        parsedDkim.status = st;
        parsedDkim.details = `X-DKIM-Result: ${st}`;
      }
    }
  }

  for (const xdm of dmarcFilterHeaders) {
    if (!isDefinitive(parsedDmarc.status)) {
      const match = xdm.match(/\b(pass|fail|reject|quarantine|none)\b/i);
      if (match) {
        const st = normalizeDmarcStatus(match[1]);
        if (st !== 'NONE') {
          parsedDmarc.status = st;
          parsedDmarc.details = `DMARC-Filter: ${st}`;
        }
      }
    }
  }

  // -------------------------------------------------------------
  // 5. Parse ARC-Authentication-Results / ARC-Seal
  // -------------------------------------------------------------
  if (arcAuthHeaders.length > 0 && parsedArc.status === 'NONE') {
    const arcHeader = arcAuthHeaders[0];
    const instMatch = arcHeader.match(/i\s*=\s*(\d+)/i);
    const arcResultMatch = arcHeader.match(/arc\s*=\s*([a-zA-Z0-9_-]+)/i);
    if (arcResultMatch) {
      const arcStat = normalizeArcStatus(arcResultMatch[1]);
      parsedArc = {
        status: arcStat,
        instance: instMatch ? parseInt(instMatch[1], 10) : 1,
        details: `ARC Chain evaluated at instance ${instMatch ? instMatch[1] : 1} (${arcStat})`
      };
    }
  }

  // -------------------------------------------------------------
  // 6. DMARC Alignment & Enforcement synthesis fallback
  // -------------------------------------------------------------
  if (parsedDmarc.status === 'NONE' && context?.domainDns?.dmarc_policy) {
    const pol = context.domainDns.dmarc_policy.toLowerCase();
    parsedDmarc.policy = (pol === 'reject' || pol === 'quarantine' || pol === 'none') ? pol : 'none';

    // If SPF and DKIM both failed or are missing, and domain requires strict reject/quarantine:
    if ((parsedSpf.status === 'FAIL' || parsedSpf.status === 'SOFTFAIL' || parsedSpf.status === 'NONE') &&
        (parsedDkim.status === 'FAIL' || parsedDkim.status === 'INVALID' || parsedDkim.status === 'NONE')) {
      if (pol === 'reject') {
        parsedDmarc.status = 'REJECT';
        parsedDmarc.details = `DMARC REJECT enforced: strict policy p=reject failed both SPF (${parsedSpf.status}) and DKIM (${parsedDkim.status}) alignment`;
      } else if (pol === 'quarantine') {
        parsedDmarc.status = 'QUARANTINE';
        parsedDmarc.details = `DMARC QUARANTINE enforced: policy p=quarantine failed SPF/DKIM alignment`;
      } else if (pol === 'none') {
        parsedDmarc.status = 'FAIL';
        parsedDmarc.details = `DMARC FAIL (p=none): Alignment check failed for domain ${fromDomain || 'sender'}`;
      }
    } else if (parsedSpf.status === 'PASS' || parsedDkim.status === 'PASS') {
      parsedDmarc.status = 'PASS';
      parsedDmarc.details = `DMARC PASS: Authenticated alignment verified with domain ${fromDomain || 'sender'}`;
    }
  }

  return {
    spf: parsedSpf,
    dkim: parsedDkim,
    dmarc: parsedDmarc,
    arc: parsedArc,
    rawAuthHeaders
  };
}
