/**
 * TraceXMail Structural Identity-Consistency & Forensic Feature Extraction Engine
 * Provides deterministic, explainable feature extraction for ML classification & heuristic scoring.
 * Enforces identity consistency between From Header, Display Name, Reply-To, Return-Path,
 * and Authoritative DNS / Cryptographic Authentication.
 */

import fs from 'fs';
import path from 'path';

export interface BrandDefinition {
  id: string;
  name: string;
  legitimateDomains: string[];
  keywords: string[];
  regex: string;
}

export interface BrandConfig {
  version: string;
  brands: BrandDefinition[];
}

// Fallback brands if config file cannot be read
const DEFAULT_BRANDS: BrandDefinition[] = [
  {
    id: 'paypal',
    name: 'PayPal',
    legitimateDomains: ['paypal.com', 'paypal.co.uk', 'paypal.de', 'paypal-communication.com'],
    keywords: ['paypal', 'pay pal'],
    regex: '\\b(?:pay\\s*pal|paypal)\\b'
  },
  {
    id: 'microsoft',
    name: 'Microsoft',
    legitimateDomains: ['microsoft.com', 'office365.com', 'office.com', 'microsoftonline.com', 'outlook.com', 'live.com'],
    keywords: ['microsoft', 'office 365', 'office365', 'm365', 'outlook', 'microsoft 365'],
    regex: '\\b(?:microsoft|office\\s*365|m365|outlook|microsoftonline|microsoft\\s*365)\\b'
  },
  {
    id: 'google',
    name: 'Google',
    legitimateDomains: ['google.com', 'google.co.uk', 'gmail.com', 'googlemail.com'],
    keywords: ['google', 'gmail', 'google workspace', 'google drive'],
    regex: '\\b(?:google|gmail|google\\s*workspace|google\\s*drive)\\b'
  },
  {
    id: 'apple',
    name: 'Apple',
    legitimateDomains: ['apple.com', 'icloud.com', 'appleid.apple.com'],
    keywords: ['apple', 'icloud', 'apple id', 'apple support'],
    regex: '\\b(?:apple|icloud|apple\\s*id|apple\\s*support)\\b'
  },
  {
    id: 'docusign',
    name: 'DocuSign',
    legitimateDomains: ['docusign.com', 'docusign.net'],
    keywords: ['docusign', 'docu sign'],
    regex: '\\b(?:docusign|docu\\s*sign)\\b'
  },
  {
    id: 'amazon',
    name: 'Amazon',
    legitimateDomains: ['amazon.com', 'amazon.co.uk', 'amazonaws.com'],
    keywords: ['amazon', 'aws', 'amazon web services'],
    regex: '\\b(?:amazon|amazonaws|aws)\\b'
  },
  {
    id: 'chase',
    name: 'Chase Bank',
    legitimateDomains: ['chase.com', 'jpmorgan.com'],
    keywords: ['chase', 'jpmorgan', 'chase online'],
    regex: '\\b(?:chase|jpmorgan)\\b'
  },
  {
    id: 'bankofamerica',
    name: 'Bank of America',
    legitimateDomains: ['bankofamerica.com', 'bofa.com'],
    keywords: ['bank of america', 'bofa'],
    regex: '\\b(?:bank\\s*of\\s*america|bofa)\\b'
  },
  {
    id: 'wellsfargo',
    name: 'Wells Fargo',
    legitimateDomains: ['wellsfargo.com'],
    keywords: ['wells fargo', 'wellsfargo'],
    regex: '\\b(?:wells\\s*fargo|wellsfargo)\\b'
  },
  {
    id: 'netflix',
    name: 'Netflix',
    legitimateDomains: ['netflix.com'],
    keywords: ['netflix'],
    regex: '\\b(?:netflix)\\b'
  },
  {
    id: 'dropbox',
    name: 'Dropbox',
    legitimateDomains: ['dropbox.com'],
    keywords: ['dropbox'],
    regex: '\\b(?:dropbox)\\b'
  },
  {
    id: 'stripe',
    name: 'Stripe',
    legitimateDomains: ['stripe.com'],
    keywords: ['stripe'],
    regex: '\\b(?:stripe)\\b'
  },
  {
    id: 'github',
    name: 'GitHub',
    legitimateDomains: ['github.com'],
    keywords: ['github'],
    regex: '\\b(?:github)\\b'
  },
  {
    id: 'fedex',
    name: 'FedEx',
    legitimateDomains: ['fedex.com'],
    keywords: ['fedex'],
    regex: '\\b(?:fedex)\\b'
  },
  {
    id: 'ups',
    name: 'UPS',
    legitimateDomains: ['ups.com'],
    keywords: ['ups'],
    regex: '\\b(?:ups)\\b'
  }
];

let cachedBrands: BrandDefinition[] | null = null;

export function loadBrandDefinitions(): BrandDefinition[] {
  if (cachedBrands) return cachedBrands;
  try {
    const configPath = path.join(process.cwd(), 'config', 'brand_domains.json');
    if (fs.existsSync(configPath)) {
      const raw = fs.readFileSync(configPath, 'utf8');
      const parsed: BrandConfig = JSON.parse(raw);
      if (parsed.brands && Array.isArray(parsed.brands)) {
        cachedBrands = parsed.brands;
        return cachedBrands;
      }
    }
  } catch (e) {
    console.warn('[BrandConfig] Failed to load config/brand_domains.json, using defaults:', e);
  }
  cachedBrands = DEFAULT_BRANDS;
  return cachedBrands;
}

/**
 * Extracts pure domain from an email address or domain string.
 */
export function extractDomain(inputStr: string): string {
  if (!inputStr) return '';
  const match = inputStr.match(/@([a-zA-Z0-9.-]+)/);
  if (match) return match[1].toLowerCase().trim();
  return inputStr.toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '').trim();
}

/**
 * Checks for punycode or obvious homoglyph indicators in domain.
 */
export function isPunycodeOrHomoglyph(domain: string): boolean {
  if (!domain) return false;
  if (domain.startsWith('xn--') || domain.includes('.xn--')) return true;
  // Cyrillic/Greek character ranges mixed in domain
  if (/[\u0400-\u04FF\u0370-\u03FF]/.test(domain)) return true;
  return false;
}

export interface StructuralIdentityEvaluation {
  claimedBrand: string | null;
  isBrandDomainAligned: boolean;
  isBrandDisplayMismatch: boolean;
  isLookalikeDomain: boolean;
  lookalikePattern: string | null;
  isReplyToMismatch: boolean;
  isReturnPathMismatch: boolean;
  isPunycode: boolean;
  structuralTokens: string[];
}

/**
 * Evaluates structural consistency across sender headers, display name, and brand registries.
 */
export function evaluateStructuralIdentity(input: {
  from: string;
  fromDomain?: string;
  replyTo?: string;
  returnPath?: string;
  auth?: {
    spf?: { status?: string };
    dkim?: { status?: string };
    dmarc?: { status?: string; policy?: string };
  };
  domainIntelligence?: {
    status?: string;
    is_newly_registered?: boolean;
    domain_age_days?: number;
    mx_missing?: boolean;
    typosquatting?: { is_typosquat?: boolean; target_brand?: string };
  };
  hops?: Array<{ isTor?: boolean; is_tor?: boolean; abuseScore?: number }>;
}): StructuralIdentityEvaluation {
  const brands = loadBrandDefinitions();
  const from = input.from || '';
  const fromDomain = (input.fromDomain || extractDomain(from)).toLowerCase();
  const replyTo = input.replyTo || '';
  const returnPath = input.returnPath || '';

  const replyDomain = extractDomain(replyTo);
  const returnDomain = extractDomain(returnPath);

  let claimedBrand: string | null = null;
  let isBrandDomainAligned = false;
  let isBrandDisplayMismatch = false;
  let isLookalikeDomain = false;
  let lookalikePattern: string | null = null;

  const structuralTokens: string[] = [];

  // 1. Sender Domain Token
  if (fromDomain) {
    structuralTokens.push(`domain_${fromDomain.replace(/[^a-z0-9]/g, '_')}`);
  }

  // 2. Punycode check
  const isPunycode = isPunycodeOrHomoglyph(fromDomain);
  if (isPunycode) {
    structuralTokens.push('feat_lookalike_punycode');
    structuralTokens.push('feat_impersonation_cue');
  }

  // 3. Brand & Display Name Spoofing
  const lowerFrom = from.toLowerCase();
  for (const b of brands) {
    let matchesDisplayName = false;
    try {
      const rx = new RegExp(b.regex, 'i');
      matchesDisplayName = rx.test(lowerFrom);
    } catch {
      matchesDisplayName = b.keywords.some(k => lowerFrom.includes(k.toLowerCase()));
    }

    if (matchesDisplayName) {
      claimedBrand = b.name;
      structuralTokens.push(`feat_brand_ref_${b.id}`);

      const isLegitDomain = b.legitimateDomains.some(ld =>
        fromDomain === ld || fromDomain.endsWith('.' + ld)
      );

      if (isLegitDomain) {
        isBrandDomainAligned = true;
        structuralTokens.push('feat_brand_domain_aligned');
      } else {
        isBrandDisplayMismatch = true;
        structuralTokens.push('feat_brand_display_domain_mismatch');
        structuralTokens.push('feat_impersonation_cue');
      }
    }

    // Check lookalike patterns in domain name (e.g. paypal-security.com, verify-docusign.net)
    if (fromDomain && !b.legitimateDomains.includes(fromDomain)) {
      if (
        fromDomain.includes(`${b.id}-`) ||
        fromDomain.includes(`-${b.id}`) ||
        fromDomain.includes(`${b.id}.`) ||
        (fromDomain.includes(b.id) && fromDomain.length > b.id.length + 4)
      ) {
        isLookalikeDomain = true;
        lookalikePattern = `Hyphenated/Compound Lookalike of ${b.name}`;
        structuralTokens.push('feat_lookalike_hyphenated_brand');
        structuralTokens.push(`feat_lookalike_brand_${b.id}`);
        structuralTokens.push('feat_impersonation_cue');
      }
    }
  }

  // 4. Reply-To Mismatch
  const isReplyToMismatch = Boolean(replyDomain && fromDomain && replyDomain !== fromDomain);
  if (isReplyToMismatch) {
    structuralTokens.push('feat_reply_to_mismatch');
  }

  // 5. Return-Path Mismatch
  const isReturnPathMismatch = Boolean(returnDomain && fromDomain && returnDomain !== fromDomain);
  if (isReturnPathMismatch) {
    structuralTokens.push('feat_return_path_mismatch');
  }

  // 6. Cryptographic Authentication Signals
  const spfStatus = (input.auth?.spf?.status || '').toUpperCase();
  if (spfStatus === 'PASS') structuralTokens.push('feat_auth_spf_pass');
  else if (spfStatus === 'FAIL') {
    structuralTokens.push('feat_auth_spf_fail');
    structuralTokens.push('feat_impersonation_cue');
  } else if (spfStatus === 'SOFTFAIL') structuralTokens.push('feat_auth_spf_softfail');
  else structuralTokens.push('feat_auth_spf_none');

  const dkimStatus = (input.auth?.dkim?.status || '').toUpperCase();
  if (dkimStatus === 'PASS') structuralTokens.push('feat_auth_dkim_pass');
  else if (dkimStatus === 'FAIL' || dkimStatus === 'INVALID') {
    structuralTokens.push('feat_auth_dkim_fail');
    structuralTokens.push('feat_impersonation_cue');
  } else structuralTokens.push('feat_auth_dkim_none');

  const dmarcStatus = (input.auth?.dmarc?.status || '').toUpperCase();
  if (dmarcStatus === 'PASS') structuralTokens.push('feat_auth_dmarc_pass');
  else if (dmarcStatus === 'FAIL' || dmarcStatus === 'REJECT') {
    structuralTokens.push('feat_auth_dmarc_fail');
    structuralTokens.push('feat_impersonation_cue');
  } else structuralTokens.push('feat_auth_dmarc_none');

  // 7. Domain Intelligence Signals
  if (input.domainIntelligence?.status === 'nxdomain') {
    structuralTokens.push('feat_nxdomain');
  }
  if (input.domainIntelligence?.is_newly_registered || (input.domainIntelligence?.domain_age_days !== undefined && input.domainIntelligence.domain_age_days < 30)) {
    structuralTokens.push('feat_newly_registered_domain');
  }
  if (input.domainIntelligence?.mx_missing) {
    structuralTokens.push('feat_mx_missing');
  }

  // 8. Routing / Tor Signals
  if (input.hops?.some(h => h.isTor || h.is_tor || (h.abuseScore && h.abuseScore > 60))) {
    structuralTokens.push('feat_anonymized_relay_tor');
  }

  return {
    claimedBrand,
    isBrandDomainAligned,
    isBrandDisplayMismatch,
    isLookalikeDomain,
    lookalikePattern,
    isReplyToMismatch,
    isReturnPathMismatch,
    isPunycode,
    structuralTokens
  };
}

/**
 * Standard unified tokenizer that extracts NLP tokens, n-grams, and structural identity features.
 * Guaranteed to produce identical feature tokens across Training, Standalone Verification, and Runtime Inference.
 */
export function extractForensicTokens(input: {
  subject: string;
  from?: string;
  fromDomain?: string;
  bodyText?: string;
  text?: string;
  replyTo?: string;
  returnPath?: string;
  auth?: {
    spf?: { status?: string };
    dkim?: { status?: string };
    dmarc?: { status?: string; policy?: string };
  };
  domainIntelligence?: {
    status?: string;
    is_newly_registered?: boolean;
    domain_age_days?: number;
    mx_missing?: boolean;
    typosquatting?: { is_typosquat?: boolean; target_brand?: string };
  };
  hops?: Array<{ isTor?: boolean; is_tor?: boolean; abuseScore?: number }>;
}): string[] {
  const subject = input.subject || '';
  const body = input.bodyText || input.text || '';
  const from = input.from || '';
  const fromDomain = (input.fromDomain || extractDomain(from)).toLowerCase();

  const combined = `${subject} ${subject} ${from} ${fromDomain} ${body.slice(0, 4000)}`;
  const normalized = combined
    .toLowerCase()
    .replace(/https?:\/\/[^\s]+/g, ' url_token ')
    .replace(/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g, ' ip_token ')
    .replace(/[^\w\s]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();

  const words = normalized.split(' ').filter(w => w.length >= 2 && w.length <= 25);
  const tokens: string[] = [...words];

  // Word bigrams for syntactic pattern detection
  for (let i = 0; i < words.length - 1; i++) {
    tokens.push(`${words[i]}_${words[i + 1]}`);
  }

  // Evaluate and inject structural identity features
  const structuralEval = evaluateStructuralIdentity({
    from,
    fromDomain,
    replyTo: input.replyTo,
    returnPath: input.returnPath,
    auth: input.auth,
    domainIntelligence: input.domainIntelligence,
    hops: input.hops
  });

  tokens.push(...structuralEval.structuralTokens);

  // Linguistic semantic cues
  if (/(?:wire|direct deposit|payroll|w-2|gift card|invoice|remittance|swift transfer|routing number|escrow|bank details|ach debit)/i.test(combined)) {
    tokens.push('__cue_fraud_wire__');
  }
  if (/(?:urgent|immediate|account suspended|password expired|verify your identity|unauthorized access|restricted|unlock account|confirm credentials)/i.test(combined)) {
    tokens.push('__cue_phish_urgency__');
  }
  if (/(?:unsubscribe|newsletter|discount|promo|b2b leads|opt-out|voucher|cold outbound|pipeline|webinar)/i.test(combined)) {
    tokens.push('__cue_marketing_promo__');
  }
  if (/(?:github|commit|pull request|jira|slack|gitlab|standup|meeting notes|agenda|aws billing|cloud run|datadog|receipt)/i.test(combined)) {
    tokens.push('__cue_legitimate_work__');
  }

  return tokens;
}
