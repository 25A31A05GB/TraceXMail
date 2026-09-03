export interface WhyExplanation {
  why: string;
  evidence_chain: string[];
  confidence: number;
  limitation: string;
}

export interface EmailHop {
  hopNumber: number;
  fromHost?: string;
  fromIp?: string;
  byHost?: string;
  protocol?: string;
  timestamp?: string;
  delaySec?: number;
  city?: string;
  country?: string;
  countryCode?: string;
  lat?: number;
  lng?: number;
  asn?: string;
  org?: string;
  isp?: string;
  region?: string;
  reverseDns?: string;
  abuseScore?: number;
  abuseStatus?: string;
  isBlacklisted?: boolean;
  isProxyOrVpn?: boolean;
  isOrigin?: boolean;
  isPublicGateway?: boolean;
  isPrivate?: boolean;
  isRfc1918?: boolean;
  subnetType?: string;
  cidr?: string;
  scope?: 'PRIVATE_LAN' | 'PUBLIC_INTERNET' | 'LOOPBACK' | 'LINK_LOCAL' | 'UNMAPPED';
  subnetDescription?: string;
  infrastructureType?: string;
  is_vpn?: boolean;
  is_tor?: boolean;
  is_open_relay?: boolean;
  is_botnet_indicator?: boolean;
  is_cloud?: boolean;
  lookupMethod?: string;
  why?: WhyExplanation;
  geonameId?: number;
  continentCode?: string;
  continentName?: string;
  timeZone?: string;
  isInEuropeanUnion?: boolean;
  accuracyRadius?: number;
  maxmindVerified?: boolean;
  maxmindSource?: string;
  maxmindCopyright?: string;
  maxmindLicense?: string;
}

export interface DomainMxRecord {
  priority: number;
  host: string;
  ip?: string;
  status?: string;
}

export interface DomainIntelligence {
  domain: string;
  status?: string;
  error?: string;
  from_cache?: boolean;
  registrar?: string;
  created_date?: string;
  expiration_date?: string;
  domain_age_days?: number;
  is_newly_registered?: boolean;
  is_typosquat?: boolean;
  typosquat_matched_brand?: string;
  typosquatting?: {
    is_typosquat: boolean;
    target_brand?: string;
    distance?: number;
    similarity_score?: number;
    is_exact_match?: boolean;
    reasons?: string[];
    technique?: string;
  };
  rdap?: {
    domain?: string;
    registrar?: string;
    creation_date?: string;
    expiration_date?: string;
    updated_date?: string;
    domain_age_days?: number;
    is_newly_registered?: boolean;
    nameservers?: string[];
    rdap_status?: string[];
    status?: string;
  };
  dns?: {
    domain?: string;
    ns?: string[];
    a?: string[];
    aaaa?: string[];
    a_records?: string[];
    mx?: string[];
    mx_records?: DomainMxRecord[];
    txt?: string[];
    spf?: string;
    spf_qualifier?: string;
    spf_mechanisms?: string[];
    dmarc?: string;
    dmarc_policy?: string;
    dmarc_sp?: string;
    dmarc_pct?: number;
    dmarc_rua?: string;
    dmarc_enforcement?: string;
    dnssec?: string;
  };
  mx_records?: string[];
  mx_missing?: boolean;
  spf_record?: string | null;
  spf_missing?: boolean;
  dmarc_record?: string | null;
  dmarc_missing?: boolean;
  nameservers?: string[];
  a_records?: string[];
  flags?: string[];
  risk_flags?: string[];
  lookup_method?: string;
}

export type Hop = EmailHop;

export interface ExtractedUrl {
  url: string;
  defangedUrl: string;
  domain: string;
  status: 'MALICIOUS' | 'SUSPICIOUS' | 'CLEAN' | 'UNRATED';
  virustotalScore?: string;
  category?: string;
  redirectsTo?: string;
}

export interface AttachmentInfo {
  filename: string;
  size: string;
  mimeType: string;
  sha256: string;
  md5: string;
  status: 'CLEAN' | 'MALICIOUS' | 'SUSPICIOUS';
  vtDetection?: string;
}

export interface AuthResults {
  spf: {
    status: 'PASS' | 'FAIL' | 'SOFTFAIL' | 'NEUTRAL' | 'NONE' | 'TEMPERROR' | 'PERMERROR';
    record?: string;
    ip?: string;
    domain?: string;
    details?: string;
  };
  dkim: {
    status: 'PASS' | 'FAIL' | 'NONE' | 'INVALID' | 'NEUTRAL' | 'TEMPERROR' | 'PERMERROR';
    selector?: string;
    domain?: string;
    details?: string;
  };
  dmarc: {
    status: 'PASS' | 'FAIL' | 'QUARANTINE' | 'REJECT' | 'NONE' | 'TEMPERROR' | 'PERMERROR';
    policy?: string;
    domain?: string;
    details?: string;
  };
  arc?: {
    status: 'PASS' | 'FAIL' | 'NONE';
    details?: string;
  };
}

export interface HeuristicSignal {
  id: string;
  title: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  description: string;
  triggered: boolean;
  score?: number;
  why?: WhyExplanation;
}

export interface ForensicLogEntry {
  id: string;
  timestamp: string;
  tag: 'INIT' | 'DNS' | 'SEC' | 'API' | 'ML' | 'GRAPH' | 'INFO' | 'WARN' | 'ALERT';
  message: string;
  highlight?: boolean;
}

export interface EvidenceVaultRecord {
  evidence_id: string;
  sha256_hash: string;
  recomputed_sha256?: string;
  hash_verified?: boolean;
  match?: boolean;
  tamper_detected?: boolean;
  source: 'email_upload' | 'api' | 'forwarded' | 'gateway_webhook' | string;
  filename: string;
  file_size: number;
  organization_id?: string;
  case_id?: string;
  evidence_type?: string;
  notes?: string;
  received_at: string;
  created_at?: string;
  custody_chain?: Array<{
    action: string;
    timestamp: string;
    actor: string;
    sha256?: string;
    recomputed_sha256?: string;
    result?: string;
  }>;
}

export interface AINarrative {
  narrative: string;
  model: string;
  source: string;
  disclaimer: string;
}

export interface EmailAnalysis {
  id: string;
  sessionId?: string;
  trackingId?: string;
  evidenceId?: string;
  sha256Hash?: string;
  sha256?: string;
  custodyHash?: string;
  evidenceSource?: string;
  evidenceReceivedAt?: string;
  hashVerified?: boolean;
  name?: string;
  analyzedAt?: string;
  subject?: string;
  from?: string;
  to?: string;
  replyTo?: string;
  returnPath?: string;
  date?: string;
  messageId?: string;
  threatVerdict?: string;
  threatScore?: number;
  threatScoreBreakdown?: {
    total: number;
    maxScore: number;
    components: {
      authentication: { score: number; max: number; reasons: string[] };
      domainRisk: { score: number; max: number; reasons: string[] };
      infrastructureRisk: { score: number; max: number; reasons: string[] };
      mlClassification: { score: number; max: number; reasons: string[] };
      heuristics: { score: number; max: number; reasons: string[] };
    };
  };
  classification?: string;
  probabilities?: Record<string, number>;
  phishingProbability?: number;
  rawHeaders?: string;
  authResults?: AuthResults;
  heuristicSignals?: HeuristicSignal[];
  headers: {
    subject: string;
    from: string;
    fromEmail: string;
    fromName: string;
    to: string;
    replyTo?: string;
    returnPath?: string;
    date: string;
    messageId: string;
    contentType?: string;
    userAgent?: string;
    xMailer?: string;
    priority?: string;
    allHeaders: Record<string, string>;
  };
  auth: AuthResults;
  hops: EmailHop[];
  urls: ExtractedUrl[];
  attachments: AttachmentInfo[];
  heuristics: HeuristicSignal[];
  logs: ForensicLogEntry[];
  riskScore: number; // 0 to 100
  verdict: 'MALICIOUS PHISH' | 'SUSPICIOUS' | 'SPAM' | 'LEGITIMATE' | string;
  mlConfidence: number; // e.g. 0.98
  rawEml: string;
  summary: string;
  domain_intelligence?: DomainIntelligence;
  domainIntelligence?: DomainIntelligence;
  maxmindIntelligence?: {
    geonameId?: number;
    city?: string;
    region?: string;
    country?: string;
    countryCode?: string;
    continentCode?: string;
    continentName?: string;
    timeZone?: string;
    isInEuropeanUnion?: boolean;
    lat?: number;
    lng?: number;
    accuracyRadius?: number;
    asn?: string;
    asnOrg?: string;
    sourceFile?: string;
    copyright?: string;
    license?: string;
    isVerified?: boolean;
    filesFound?: string[];
  };
  why?: WhyExplanation;
  attributionWhy?: WhyExplanation;
  originWhy?: WhyExplanation;
  becWhy?: WhyExplanation;
  aiNarrative?: AINarrative | null;
  ai_narrative?: AINarrative | null;
  graph?: any;
  isOfflineFallback?: boolean;
}

export interface EvidenceCardData {
  caseId: string;
  evidenceId: string;
  timestamp: string;
  verdict: {
    text: string;
    status: 'bad' | 'warn' | 'good' | string;
    scoreLabel: string;
  };
  subject: string;
  identityRows: Array<{
    k: string;
    v: string;
    status?: 'bad' | 'warn' | 'good' | string;
  }>;
  checks: Array<{
    label: string;
    value: string;
    status: 'pass' | 'fail' | 'warn' | string;
  }>;
  origin?: {
    sectionTitle: string;
    ip: string;
    ipStatus?: 'bad' | 'warn' | 'good' | string;
    location: string;
    mapsUrl?: string;
    extraRows?: Array<{
      k: string;
      v: string;
      status?: 'bad' | 'warn' | 'good' | string;
    }>;
  };
  relay?: {
    chain: string;
    graphUrl?: string;
  };
  entity?: {
    sectionTitle: string;
    rows: Array<{
      k: string;
      v: string;
      status?: 'bad' | 'warn' | 'good' | string;
    }>;
    flags?: Array<{
      text: string;
      level?: 'red' | 'amber' | 'green' | string;
    }>;
  };
  aiSummary?: {
    text: string;
    engine: string;
    fullUrl?: string;
  };
  findings?: Array<{
    label: string;
    badge: string;
    status: 'mal' | 'clean' | 'warn' | string;
  }>;
  score?: {
    label: string;
    percent: number;
    resultText: string;
    resultLabel: string;
    good?: boolean;
  };
  footer?: {
    hashLabel: string;
    hash: string;
    actionLabel: string;
    action: string;
    actionGood?: boolean;
  };
}

