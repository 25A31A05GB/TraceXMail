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
  isBlacklisted?: boolean;
  isProxyOrVpn?: boolean;
  isOrigin?: boolean;
  infrastructureType?: string;
  is_vpn?: boolean;
  is_tor?: boolean;
  is_open_relay?: boolean;
  is_botnet_indicator?: boolean;
  is_cloud?: boolean;
  lookupMethod?: string;
  why?: WhyExplanation;
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
    status: 'PASS' | 'FAIL' | 'SOFTFAIL' | 'NEUTRAL' | 'NONE';
    record?: string;
    ip?: string;
    domain?: string;
    details?: string;
  };
  dkim: {
    status: 'PASS' | 'FAIL' | 'NONE' | 'INVALID';
    selector?: string;
    domain?: string;
    details?: string;
  };
  dmarc: {
    status: 'PASS' | 'FAIL' | 'QUARANTINE' | 'REJECT' | 'NONE';
    policy?: string;
    domain?: string;
    details?: string;
  };
  arc?: {
    status: 'PASS' | 'FAIL' | 'NONE';
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
  sessionId: string;
  trackingId: string;
  evidenceId?: string;
  sha256Hash?: string;
  custodyHash?: string;
  evidenceSource?: string;
  evidenceReceivedAt?: string;
  hashVerified?: boolean;
  name: string;
  analyzedAt: string;
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
  verdict: 'MALICIOUS PHISH' | 'SUSPICIOUS' | 'SPAM' | 'LEGITIMATE';
  mlConfidence: number; // e.g. 0.98
  rawEml: string;
  summary: string;
  why?: WhyExplanation;
  attributionWhy?: WhyExplanation;
  originWhy?: WhyExplanation;
  becWhy?: WhyExplanation;
  aiNarrative?: AINarrative | null;
  ai_narrative?: AINarrative | null;
  graph?: any;
  domain_intelligence?: any;
  isOfflineFallback?: boolean;
}

