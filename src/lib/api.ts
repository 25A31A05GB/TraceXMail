/**
 * TraceXMail Frontend API Client (Axios)
 * Multi-tenant organization headers, error handling, and typed REST methods.
 */

import axios, { AxiosInstance } from 'axios';

const DEFAULT_ORG_ID = 'org_acme_soc_01';

export const API_URL = (
  (import.meta as any).env?.VITE_API_URL || ''
).replace(/\/$/, '');

export interface SessionUser {
  userId: string;
  email: string;
  organizationId: string;
  role: 'admin' | 'analyst' | 'read_only' | string;
  label?: string;
  authMethod?: string;
}

// In-Memory Session Storage (Complies with security audit: NEVER store in localStorage)
let memorySessionToken: string | null = null;
let memorySessionUser: SessionUser | null = null;
let sessionInitPromise: Promise<{ token: string; user: SessionUser | null }> | null = null;

type SessionListener = (session: { token: string | null; user: SessionUser | null }) => void;
const sessionListeners = new Set<SessionListener>();

export function getSessionToken(): string | null {
  return memorySessionToken;
}

export function getSessionUser(): SessionUser | null {
  return memorySessionUser;
}

export function setSession(token: string | null, user: SessionUser | null) {
  memorySessionToken = token;
  memorySessionUser = user;
  sessionListeners.forEach(fn => fn({ token, user }));
}

export function subscribeSession(listener: SessionListener): () => void {
  sessionListeners.add(listener);
  listener({ token: memorySessionToken, user: memorySessionUser });
  return () => {
    sessionListeners.delete(listener);
  };
}

/**
 * Lightweight session acquisition:
 * Obtains a default demo analyst JWT session on first load if no token exists in memory.
 */
export async function initializeSession(role: 'admin' | 'analyst' | 'read_only' = 'analyst'): Promise<{ token: string; user: SessionUser | null }> {
  if (memorySessionToken && memorySessionUser && memorySessionUser.role === role) {
    return { token: memorySessionToken, user: memorySessionUser };
  }

  if (sessionInitPromise) {
    return sessionInitPromise;
  }

  sessionInitPromise = (async () => {
    try {
      const res = await fetch(`${API_URL}/api/auth/session`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-organization-id': DEFAULT_ORG_ID
        },
        body: JSON.stringify({ role, organization_id: DEFAULT_ORG_ID })
      });
      if (res.ok) {
        const data = await res.json();
        memorySessionToken = data.token;
        memorySessionUser = data.user;
        sessionListeners.forEach(fn => fn({ token: memorySessionToken, user: memorySessionUser }));
        return { token: data.token, user: data.user };
      }
    } catch (err) {
      console.warn('[Session] Failed initializing default demo session:', err);
    } finally {
      sessionInitPromise = null;
    }
    return { token: '', user: null };
  })();

  return sessionInitPromise;
}

// Auto-trigger session initialization in background on client startup
if (typeof window !== 'undefined') {
  initializeSession().catch(console.warn);
}

export const apiClient: AxiosInstance = axios.create({
  baseURL: `${API_URL}/api`,
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json',
    'x-organization-id': DEFAULT_ORG_ID,
  },
});

// Request interceptor: attaches the verified JWT token to all outbound Axios calls
apiClient.interceptors.request.use(async (config) => {
  if (!memorySessionToken) {
    await initializeSession();
  }
  if (memorySessionToken) {
    config.headers.set('Authorization', `Bearer ${memorySessionToken}`);
  }
  if (!config.headers.has('x-organization-id')) {
    config.headers.set('x-organization-id', DEFAULT_ORG_ID);
  }
  return config;
});

// Response interceptor for unified error logging
apiClient.interceptors.response.use(
  (response) => response,
  (error) => {
    const status = error.response?.status;
    const responseData = error.response?.data;
    let errorMessage = 'API Request Failed';

    if (typeof responseData === 'string') {
      errorMessage = responseData;
    } else if (responseData && typeof responseData === 'object') {
      errorMessage = responseData.error || responseData.message || JSON.stringify(responseData);
    } else if (error.message) {
      errorMessage = error.message;
    }

    if (status === 429 || errorMessage.toLowerCase().includes('rate limit') || errorMessage.toLowerCase().includes('rate exceeded')) {
      console.warn('[TraceXMail API Warning] Rate limit encountered:', errorMessage);
    } else {
      console.error('[TraceXMail API Error]', errorMessage);
    }
    return Promise.reject(error);
  }
);

/**
 * Centralized fetch wrapper that automatically injects the active session's
 * Authorization: Bearer <token> and organization headers.
 */
export async function apiFetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
  if (!memorySessionToken) {
    await initializeSession();
  }

  const headers = new Headers(init?.headers);
  if (memorySessionToken && !headers.has('Authorization')) {
    headers.set('Authorization', `Bearer ${memorySessionToken}`);
  }
  if (!headers.has('x-organization-id')) {
    headers.set('x-organization-id', DEFAULT_ORG_ID);
  }

  return fetch(input, {
    ...init,
    headers
  });
}

export interface HealthResponse {
  status: string;
  service: string;
  version: string;
  database: {
    dialect: string;
    supabase_connected: boolean;
    tables_count: number;
    tenant_tables_with_rls: number;
    rls_policy: string;
  };
  default_tenant: {
    organization_id: string | null;
    organization_name: string | null;
    default_user_email: string | null;
    default_user_role: string | null;
  };
  records: {
    cases_count: number;
    campaigns_count: number;
  };
  timestamp: string;
}

export interface DashboardStats {
  summary: {
    total_cases: number;
    real_cases_count?: number;
    demo_cases_count?: number;
    total_emails_ingested: number;
    active_campaigns: number;
    active_alerts: number;
    threat_distribution: {
      CRITICAL: number;
      HIGH: number;
      MEDIUM: number;
      LOW: number;
      CLEAN: number;
    };
    average_threat_score: number;
  };
  threat_actors: Array<{
    name: string;
    campaign_count: number;
    target: string;
    status: string;
  }>;
  recent_alerts: Array<{
    id: string;
    title: string;
    description: string;
    severity: string;
    status: string;
    created_at: string;
  }>;
}

export interface CaseItem {
  id: string;
  title: string;
  description?: string;
  status: string;
  severity: string;
  threat_score: number;
  created_at?: string;
  tags?: string[];
  assigned_user?: string;
  is_demo?: boolean;
  source?: string;
  ml_confidence?: number;
  phishing_probability?: number;
}

export interface CampaignRelationship {
  rule: string;
  strength: 'STRONG' | 'MEDIUM' | 'WEAK';
  description: string;
  value?: string;
  similarity?: number;
  auto_merge_eligible?: boolean;
}

export interface CampaignItem {
  id: string;
  name: string;
  threat_actor: string;
  target_industry: string;
  status: string;
  total_emails: number;
  member_email_ids?: string[];
  first_seen?: string;
  last_seen?: string;
  notes?: string;
  shared_evidence?: CampaignRelationship[];
  possible_related?: Array<{
    email_id: string;
    subject: string;
    relationship_strength: 'STRONG' | 'MEDIUM' | 'WEAK';
    similarity_score: number;
    reason: string;
  }>;
}

export interface TimelineEvent {
  date: string;
  domain: string;
  ip: string;
  email_id: string;
  subject?: string;
  sender?: string;
  asn?: string;
  asn_org?: string;
  infrastructure_type?: string;
  change_event: string;
  is_infrastructure_move?: boolean;
  notes?: string;
}

export interface InfrastructureMove {
  type: string;
  subtype?: string;
  domain?: string;
  from_ip?: string;
  to_ip?: string;
  ip?: string;
  from_asn?: string;
  to_asn?: string;
  email_id?: string;
  date?: string;
  description: string;
}

export interface CampaignTimelineResponse {
  campaign_id?: string;
  timeline: TimelineEvent[];
  total_events: number;
  infrastructure_moves: InfrastructureMove[];
  moves_count: number;
  has_infrastructure_moves: boolean;
  first_seen?: string;
  last_seen?: string;
  domain_ip_mappings?: Record<string, string[]>;
  churn_analysis?: Record<string, {
    distinct_ips_count: number;
    distinct_ips: string[];
    is_high_churn: boolean;
    assessment: string;
  }>;
}

export interface SearchResults {
  query: string;
  total_results: number;
  results: {
    cases: CaseItem[];
    emails: Array<{
      id: string;
      subject: string;
      sender: string;
      recipient: string;
      date: string;
    }>;
    urls: Array<{
      id: string;
      url: string;
    }>;
    iocs: Array<{
      id: string;
      type: string;
      value: string;
      reputation: string;
    }>;
  };
}

export const forensicApi = {
  // System Health
  getHealth: async (): Promise<HealthResponse> => {
    const res = await apiClient.get<HealthResponse>('/health');
    return res.data;
  },

  // Dashboard Stats
  getDashboardStats: async (): Promise<DashboardStats> => {
    const res = await apiClient.get<DashboardStats>('/stats');
    return res.data;
  },

  // Cases Management
  getCases: async (params?: { exclude_demo?: boolean; real_only?: boolean; mask_pii?: boolean; organization_id?: string }): Promise<CaseItem[]> => {
    const queryParams = {
      exclude_demo: params?.exclude_demo !== undefined ? params.exclude_demo : true,
      ...params
    };
    const res = await apiClient.get<CaseItem[]>('/cases', { params: queryParams });
    return res.data;
  },

  getCase: async (caseId: string): Promise<any> => {
    const res = await apiClient.get(`/cases/${caseId}`);
    return res.data;
  },

  createCase: async (caseData: { title: string; description?: string; severity?: string; threat_score?: number }): Promise<CaseItem> => {
    const res = await apiClient.post<CaseItem>('/cases', caseData);
    return res.data;
  },

  updateCase: async (caseId: string, updates: { status?: string; notes?: string; analyst_notes?: string; severity?: string; tags?: string[] }): Promise<CaseItem> => {
    const res = await apiClient.patch<CaseItem>(`/cases/${caseId}`, updates);
    return res.data;
  },

  deleteCase: async (caseId: string): Promise<any> => {
    const res = await apiClient.delete(`/cases/${caseId}`);
    return res.data;
  },

  addEmailsToCase: async (caseId: string, emailIds: string[]): Promise<any> => {
    const res = await apiClient.post(`/cases/${caseId}/emails`, { email_ids: emailIds });
    return res.data;
  },

  // Campaigns Management
  getCampaigns: async (): Promise<CampaignItem[]> => {
    const res = await apiClient.get<CampaignItem[]>('/campaigns');
    return res.data;
  },

  getCampaignDetail: async (campaignId: string): Promise<any> => {
    const res = await apiClient.get(`/campaigns/${campaignId}`);
    return res.data;
  },

  getCampaignTimeline: async (campaignId: string): Promise<CampaignTimelineResponse> => {
    const res = await apiClient.get<CampaignTimelineResponse>(`/campaigns/${campaignId}/timeline`);
    return res.data;
  },

  getTemporalAnalysis: async (params?: { domain?: string; ip?: string; campaign_id?: string }): Promise<CampaignTimelineResponse> => {
    const res = await apiClient.get<CampaignTimelineResponse>('/temporal-analysis', { params });
    return res.data;
  },

  getCampaignCandidates: async (emailId: string): Promise<any> => {
    const res = await apiClient.get(`/emails/${emailId}/campaign-candidates`);
    return res.data;
  },

  addCampaignMembers: async (campaignId: string, emailIds: string[]): Promise<any> => {
    const res = await apiClient.post(`/campaigns/${campaignId}/members`, { email_ids: emailIds });
    return res.data;
  },

  createCampaign: async (campaign: { name: string; threat_actor?: string; target_industry?: string; notes?: string; email_ids?: string[] }): Promise<any> => {
    const res = await apiClient.post('/campaigns', campaign);
    return res.data;
  },

  // Global Search
  search: async (query: string): Promise<SearchResults> => {
    const res = await apiClient.get<SearchResults>(`/search?q=${encodeURIComponent(query)}`);
    return res.data;
  },

  // Ingest & Samples
  getSamples: async (): Promise<any[]> => {
    const res = await apiClient.get('/samples');
    return res.data;
  },

  analyzeSample: async (filename: string): Promise<any> => {
    const res = await apiClient.get(`/samples/${filename}`);
    return res.data;
  },

  ingestRaw: async (rawContent: string, filename = 'manual.eml'): Promise<any> => {
    const res = await apiClient.post('/analyze/raw', { raw_content: rawContent, filename });
    return res.data;
  },

  // Alerts & Telemetry
  getAlerts: async (): Promise<any[]> => {
    const res = await apiClient.get('/alerts');
    return res.data;
  },

  markAlertRead: async (alertId: string): Promise<any> => {
    const res = await apiClient.patch(`/alerts/${alertId}/read`);
    return res.data;
  },

  markAllAlertsRead: async (): Promise<any> => {
    const res = await apiClient.post('/alerts/mark-all-read');
    return res.data;
  },

  broadcastAlert: async (alertData: { title: string; description: string; severity?: string; category?: string }): Promise<any> => {
    const res = await apiClient.post('/alerts/broadcast', alertData);
    return res.data;
  },

  // Slack SOC Integration
  getSlackStatus: async (): Promise<{
    status: string;
    configured: boolean;
    webhook_url_masked: string;
    auto_send: boolean;
    min_severity: string;
    channel?: string;
    username?: string;
    total_deliveries: number;
    recent_deliveries: Array<{
      id: string;
      timestamp: string;
      case_id?: string;
      alert_id?: string;
      subject: string;
      severity: string;
      threat_score: number;
      status: 'DELIVERED' | 'FAILED' | 'SKIPPED_SEVERITY' | 'UNCONFIGURED_WEBHOOK';
      status_code?: number;
      error?: string;
      webhook_url_masked: string;
      payload_preview: any;
    }>;
  }> => {
    const res = await apiClient.get('/slack/status');
    return res.data;
  },

  updateSlackConfig: async (config: {
    webhook_url?: string;
    auto_send?: boolean;
    min_severity?: 'ALL' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
    channel?: string;
    username?: string;
  }): Promise<any> => {
    const res = await apiClient.post('/slack/config', config);
    return res.data;
  },

  testSlackWebhook: async (webhookUrl?: string): Promise<{
    success: boolean;
    status: string;
    statusCode?: number;
    message: string;
    log: any;
  }> => {
    const res = await apiClient.post('/slack/test', { webhook_url: webhookUrl });
    return res.data;
  },

  sendCaseToSlack: async (caseId: string): Promise<{ status: string; log: any }> => {
    const res = await apiClient.post(`/slack/send-case/${caseId}`);
    return res.data;
  },

  getSlackDeliveries: async (): Promise<any[]> => {
    const res = await apiClient.get('/slack/deliveries');
    return res.data;
  },

  // VirusTotal API Threat Intelligence Integration
  getVirusTotalStatus: async (): Promise<{
    configured: boolean;
    active: boolean;
    provider: string;
    endpoint: string;
    message: string;
    cacheStats?: { cachedUrls: number; cachedFiles: number };
  }> => {
    const res = await apiClient.get('/virustotal/status');
    return res.data;
  },

  lookupVirusTotalUrl: async (url: string, forceRefresh = false): Promise<any> => {
    const res = await apiClient.post('/virustotal/url', { url, force_refresh: forceRefresh });
    return res.data;
  },

  lookupVirusTotalFile: async (hash: string, forceRefresh = false): Promise<any> => {
    const res = await apiClient.post('/virustotal/file', { hash, force_refresh: forceRefresh });
    return res.data;
  },

  enrichVirusTotal: async (params: { caseId?: string; urls?: any[]; attachments?: any[]; existingLogs?: any[] }): Promise<{
    status: string;
    vt_active: boolean;
    is_configured?: boolean;
    message?: string;
    scanned_count: number;
    flagged_count: number;
    api_status?: {
      configured: boolean;
      provider: string;
      endpoint: string;
      message: string;
    };
    urls: any[];
    attachments: any[];
    logs: any[];
    new_vt_logs: any[];
  }> => {
    const res = await apiClient.post('/virustotal/enrich', {
      case_id: params.caseId,
      urls: params.urls,
      attachments: params.attachments,
      existing_logs: params.existingLogs
    });
    return res.data;
  },

  // Network Intelligence (Client / Session Telemetry)
  getNetworkInfo: async (forceRefresh = false): Promise<NetworkInfoData> => {
    const res = await apiClient.get('/network-info', {
      params: forceRefresh ? { force_refresh: 'true' } : undefined,
      headers: { 'Cache-Control': 'no-cache' }
    });
    return res.data;
  },

  measureLatency: async (): Promise<number> => {
    const start = performance.now();
    await fetch(`${API_URL}/api/network/ping`, { cache: 'no-store' });
    const end = performance.now();
    return Math.max(1, Math.round(end - start));
  },

  measureBandwidth: async (): Promise<{ durationMs: number; bytes: number; mbps: number }> => {
    const start = performance.now();
    const response = await fetch(`${API_URL}/api/network/bandwidth-payload`, { cache: 'no-store' });
    if (!response.ok) {
      throw new Error(`Bandwidth test failed with status ${response.status}`);
    }
    const buffer = await response.arrayBuffer();
    const end = performance.now();
    const durationMs = Math.max(1, end - start);
    const durationSec = durationMs / 1000;
    const bytes = buffer.byteLength;
    const bits = bytes * 8;
    const mbps = Number(((bits / durationSec) / (1024 * 1024)).toFixed(2));
    return { durationMs: Math.round(durationMs), bytes, mbps };
  },
};

export interface NetworkInfoData {
  ip: string;
  ipVersion: 'IPv4' | 'IPv6' | 'Unknown';
  city: string;
  region: string;
  country: string;
  organization: string;
  asn: string;
  serverLocation: string;
  source: string;
  isApproximate: boolean;
  disclaimer: string;
  cached?: boolean;
}

