/**
 * TraceXMail Frontend API Client (Axios)
 * Multi-tenant organization headers, error handling, and typed REST methods.
 */

import axios, { AxiosInstance } from 'axios';

const DEFAULT_ORG_ID = 'org_acme_soc_01';

const API_URL = (
  (import.meta as any).env?.VITE_API_URL || ''
).replace(/\/$/, '');

export const apiClient: AxiosInstance = axios.create({
  baseURL: `${API_URL}/api`,
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json',
    'x-organization-id': DEFAULT_ORG_ID,
  },
});

// Response interceptor for unified error logging
apiClient.interceptors.response.use(
  (response) => response,
  (error) => {
    console.error('[TraceXMail API Error]', error.response?.data || error.message);
    return Promise.reject(error);
  }
);

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
};
