import axios from 'axios';

export interface SlackConfig {
  webhookUrl: string;
  autoSendAlerts: boolean;
  minSeverity: 'ALL' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  channel?: string;
  username?: string;
}

export interface SlackDeliveryLog {
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
}

let slackConfig: SlackConfig = {
  webhookUrl: process.env.SLACK_WEBHOOK_URL || '',
  autoSendAlerts: true,
  minSeverity: 'MEDIUM',
  channel: '#soc-threat-alerts',
  username: 'TraceXMail SOC Engine'
};

const deliveryLogs: SlackDeliveryLog[] = [];

export function getSlackConfig(): SlackConfig {
  return { ...slackConfig };
}

export function updateSlackConfig(updates: Partial<SlackConfig>): SlackConfig {
  slackConfig = {
    ...slackConfig,
    ...updates
  };
  return { ...slackConfig };
}

export function getSlackDeliveries(): SlackDeliveryLog[] {
  return [...deliveryLogs];
}

export function maskWebhookUrl(url: string): string {
  if (!url) return 'Not Configured';
  try {
    const trimmed = url.trim();
    if (trimmed.length <= 15) return '***';
    const firstPart = trimmed.slice(0, 22);
    const lastPart = trimmed.slice(-6);
    return `${firstPart}...${lastPart}`;
  } catch {
    return '***';
  }
}

const SEVERITY_LEVELS: Record<string, number> = {
  ALL: 0,
  LOW: 1,
  MEDIUM: 2,
  HIGH: 3,
  CRITICAL: 4
};

export function shouldSendAlert(severity: string, minSeverity: string): boolean {
  const alertLevel = SEVERITY_LEVELS[severity?.toUpperCase()] ?? 2;
  const targetLevel = SEVERITY_LEVELS[minSeverity?.toUpperCase()] ?? 2;
  return alertLevel >= targetLevel;
}

export interface DispatchSlackParams {
  caseItem: {
    id: string;
    title: string;
    description?: string;
    severity: string;
    threat_score: number;
    status: string;
    assigned_user?: string;
    tags?: string[];
  };
  alertItem?: {
    id: string;
    title: string;
    description: string;
    severity: string;
    threat_score: number;
    category?: string;
  };
  fileName?: string;
  threatScore: number;
  verdict: string;
  from: string;
  to?: string;
  subject: string;
  fromDomain: string;
  primaryGeoHop?: {
    fromIp?: string;
    city?: string;
    country?: string;
    countryCode?: string;
    asn?: string;
    org?: string;
    isPrivate?: boolean;
    subnetType?: string;
  };
  domainIntelligence?: {
    domain: string;
    status: string;
    registrar?: string;
    creationDate?: string;
  };
  spfResult?: { result: string; details?: string };
  dmarcResult?: { result: string; details?: string };
  isTyposquat?: boolean;
  torHop?: any;
}

export function buildSlackBlockKitPayload(params: DispatchSlackParams) {
  const {
    caseItem,
    alertItem,
    fileName = 'email_submission.eml',
    threatScore,
    verdict,
    from,
    to,
    subject,
    fromDomain,
    primaryGeoHop,
    domainIntelligence,
    spfResult,
    dmarcResult,
    isTyposquat,
    torHop
  } = params;

  const sev = caseItem.severity?.toUpperCase() || 'HIGH';
  const emoji = sev === 'CRITICAL' ? '🚨' : sev === 'HIGH' ? '⚠️' : sev === 'MEDIUM' ? '⚡' : '🔍';
  const alertTitle = alertItem?.title || `${emoji} [${sev}] Threat Detected: ${subject}`;

  const originIp = primaryGeoHop?.fromIp || '127.0.0.1';
  const originLoc = primaryGeoHop?.isPrivate 
    ? `${primaryGeoHop.subnetType || 'RFC 1918 Private LAN'}`
    : `${primaryGeoHop?.city || 'Public Transit'}, ${primaryGeoHop?.country || 'Global Internet'}`;

  const domainStatus = domainIntelligence?.status ? domainIntelligence.status.toUpperCase() : 'RESOLVED';
  const authStatus = `SPF: *${spfResult?.result?.toUpperCase() || 'PASS'}* | DMARC: *${dmarcResult?.result?.toUpperCase() || 'PASS'}*`;

  const threatType = isTyposquat 
    ? '🚨 Lookalike Typosquatting Domain'
    : torHop 
    ? '⚠️ Tor Exit Node Routing'
    : threatScore >= 75 
    ? '🔥 High-Risk Phishing Lure'
    : '🛡️ Forensic RFC822 Record';

  return {
    text: `${emoji} [TraceXMail SOC Alert] ${alertTitle} - Risk Score: ${threatScore}/100`,
    blocks: [
      {
        type: 'header',
        text: {
          type: 'plain_text',
          text: `🛡️ TraceXMail Forensic Threat Alert`,
          emoji: true
        }
      },
      {
        type: 'section',
        text: {
          type: 'mrkdwn',
          text: `*${alertTitle}*\n*Case ID:* \`${caseItem.id}\` | *Severity:* *${sev}* | *Risk Score:* *${threatScore}/100*\n*Verdict:* \`${verdict}\`\n*Category:* ${threatType}`
        }
      },
      {
        type: 'divider'
      },
      {
        type: 'section',
        fields: [
          {
            type: 'mrkdwn',
            text: `*Sender Address:*\n\`${from}\``
          },
          {
            type: 'mrkdwn',
            text: `*Recipient:*\n\`${to || 'SOC Quarantine Mailbox'}\``
          },
          {
            type: 'mrkdwn',
            text: `*Origin Hop & Geolocation:*\n\`${originIp}\`\n_${originLoc}_`
          },
          {
            type: 'mrkdwn',
            text: `*Domain & Auth Status:*\n\`${fromDomain}\` (${domainStatus})\n${authStatus}`
          }
        ]
      },
      ...(caseItem.description ? [
        {
          type: 'section',
          text: {
            type: 'mrkdwn',
            text: `*Forensic Summary:*\n>${caseItem.description.replace(/\n/g, '\n>')}`
          }
        }
      ] : []),
      {
        type: 'context',
        elements: [
          {
            type: 'mrkdwn',
            text: `🕒 *Analyzed At:* ${new Date().toUTCString()} | *Evidence File:* \`${fileName}\` | *Engine:* \`TraceXMail v2.2\``
          }
        ]
      }
    ]
  };
}

export async function dispatchSlackCaseAlert(params: DispatchSlackParams): Promise<SlackDeliveryLog> {
  const { caseItem, alertItem, subject, threatScore } = params;
  const config = getSlackConfig();
  const severity = caseItem.severity || 'HIGH';

  const logId = `slack_log_${Date.now()}_${Math.random().toString(36).slice(2, 6)}`;
  const payload = buildSlackBlockKitPayload(params);

  // Check if auto-send is enabled and severity satisfies threshold
  if (!config.autoSendAlerts) {
    const log: SlackDeliveryLog = {
      id: logId,
      timestamp: new Date().toISOString(),
      case_id: caseItem.id,
      alert_id: alertItem?.id,
      subject,
      severity,
      threat_score: threatScore,
      status: 'SKIPPED_SEVERITY',
      error: 'Auto-send is disabled in Slack settings',
      webhook_url_masked: maskWebhookUrl(config.webhookUrl),
      payload_preview: payload
    };
    deliveryLogs.unshift(log);
    if (deliveryLogs.length > 100) deliveryLogs.pop();
    return log;
  }

  if (!shouldSendAlert(severity, config.minSeverity)) {
    const log: SlackDeliveryLog = {
      id: logId,
      timestamp: new Date().toISOString(),
      case_id: caseItem.id,
      alert_id: alertItem?.id,
      subject,
      severity,
      threat_score: threatScore,
      status: 'SKIPPED_SEVERITY',
      error: `Severity ${severity} does not meet minimum threshold ${config.minSeverity}`,
      webhook_url_masked: maskWebhookUrl(config.webhookUrl),
      payload_preview: payload
    };
    deliveryLogs.unshift(log);
    if (deliveryLogs.length > 100) deliveryLogs.pop();
    return log;
  }

  // If webhook URL is not configured
  if (!config.webhookUrl || !config.webhookUrl.trim().startsWith('http')) {
    const log: SlackDeliveryLog = {
      id: logId,
      timestamp: new Date().toISOString(),
      case_id: caseItem.id,
      alert_id: alertItem?.id,
      subject,
      severity,
      threat_score: threatScore,
      status: 'UNCONFIGURED_WEBHOOK',
      error: 'Slack Webhook URL is not configured. Set SLACK_WEBHOOK_URL or configure in Alerts/Settings.',
      webhook_url_masked: 'Not Configured',
      payload_preview: payload
    };
    deliveryLogs.unshift(log);
    if (deliveryLogs.length > 100) deliveryLogs.pop();
    console.log(`[Slack Dispatch Simulated] Webhook not configured. Alert for case "${caseItem.id}" logged to delivery vault.`);
    return log;
  }

  // Send real HTTP POST to Slack Webhook
  try {
    const response = await axios.post(config.webhookUrl, payload, {
      headers: { 'Content-Type': 'application/json' },
      timeout: 8000
    });

    const log: SlackDeliveryLog = {
      id: logId,
      timestamp: new Date().toISOString(),
      case_id: caseItem.id,
      alert_id: alertItem?.id,
      subject,
      severity,
      threat_score: threatScore,
      status: 'DELIVERED',
      status_code: response.status,
      webhook_url_masked: maskWebhookUrl(config.webhookUrl),
      payload_preview: payload
    };

    deliveryLogs.unshift(log);
    if (deliveryLogs.length > 100) deliveryLogs.pop();
    console.log(`[Slack Dispatch Success] Dispatched alert for case "${caseItem.id}" to Slack (${response.status} OK).`);
    return log;
  } catch (err: any) {
    const errorMsg = err.response?.data || err.message || 'Network error delivering to Slack webhook';
    const statusCode = err.response?.status;

    const log: SlackDeliveryLog = {
      id: logId,
      timestamp: new Date().toISOString(),
      case_id: caseItem.id,
      alert_id: alertItem?.id,
      subject,
      severity,
      threat_score: threatScore,
      status: 'FAILED',
      status_code: statusCode,
      error: typeof errorMsg === 'string' ? errorMsg : JSON.stringify(errorMsg),
      webhook_url_masked: maskWebhookUrl(config.webhookUrl),
      payload_preview: payload
    };

    deliveryLogs.unshift(log);
    if (deliveryLogs.length > 100) deliveryLogs.pop();
    console.warn(`[Slack Dispatch Failed] Failed to dispatch alert for case "${caseItem.id}" to Slack:`, errorMsg);
    return log;
  }
}

export async function sendTestSlackAlert(targetWebhookUrl?: string): Promise<{
  success: boolean;
  status: string;
  statusCode?: number;
  message: string;
  log: SlackDeliveryLog;
}> {
  const urlToUse = targetWebhookUrl?.trim() || slackConfig.webhookUrl;

  const testParams: DispatchSlackParams = {
    caseItem: {
      id: `case-test-${Date.now()}`,
      title: '🚨 [TEST ALERT] Targeted Executive Impersonation (Wire Fraud Lure)',
      description: 'Synthetic validation test triggered by SOC analyst to verify Slack alert channel dispatch and Block Kit formatting.',
      severity: 'CRITICAL',
      threat_score: 95,
      status: 'OPEN',
      assigned_user: 'Lead SOC Analyst'
    },
    alertItem: {
      id: `alt_test_${Date.now()}`,
      title: '🚨 [CRITICAL] Synthetic SOC Alert Dispatch Test',
      description: 'Verifying end-to-end integration with Slack incoming webhooks.',
      severity: 'CRITICAL',
      threat_score: 95,
      category: 'TEST_DISPATCH'
    },
    fileName: 'synthetic_bec_wire_lure.eml',
    threatScore: 95,
    verdict: 'MALICIOUS (PHISHING & BEC)',
    from: '"Chief Financial Officer" <cfo-office@secure-exec-payroll.com>',
    to: 'finance-desk@enterprise-corp.sec',
    subject: 'URGENT: Verify Updated Wire Transfer Instructions for Q3 Settlement',
    fromDomain: 'secure-exec-payroll.com',
    primaryGeoHop: {
      fromIp: '185.220.101.5',
      city: 'Sofia',
      country: 'Bulgaria',
      countryCode: 'BG',
      asn: 'AS200548',
      org: 'Zettahost Cyber Ltd',
      isPrivate: false
    },
    domainIntelligence: {
      domain: 'secure-exec-payroll.com',
      status: 'active',
      registrar: 'NameCheap Inc.',
      creationDate: '2026-08-15'
    },
    spfResult: { result: 'FAIL', details: 'IP 185.220.101.5 not authorized by domain SPF record' },
    dmarcResult: { result: 'FAIL', details: 'DMARC alignment failed: p=reject' },
    isTyposquat: true,
    torHop: { fromIp: '185.220.101.5' }
  };

  const payload = buildSlackBlockKitPayload(testParams);
  const logId = `slack_test_${Date.now()}`;

  if (!urlToUse || !urlToUse.startsWith('http')) {
    const log: SlackDeliveryLog = {
      id: logId,
      timestamp: new Date().toISOString(),
      case_id: testParams.caseItem.id,
      alert_id: testParams.alertItem?.id,
      subject: testParams.subject,
      severity: 'CRITICAL',
      threat_score: 95,
      status: 'UNCONFIGURED_WEBHOOK',
      error: 'Slack Webhook URL is empty or invalid. Please provide a valid https://hooks.slack.com/... URL.',
      webhook_url_masked: 'Not Configured',
      payload_preview: payload
    };
    deliveryLogs.unshift(log);
    return {
      success: false,
      status: 'UNCONFIGURED_WEBHOOK',
      message: 'Slack Webhook URL is not configured. Please paste your Incoming Webhook URL to test.',
      log
    };
  }

  try {
    const res = await axios.post(urlToUse, payload, {
      headers: { 'Content-Type': 'application/json' },
      timeout: 8000
    });

    const log: SlackDeliveryLog = {
      id: logId,
      timestamp: new Date().toISOString(),
      case_id: testParams.caseItem.id,
      alert_id: testParams.alertItem?.id,
      subject: testParams.subject,
      severity: 'CRITICAL',
      threat_score: 95,
      status: 'DELIVERED',
      status_code: res.status,
      webhook_url_masked: maskWebhookUrl(urlToUse),
      payload_preview: payload
    };
    deliveryLogs.unshift(log);

    return {
      success: true,
      status: 'DELIVERED',
      statusCode: res.status,
      message: 'Test notification successfully delivered to Slack channel!',
      log
    };
  } catch (err: any) {
    const errorMsg = err.response?.data || err.message || 'Error delivering to Slack';
    const log: SlackDeliveryLog = {
      id: logId,
      timestamp: new Date().toISOString(),
      case_id: testParams.caseItem.id,
      alert_id: testParams.alertItem?.id,
      subject: testParams.subject,
      severity: 'CRITICAL',
      threat_score: 95,
      status: 'FAILED',
      status_code: err.response?.status,
      error: typeof errorMsg === 'string' ? errorMsg : JSON.stringify(errorMsg),
      webhook_url_masked: maskWebhookUrl(urlToUse),
      payload_preview: payload
    };
    deliveryLogs.unshift(log);

    return {
      success: false,
      status: 'FAILED',
      statusCode: err.response?.status,
      message: `Failed to deliver test alert to Slack: ${typeof errorMsg === 'string' ? errorMsg : JSON.stringify(errorMsg)}`,
      log
    };
  }
}
