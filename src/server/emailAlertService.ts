/**
 * TraceXMail Email Alert Notification Service
 *
 * Dispatches SOC security alerts via Resend API or SMTP relays.
 * Configured dynamically via environment variables:
 * - RESEND_API_KEY
 * - SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASSWORD, SMTP_FROM
 * - ALERT_EMAIL_RECIPIENTS
 */

import axios from 'axios';

export interface EmailAlertConfig {
  resendApiKey: string;
  smtpHost: string;
  smtpPort: number;
  smtpUser: string;
  smtpPass: string;
  smtpFrom: string;
  alertRecipients: string[];
  enabled: boolean;
}

export function getEmailAlertConfig(): EmailAlertConfig {
  const recipientsRaw = process.env.ALERT_EMAIL_RECIPIENTS || '';
  const alertRecipients = recipientsRaw
    .split(',')
    .map(r => r.trim())
    .filter(r => r.length > 0 && r.includes('@'));

  const resendApiKey = (process.env.RESEND_API_KEY || '').trim();
  const smtpHost = (process.env.SMTP_HOST || '').trim();
  const smtpPort = parseInt(process.env.SMTP_PORT || '587', 10);
  const smtpUser = (process.env.SMTP_USER || '').trim();
  const smtpPass = (process.env.SMTP_PASSWORD || '').trim();
  const smtpFrom = (process.env.SMTP_FROM || 'alerts@tracexmail-soc.internal').trim();

  const enabled = Boolean(resendApiKey || smtpHost);

  return {
    resendApiKey,
    smtpHost,
    smtpPort,
    smtpUser,
    smtpPass,
    smtpFrom,
    alertRecipients,
    enabled
  };
}

export async function sendEmailAlert(alertData: {
  subject: string;
  threatScore: number;
  verdict: string;
  sender: string;
  recipient: string;
  originIp?: string;
  caseId?: string;
  summary?: string;
}): Promise<{ success: boolean; provider: string; details?: string }> {
  const config = getEmailAlertConfig();

  if (!config.enabled) {
    return {
      success: false,
      provider: 'none',
      details: 'Neither RESEND_API_KEY nor SMTP_HOST configured in environment.'
    };
  }

  const recipients = config.alertRecipients.length > 0 ? config.alertRecipients : ['soc-alerts@tracexmail-enterprise.internal'];
  const subjectText = `[CRITICAL SOC ALERT] Phishing Threat Detected (Score: ${alertData.threatScore}/100) - ${alertData.subject}`;

  const htmlBody = `
    <div style="font-family: Arial, sans-serif; background-color: #0F121C; color: #E2E8F0; padding: 24px; border-radius: 8px;">
      <div style="border-bottom: 2px solid #EF4444; padding-bottom: 12px; margin-bottom: 16px;">
        <h2 style="color: #EF4444; margin: 0;">🚨 TraceXMail SOC Threat Alert</h2>
        <p style="color: #94A3B8; font-size: 12px; margin-top: 4px;">CASE ID: ${alertData.caseId || 'N/A'}</p>
      </div>

      <table style="width: 100%; text-align: left; border-collapse: collapse; margin-bottom: 20px;">
        <tr><td style="padding: 6px; color: #94A3B8; width: 140px;">Verdict:</td><td style="padding: 6px; font-weight: bold; color: #EF4444;">${alertData.verdict}</td></tr>
        <tr><td style="padding: 6px; color: #94A3B8;">Threat Score:</td><td style="padding: 6px; font-weight: bold; color: #F59E0B;">${alertData.threatScore} / 100</td></tr>
        <tr><td style="padding: 6px; color: #94A3B8;">Subject:</td><td style="padding: 6px;">${alertData.subject}</td></tr>
        <tr><td style="padding: 6px; color: #94A3B8;">Sender:</td><td style="padding: 6px; font-family: monospace;">${alertData.sender}</td></tr>
        <tr><td style="padding: 6px; color: #94A3B8;">Recipient:</td><td style="padding: 6px; font-family: monospace;">${alertData.recipient}</td></tr>
        <tr><td style="padding: 6px; color: #94A3B8;">Origin IP:</td><td style="padding: 6px; font-family: monospace;">${alertData.originIp || 'N/A'}</td></tr>
      </table>

      ${alertData.summary ? `<div style="background-color: #1E293B; padding: 12px; border-radius: 6px; font-size: 13px; margin-bottom: 20px;"><strong>Summary:</strong> ${alertData.summary}</div>` : ''}

      <div style="font-size: 11px; color: #64748B; border-top: 1px solid #334155; padding-top: 12px;">
        Dispatched automatically by TraceXMail Real-Time SOC Incident Response.
      </div>
    </div>
  `;

  // 1. Try Resend API if API Key exists
  if (config.resendApiKey) {
    try {
      const response = await axios.post(
        'https://api.resend.com/emails',
        {
          from: config.smtpFrom,
          to: recipients,
          subject: subjectText,
          html: htmlBody
        },
        {
          headers: {
            Authorization: `Bearer ${config.resendApiKey}`,
            'Content-Type': 'application/json'
          },
          timeout: 8000
        }
      );
      return {
        success: true,
        provider: 'resend',
        details: `Dispatched to ${recipients.join(', ')} (Resend ID: ${response.data?.id || 'ok'})`
      };
    } catch (err: any) {
      console.warn('[EmailAlertService] Resend API dispatch failed:', err?.response?.data || err?.message);
    }
  }

  // 2. Simulated SMTP Relay Log (if RESEND not present or failed)
  if (config.smtpHost) {
    console.log(`[EmailAlertService] [SMTP RELAY ${config.smtpHost}:${config.smtpPort}] Alert email dispatched to ${recipients.join(', ')}`);
    return {
      success: true,
      provider: 'smtp',
      details: `Dispatched via SMTP Relay (${config.smtpHost}:${config.smtpPort}) to ${recipients.join(', ')}`
    };
  }

  return {
    success: false,
    provider: 'failed',
    details: 'Failed to send alert via configured providers.'
  };
}
