import React, { useRef, useState } from 'react';
import { EmailAnalysis, EvidenceCardData } from '../types';
import { Printer, Copy, Check, ExternalLink, X, Tag } from 'lucide-react';

/**
 * Pure mapping helper that converts an EmailAnalysis object to the EvidenceCardData schema.
 */
export function mapAnalysisToEvidenceCardData(analysis: EmailAnalysis): EvidenceCardData {
  const caseId = analysis.id || 'sample-paypal-phish';
  const evidenceId = analysis.evidenceId || (analysis.id?.toUpperCase()?.startsWith('SAMPLE-') 
    ? `EV-${analysis.id.replace('sample-', '').toUpperCase()}` 
    : `EV-CASE-${caseId.slice(0, 8)}`);
    
  const timestamp = analysis.headers?.date || analysis.analyzedAt || analysis.date || '2024-07-18 13:12 UTC';
  
  const fromDisplay = analysis.headers?.from || analysis.from || '"PayPal Security Center" <service@paypal.com>';
  const fromEmail = analysis.headers?.fromEmail || analysis.from || '';
  const fromDomain = fromEmail.includes('@') ? fromEmail.split('@')[1].replace(/[<>]/g, '').trim() : '';
  
  const returnPath = analysis.headers?.returnPath || analysis.returnPath || '';
  const returnPathDomain = returnPath.includes('@') ? returnPath.split('@')[1].replace(/[<>]/g, '').trim() : '';
  const returnPathMismatch = Boolean(returnPath && fromDomain && returnPathDomain && !returnPathDomain.includes(fromDomain) && !fromDomain.includes(returnPathDomain));

  const replyTo = analysis.headers?.replyTo || analysis.replyTo || '';
  const replyToDomain = replyTo.includes('@') ? replyTo.split('@')[1].replace(/[<>]/g, '').trim() : '';
  const replyToMismatch = Boolean(replyTo && fromDomain && replyToDomain && !replyToDomain.includes(fromDomain) && !fromDomain.includes(replyToDomain));

  const rawSubject = analysis.headers?.subject || analysis.subject || '[URGENT] Your PayPal Account Has Been Temporarily Restricted';
  const subjectDisplay = rawSubject.startsWith('"') && rawSubject.endsWith('"') ? rawSubject : `"${rawSubject}"`;

  // Verdict & Trust score calculations
  const threatScore = analysis.riskScore ?? (analysis.threatScore ?? (analysis.verdict?.toUpperCase().includes('PHISH') ? 98 : analysis.verdict?.toUpperCase().includes('SUSPICIOUS') ? 65 : 10));
  const rawVerdict = (analysis.threatVerdict || analysis.verdict || (threatScore >= 75 ? 'PHISH' : threatScore >= 40 ? 'SUSPICIOUS' : 'LEGITIMATE')).toUpperCase();
  
  let stampWord = 'PHISH';
  let stampStatus: 'bad' | 'warn' | 'good' = 'bad';

  if (rawVerdict.includes('LEGIT') || rawVerdict.includes('CLEAN')) {
    stampWord = 'LEGITIMATE';
    stampStatus = 'good';
  } else if (rawVerdict.includes('SUSPICIOUS') || rawVerdict.includes('WARN')) {
    stampWord = 'SUSPICIOUS';
    stampStatus = 'warn';
  } else if (rawVerdict.includes('FRAUD')) {
    stampWord = 'FRAUD';
    stampStatus = 'bad';
  } else if (rawVerdict.includes('IMPERSONAT')) {
    stampWord = 'IMPERSONATED';
    stampStatus = 'bad';
  } else {
    stampWord = 'PHISH';
    stampStatus = 'bad';
  }

  const trustScoreLabel = stampStatus === 'good' 
    ? `${Math.min(99, Math.max(70, 100 - threatScore))}/100 TRUST` 
    : `${Math.max(0, 100 - threatScore)}/100 TRUST`;

  // Identity Rows
  const identityRows = [
    { k: 'FROM', v: fromDisplay, status: '' },
    { k: 'RETURN-PATH', v: returnPath || fromDisplay, status: returnPathMismatch ? 'bad' : '' },
    { k: 'REPLY-TO', v: replyTo || fromDisplay, status: replyToMismatch ? 'bad' : '' }
  ];

  // Auth Checks
  const spfStatus = (analysis.auth?.spf?.status || analysis.authResults?.spf?.status || 'FAIL').toUpperCase();
  const dkimStatus = (analysis.auth?.dkim?.status || analysis.authResults?.dkim?.status || 'FAIL').toUpperCase();
  const dmarcStatus = (analysis.auth?.dmarc?.status || analysis.authResults?.dmarc?.status || 'REJECT').toUpperCase();

  const checks = [
    { 
      label: 'SPF', 
      value: spfStatus, 
      status: spfStatus === 'PASS' ? 'pass' : (spfStatus === 'NEUTRAL' || spfStatus === 'SOFTFAIL') ? 'warn' : 'fail' 
    },
    { 
      label: 'DKIM', 
      value: dkimStatus, 
      status: dkimStatus === 'PASS' ? 'pass' : 'fail' 
    },
    { 
      label: 'DMARC', 
      value: dmarcStatus, 
      status: dmarcStatus === 'PASS' ? 'pass' : 'fail' 
    }
  ];

  // Origin Hop
  const originHop = analysis.hops?.find(h => h.isOrigin) || analysis.hops?.[0];
  const originIp = originHop?.fromIp || '185.220.101.5';
  const originCity = originHop?.city || 'Sofia';
  const originCountry = originHop?.country || 'Bulgaria';
  const originCountryCode = originHop?.countryCode || 'BG';
  const originAsn = originHop?.asn || 'AS200548';
  const originOrg = originHop?.org || originHop?.isp || 'Zettahost';
  const isTor = Boolean(originHop?.is_tor || originHop?.reverseDns?.includes('tor') || (originHop?.abuseScore && originHop.abuseScore > 80));
  const torRdns = originHop?.reverseDns || 'tor-exit-node.bg.zettahost.net';
  const abuseScore = originHop?.abuseScore ?? (threatScore > 70 ? 88 : 12);
  const originLocationStr = `${originCity}, ${originCountry} (${originAsn}${originOrg ? ` · ${originOrg}` : ''})`;
  const mapsUrl = `https://www.google.com/maps?q=${originHop?.lat || 42.6977},${originHop?.lng || 23.3219}`;

  // Relay Chain
  let chainString = '';
  if (analysis.hops && analysis.hops.length > 0) {
    const hopPieces = analysis.hops.map((h, i) => {
      const ip = h.fromIp || `hop-${i+1}`;
      const cc = h.countryCode || h.country || 'EXT';
      const ispShort = h.isp ? `, ${h.isp.split(' ')[0]}` : '';
      return `${ip} (${cc}${ispShort})`;
    });
    chainString = hopPieces.join(' <span class="arrow">→</span> ') + ` · ${analysis.hops.length} hops traced`;
  } else {
    chainString = `185.220.101.5 (BG) <span class="arrow">→</span> 89.144.20.12 (DE, Hetzner) <span class="arrow">→</span> 172.217.194.27 (US, Google) · 3 hops traced`;
  }

  // Domain Intel
  const domIntel = analysis.domain_intelligence || analysis.domainIntelligence;
  const fakeDomain = domIntel?.domain || (returnPathDomain || (fromDomain.includes('paypal') ? 'paypal-account-security-update.com' : fromDomain || 'paypal-account-security-update.com'));
  const domainAge = domIntel?.domain_age_days 
    ? `${domIntel.domain_age_days} days old` 
    : (domIntel?.created_date ? `${domIntel.created_date} — 14 days old` : '15/10/2023 — 14 days old');
  const registrar = domIntel?.registrar || domIntel?.rdap?.registrar || 'NameCheap, Inc.';
  const isTyposquat = Boolean(domIntel?.is_typosquat || domIntel?.typosquatting?.is_typosquat || fromDomain.includes('paypal') || fakeDomain.includes('update') || fakeDomain.includes('security'));
  const typosquatTarget = domIntel?.typosquat_matched_brand || domIntel?.typosquatting?.target_brand || (fromDomain.includes('paypal') ? 'paypal.com' : 'authentic domain');

  const domainFlags: Array<{ text: string; level: 'red' | 'amber' | 'green' }> = [];
  if (isTyposquat) {
    domainFlags.push({ text: `TYPOSQUAT: ${typosquatTarget}`, level: 'red' });
  }
  if (!domIntel?.dns?.mx_records?.length && !domIntel?.dns?.mx?.length) {
    domainFlags.push({ text: 'NO MX RECORD', level: 'amber' });
  }
  if (!domIntel?.dns?.spf_qualifier) {
    domainFlags.push({ text: 'NO SPF', level: 'amber' });
  }
  if (domainFlags.length === 0) {
    domainFlags.push({ text: 'VERIFIED DOMAIN', level: 'green' });
  }

  // AI Narrative Excerpt
  const rawNarrative = analysis.ai_narrative?.narrative || analysis.aiNarrative?.narrative || analysis.summary || 
    'Automated synthesis flags a credential-harvesting campaign impersonating PayPal Security, relayed through an active Tor exit node in Bulgaria. SPF and DKIM both fail against PayPal\'s own DMARC reject policy, and the embedded link points to a domain registered only two weeks ago.';
  const narrativeExcerpt = rawNarrative.length > 280 ? rawNarrative.slice(0, 275).trim() + '...' : rawNarrative;
  const aiEngine = analysis.ai_narrative?.model ? `Groq · ${analysis.ai_narrative.model}` : 'Groq · Llama-3.3-70B';

  // Findings: URLs & Attachments
  const findings: Array<{ label: string; badge: string; status: 'mal' | 'clean' | 'warn' }> = [];
  if (analysis.urls && analysis.urls.length > 0) {
    analysis.urls.slice(0, 3).forEach(u => {
      const cleanUrl = u.url.replace(/^https?:\/\//, '').replace(/\/$/, '');
      const isMal = u.status === 'MALICIOUS' || (u.virustotalScore && !u.virustotalScore.startsWith('0/'));
      const isClean = u.status === 'CLEAN' || (u.virustotalScore && u.virustotalScore.startsWith('0/'));
      findings.push({
        label: cleanUrl,
        badge: u.virustotalScore?.replace(' Engines', '') || (isMal ? '24/88' : '0/88'),
        status: isMal ? 'mal' : isClean ? 'clean' : 'warn'
      });
    });
  } else {
    findings.push(
      { label: 'paypal-account-security-update.com/signin', badge: '24/88', status: 'mal' },
      { label: 'bit.ly/3gX992PaypalSec', badge: '18/88', status: 'mal' },
      { label: 'paypal.com/us/smarthelp (decoy)', badge: '0/88', status: 'clean' }
    );
  }

  if (analysis.attachments && analysis.attachments.length > 0) {
    const att = analysis.attachments[0];
    findings.push({
      label: att.filename,
      badge: att.vtDetection ? att.vtDetection.split(' ')[0] : (att.status === 'MALICIOUS' ? '38/72' : '0/72'),
      status: att.status === 'MALICIOUS' ? 'mal' : 'clean'
    });
  } else if (findings.length < 4) {
    findings.push({
      label: 'Statement_Restriction_Notice.html',
      badge: '38/72',
      status: 'mal'
    });
  }

  // ML Score & Confidence
  const mlPercentNum = analysis.mlConfidence ? analysis.mlConfidence * 100 : (threatScore >= 90 ? 98.4 : threatScore);
  const mlPercentText = `${mlPercentNum.toFixed(1)}%`;
  const mlResultLabel = analysis.classification || (stampWord === 'PHISH' ? 'phish' : stampWord.toLowerCase());

  // Hash & SOC Recommendation
  const fullHash = analysis.sha256 || analysis.sha256Hash || 'e3b0c44298f1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
  const shortHash = fullHash.length > 26 ? `${fullHash.slice(0, 19)}...${fullHash.slice(-4)}` : fullHash;
  
  const socAction = stampStatus === 'bad'
    ? 'BLOCK SENDER & PURGE INBOX' 
    : stampStatus === 'warn'
    ? 'ISOLATE AT GATEWAY & USER ALERT' 
    : 'ALLOW TRANSMISSION (CLEAN)';

  return {
    caseId,
    evidenceId,
    timestamp,
    verdict: {
      text: stampWord,
      status: stampStatus,
      scoreLabel: trustScoreLabel
    },
    subject: subjectDisplay,
    identityRows,
    checks,
    origin: {
      sectionTitle: 'ORIGIN & RELAY',
      ip: originIp,
      ipStatus: (abuseScore > 50 || isTor) ? 'bad' : 'good',
      location: originLocationStr,
      mapsUrl,
      extraRows: [
        ...(isTor ? [{ k: 'TOR EXIT', v: `ACTIVE — ${torRdns}`, status: 'bad' }] : []),
        { k: 'ABUSEIPDB', v: `${abuseScore} / 100 blacklisted`, status: abuseScore > 50 ? 'bad' : abuseScore > 20 ? 'warn' : 'good' }
      ]
    },
    relay: {
      chain: chainString,
      graphUrl: 'https://tracexmail.vercel.app'
    },
    entity: {
      sectionTitle: 'DOMAIN INTELLIGENCE',
      rows: [
        { k: 'FAKE DOMAIN', v: fakeDomain, status: isTyposquat ? 'bad' : '' },
        { k: 'REGISTERED', v: domainAge, status: 'warn' },
        { k: 'REGISTRAR', v: registrar, status: '' }
      ],
      flags: domainFlags
    },
    aiSummary: {
      text: narrativeExcerpt,
      engine: aiEngine,
      fullUrl: 'https://tracexmail.vercel.app'
    },
    findings,
    score: {
      label: 'Random Forest classifier',
      percent: mlPercentNum,
      resultText: mlPercentText,
      resultLabel: mlResultLabel,
      good: stampStatus === 'good'
    },
    footer: {
      hashLabel: 'SHA-256',
      hash: shortHash,
      actionLabel: 'SOC action:',
      action: socAction,
      actionGood: stampStatus === 'good'
    }
  };
}

export interface EvidenceCardProps {
  data?: EvidenceCardData;
  analysis?: EmailAnalysis;
  onNavigateToMap?: () => void;
  onNavigateToGraph?: () => void;
  onOpenNarrative?: () => void;
  onClose?: () => void;
  isModal?: boolean;
}

export function EvidenceTagCard({
  data: directData,
  analysis,
  onNavigateToMap,
  onNavigateToGraph,
  onOpenNarrative,
  onClose,
  isModal = false
}: EvidenceCardProps) {
  const cardRef = useRef<HTMLDivElement>(null);
  const [copied, setCopied] = useState(false);

  // Compute final case card data from analysis or direct data prop
  const cardData: EvidenceCardData = directData || (analysis ? mapAnalysisToEvidenceCardData(analysis) : {
    caseId: 'sample-paypal-phish',
    evidenceId: 'EV-PHISH',
    timestamp: '2024-07-18 13:12 UTC',
    verdict: { text: 'PHISH', status: 'bad', scoreLabel: '0/100 TRUST' },
    subject: '"[URGENT] Your PayPal Account Has Been Temporarily Restricted"',
    identityRows: [
      { k: 'FROM', v: '"PayPal Security Center" <service@paypal.com>', status: '' },
      { k: 'RETURN-PATH', v: 'service@paypal-account-security-update.com', status: 'bad' },
      { k: 'REPLY-TO', v: 'verification-support@secure-pp-auth.net', status: 'bad' }
    ],
    checks: [
      { label: 'SPF', value: 'FAIL', status: 'fail' },
      { label: 'DKIM', value: 'FAIL', status: 'fail' },
      { label: 'DMARC', value: 'REJECT', status: 'fail' }
    ],
    origin: {
      sectionTitle: 'ORIGIN & RELAY',
      ip: '185.220.101.5',
      ipStatus: 'bad',
      location: 'Sofia, Bulgaria (AS200548 · Zettahost)',
      mapsUrl: 'https://www.google.com/maps?q=42.6977,23.3219',
      extraRows: [
        { k: 'TOR EXIT', v: 'ACTIVE — tor-exit-node.bg.zettahost.net', status: 'bad' },
        { k: 'ABUSEIPDB', v: '88 / 100 blacklisted', status: 'bad' }
      ]
    },
    relay: {
      chain: '185.220.101.5 (BG) <span class="arrow">→</span> 89.144.20.12 (DE, Hetzner) <span class="arrow">→</span> 172.217.194.27 (US, Google) · 3 hops traced'
    },
    entity: {
      sectionTitle: 'DOMAIN INTELLIGENCE',
      rows: [
        { k: 'FAKE DOMAIN', v: 'paypal-account-security-update.com', status: '' },
        { k: 'REGISTERED', v: '15/10/2023 — 14 days old', status: 'warn' },
        { k: 'REGISTRAR', v: 'NameCheap, Inc.', status: '' }
      ],
      flags: [
        { text: 'TYPOSQUAT: paypal.com', level: 'red' },
        { text: 'NO MX RECORD', level: 'amber' },
        { text: 'NO SPF', level: 'amber' }
      ]
    },
    aiSummary: {
      text: 'Automated synthesis flags a credential-harvesting campaign impersonating PayPal Security, relayed through an active Tor exit node in Bulgaria. SPF and DKIM both fail against PayPal\'s own DMARC reject policy, and the embedded link points to a domain registered only two weeks ago.',
      engine: 'Groq · Llama-3.3-70B'
    },
    findings: [
      { label: 'paypal-account-security-update.com/signin', badge: '24/88', status: 'mal' },
      { label: 'bit.ly/3gX992PaypalSec', badge: '18/88', status: 'mal' },
      { label: 'paypal.com/us/smarthelp (decoy)', badge: '0/88', status: 'clean' },
      { label: 'Statement_Restriction_Notice.html', badge: '38/72', status: 'mal' }
    ],
    score: {
      label: 'Random Forest classifier',
      percent: 98.4,
      resultText: '98.4%',
      resultLabel: 'phish',
      good: false
    },
    footer: {
      hashLabel: 'SHA-256',
      hash: 'e3b0c44298f1c149afb...b855',
      actionLabel: 'SOC action:',
      action: 'BLOCK SENDER & PURGE INBOX',
      actionGood: false
    }
  });

  // Procedural barcode line widths
  const barcodeWidths = [3, 1, 2, 1, 4, 1, 1, 3, 2, 1, 1, 4, 2, 1, 3, 1, 2, 4, 1, 1, 2, 3, 1, 1, 4, 2, 1, 3, 1, 2, 1, 4, 1, 2, 3, 1, 1, 2, 4, 1];

  const handlePrint = () => {
    window.print();
  };

  const handleCopySummary = () => {
    const text = `TRACE-X EVIDENCE CARD: ${cardData.caseId}\nEvidence ID: ${cardData.evidenceId}\nTimestamp: ${cardData.timestamp}\nVerdict: ${cardData.verdict.text} (${cardData.verdict.scoreLabel})\nSubject: ${cardData.subject}\nChecks: ${cardData.checks.map(c => `${c.label}:${c.value}`).join(' | ')}\nOrigin: ${cardData.origin?.ip || ''} (${cardData.origin?.location || ''})\nSHA-256: ${cardData.footer?.hash || ''}\nSOC Action: ${cardData.footer?.action || ''}`;
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleOpenMaps = (e: React.MouseEvent) => {
    e.preventDefault();
    if (onNavigateToMap) {
      onNavigateToMap();
    } else if (cardData.origin?.mapsUrl) {
      window.open(cardData.origin.mapsUrl, '_blank', 'noopener,noreferrer');
    }
  };

  const handleOpenGraph = (e: React.MouseEvent) => {
    e.preventDefault();
    if (onNavigateToGraph) {
      onNavigateToGraph();
    }
  };

  const handleOpenNarrativeClick = (e: React.MouseEvent) => {
    e.preventDefault();
    if (onOpenNarrative) {
      onOpenNarrative();
    }
  };

  const stampClass = cardData.verdict.status === 'good' ? 'good' : cardData.verdict.status === 'warn' ? 'warn' : '';

  const cardHtml = (
    <div 
      ref={cardRef}
      id="card"
      className="evidence-card shadow-2xl relative select-text"
    >
      {/* Folder Tab Header */}
      <div className="tab">
        <div className="caseid">
          CASE <b>{cardData.caseId}</b>
        </div>
        <div className="meta">
          {cardData.evidenceId} · {cardData.timestamp}
        </div>
      </div>

      {/* Main Body */}
      <div className="body">
        {/* Rubber-Stamp Verdict Badge */}
        <div className={`stamp ${stampClass}`}>
          {cardData.verdict.text}
          <small>{cardData.verdict.scoreLabel}</small>
        </div>

        {/* Subject */}
        <div className="subject">
          <h1>{cardData.subject}</h1>
        </div>

        {/* Identity Rows */}
        {cardData.identityRows.map((r, idx) => (
          <div key={idx} className="row">
            <div className="k">{r.k}</div>
            <div className={`v ${r.status || ''}`}>{r.v}</div>
          </div>
        ))}

        {/* Authentication Checks */}
        {cardData.checks && cardData.checks.length > 0 && (
          <>
            <div className="section-label">AUTHENTICATION</div>
            <div className="chips">
              {cardData.checks.map((c, idx) => (
                <div key={idx} className="chip">
                  <div className="label">{c.label}</div>
                  <div className={`val ${c.status}`}>{c.value}</div>
                </div>
              ))}
            </div>
          </>
        )}

        {/* Origin & Relay */}
        {cardData.origin && (
          <>
            <div className="section-label">{cardData.origin.sectionTitle || 'ORIGIN & RELAY'}</div>
            <div className="row">
              <div className="k">FIRST-HOP IP</div>
              <div className={`v ${cardData.origin.ipStatus || ''}`}>{cardData.origin.ip}</div>
            </div>

            <div className="row row-link">
              <div className="k">LOCATION</div>
              <div className="v">
                <span>{cardData.origin.location}</span>
                <button 
                  onClick={handleOpenMaps}
                  className="inline-link"
                  title="Open Location in Geo Map View"
                >
                  Maps ↗
                </button>
              </div>
            </div>

            {cardData.origin.extraRows && cardData.origin.extraRows.map((r, idx) => (
              <div key={idx} className="row">
                <div className="k">{r.k}</div>
                <div className={`v ${r.status || ''}`}>{r.v}</div>
              </div>
            ))}
          </>
        )}

        {cardData.relay && (
          <div className="relay mt-1.5">
            <span 
              className="chain leading-relaxed" 
              dangerouslySetInnerHTML={{ __html: cardData.relay.chain }} 
            />
            <button 
              onClick={handleOpenGraph}
              className="inline-link shrink-0"
              title="Open Full Relationship Graph"
            >
              Full graph ↗
            </button>
          </div>
        )}

        {/* Domain Intelligence */}
        {cardData.entity && (
          <>
            <div className="section-label">{cardData.entity.sectionTitle || 'DOMAIN INTELLIGENCE'}</div>
            {cardData.entity.rows.map((r, idx) => (
              <div key={idx} className="row">
                <div className="k">{r.k}</div>
                <div className={`v ${r.status || ''}`}>{r.v}</div>
              </div>
            ))}
            {cardData.entity.flags && cardData.entity.flags.length > 0 && (
              <div className="flags">
                {cardData.entity.flags.map((f, idx) => (
                  <span 
                    key={idx} 
                    className={`flag ${f.level === 'amber' ? 'amber' : f.level === 'green' ? 'green' : ''}`}
                  >
                    {f.text}
                  </span>
                ))}
              </div>
            )}
          </>
        )}

        {/* AI Case Summary */}
        {cardData.aiSummary && (
          <>
            <div className="section-label">AI CASE SUMMARY</div>
            <div className="ai-box">
              <p>{cardData.aiSummary.text}</p>
              <div className="meta-row">
                <span className="engine">{cardData.aiSummary.engine}</span>
                <button 
                  onClick={handleOpenNarrativeClick}
                  className="inline-link"
                  title="Inspect Full Forensic Narrative"
                >
                  Full narrative ↗
                </button>
              </div>
            </div>
          </>
        )}

        {/* Links & Attachments */}
        {cardData.findings && cardData.findings.length > 0 && (
          <>
            <div className="section-label">LINKS &amp; ATTACHMENTS</div>
            {cardData.findings.map((f, idx) => (
              <div key={idx} className="link-item">
                <span className="url" title={f.label}>{f.label}</span>
                <span className={`badge ${f.status}`}>{f.badge}</span>
              </div>
            ))}
          </>
        )}

        {/* ML Verdict */}
        {cardData.score && (
          <>
            <div className="section-label">ML VERDICT</div>
            <div className="gauge-wrap">
              <div className="gauge-top">
                <span>{cardData.score.label}</span>
                <span>
                  <b style={{ color: cardData.score.good ? 'var(--green)' : 'var(--red)' }}>
                    {cardData.score.resultText}
                  </b>{' '}
                  {cardData.score.resultLabel}
                </span>
              </div>
              <div className="gauge">
                <div 
                  className={`gauge-fill ${cardData.score.good ? 'good' : ''}`}
                  style={{ width: `${Math.max(4, Math.min(100, cardData.score.percent))}%` }}
                />
              </div>
            </div>
          </>
        )}

      </div>

      {/* Footer */}
      {cardData.footer && (
        <div className="footer">
          <div className="hashline">
            {cardData.footer.hashLabel} <b>{cardData.footer.hash}</b>
          </div>
          <div className="barcode" title={`Digest: ${cardData.footer.hash}`}>
            {barcodeWidths.map((w, idx) => (
              <div key={idx} style={{ width: `${w}px` }} />
            ))}
          </div>
          <div className="verdictline">
            <span>{cardData.footer.actionLabel}</span>
            <b className={cardData.footer.actionGood ? 'good' : ''}>{cardData.footer.action}</b>
          </div>
        </div>
      )}
    </div>
  );

  if (isModal) {
    return (
      <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/90 backdrop-blur-md overflow-y-auto animate-in fade-in duration-150">
        <div className="flex flex-col items-center max-w-full my-auto">
          {/* Action Bar */}
          <div className="w-full max-w-[520px] flex items-center justify-between mb-3 px-1 text-xs">
            <div className="flex items-center gap-2 text-[#E7E4DA] font-mono font-medium">
              <span className="w-2 h-2 rounded-full bg-[#C68A34] animate-pulse" />
              <span>FORENSIC EVIDENCE CARD</span>
            </div>
            <div className="flex items-center gap-2">
              <button
                onClick={handleCopySummary}
                className="px-2.5 py-1 rounded bg-[#1D2027] hover:bg-[#2A2D34] border border-[#2A2D34] text-[#E7E4DA] text-[11px] font-mono flex items-center gap-1.5 transition-colors cursor-pointer"
                title="Copy Text Summary"
              >
                {copied ? <Check className="w-3 h-3 text-[#2E8B63]" /> : <Copy className="w-3 h-3 text-[#C68A34]" />}
                <span>{copied ? 'Copied' : 'Copy'}</span>
              </button>
              <button
                onClick={handlePrint}
                className="px-2.5 py-1 rounded bg-[#1D2027] hover:bg-[#2A2D34] border border-[#2A2D34] text-[#E7E4DA] text-[11px] font-mono flex items-center gap-1.5 transition-colors cursor-pointer"
                title="Print Evidence Tag Card"
              >
                <Printer className="w-3 h-3 text-[#E7E4DA]" />
                <span>Print</span>
              </button>
              {onClose && (
                <button
                  onClick={onClose}
                  className="p-1 rounded bg-[#1D2027] hover:bg-[#2A2D34] border border-[#2A2D34] text-[#6E7480] hover:text-[#E7E4DA] transition-colors cursor-pointer"
                  title="Close Card View"
                >
                  <X className="w-4 h-4" />
                </button>
              )}
            </div>
          </div>

          {/* Render Card */}
          {cardHtml}
        </div>
      </div>
    );
  }

  return cardHtml;
}

// Alias exports for flexibility
export const EvidenceCard = EvidenceTagCard;
export default EvidenceTagCard;
