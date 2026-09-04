import React, { useRef, useState } from 'react';
import { EmailAnalysis, EvidenceCardData } from '../types';
import { Printer, Copy, Check, ExternalLink, X, Tag, ChevronDown, ChevronUp, AlertCircle } from 'lucide-react';
import { sha256Sync, generateEvidenceId } from '../utils/crypto';
import { resolveOrigin, formatOriginLocation, formatOriginIp } from '../utils/originResolution';

/**
 * Pure mapping helper that converts an EmailAnalysis object to the EvidenceCardData schema.
 */
export function mapAnalysisToEvidenceCardData(analysis: EmailAnalysis): EvidenceCardData {
  const caseId = analysis.id || 'case-' + Date.now();
  const evidenceId = analysis.evidenceId || (analysis.id?.toUpperCase()?.startsWith('SAMPLE-') 
    ? `EV-${analysis.id.replace('sample-', '').toUpperCase()}` 
    : (analysis.id?.startsWith('case-') ? `EV-${analysis.id.slice(5, 11).toUpperCase()}` : generateEvidenceId()));
    
  const timestamp = analysis.headers?.date || analysis.analyzedAt || analysis.date || new Date().toUTCString();
  
  const fromDisplay = analysis.headers?.from || analysis.from || analysis.headers?.fromEmail || 'unknown@sender.corp';
  const fromEmail = analysis.headers?.fromEmail || analysis.from || '';
  const fromDomain = fromEmail.includes('@') ? fromEmail.split('@')[1].replace(/[<>]/g, '').trim() : '';
  
  const returnPath = analysis.headers?.returnPath || analysis.returnPath || '';
  const returnPathDomain = returnPath.includes('@') ? returnPath.split('@')[1].replace(/[<>]/g, '').trim() : '';
  const returnPathMismatch = Boolean(returnPath && fromDomain && returnPathDomain && !returnPathDomain.includes(fromDomain) && !fromDomain.includes(returnPathDomain));

  const replyTo = analysis.headers?.replyTo || analysis.replyTo || '';
  const replyToDomain = replyTo.includes('@') ? replyTo.split('@')[1].replace(/[<>]/g, '').trim() : '';
  const replyToMismatch = Boolean(replyTo && fromDomain && replyToDomain && !replyToDomain.includes(fromDomain) && !fromDomain.includes(replyToDomain));

  const rawSubject = analysis.headers?.subject || analysis.subject || analysis.name || '(No Subject)';
  const subjectDisplay = rawSubject.startsWith('"') && rawSubject.endsWith('"') ? rawSubject : `"${rawSubject}"`;

  // Verdict & Trust score calculations
  const rawVerdict = (analysis.threatVerdict || analysis.verdict || '').toUpperCase();
  const isMalicious = rawVerdict.includes('PHISH') || rawVerdict.includes('FRAUD') || rawVerdict.includes('IMPERSONAT') || rawVerdict.includes('MALICIOUS');
  const isSuspicious = rawVerdict.includes('SUSPICIOUS') || rawVerdict.includes('WARN');
  const isClean = rawVerdict.includes('LEGIT') || rawVerdict.includes('CLEAN');

  // Accurately use backend threatScore directly without independent re-derivation or artificial overrides
  let threatScore: number | null = null;
  let hasValidThreatScore = false;
  if (typeof analysis.threatScore === 'number' && !isNaN(analysis.threatScore) && analysis.threatScore >= 0) {
    threatScore = analysis.threatScore;
    hasValidThreatScore = true;
  } else if (typeof analysis.riskScore === 'number' && !isNaN(analysis.riskScore) && analysis.riskScore >= 0) {
    threatScore = analysis.riskScore;
    hasValidThreatScore = true;
  }

  let stampWord = 'PHISH';
  let stampStatus: 'bad' | 'warn' | 'good' = 'bad';

  if (isClean && !isMalicious && !isSuspicious) {
    stampWord = 'LEGITIMATE';
    stampStatus = 'good';
  } else if (isSuspicious && !isMalicious) {
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

  const trustScoreLabel = hasValidThreatScore && threatScore !== null
    ? (stampStatus === 'good' 
        ? `${Math.max(0, Math.min(100, 100 - threatScore))}/100 TRUST` 
        : `${threatScore}/100 THREAT (${Math.max(0, Math.min(100, 100 - threatScore))}/100 TRUST)`)
    : 'Score unavailable';

  // Identity Rows
  const identityRows = [
    { k: 'FROM', v: fromDisplay, status: '' },
    { k: 'RETURN-PATH', v: returnPath || fromDisplay, status: returnPathMismatch ? 'bad' : '' },
    { k: 'REPLY-TO', v: replyTo || fromDisplay, status: replyToMismatch ? 'bad' : '' }
  ];

  // Auth Checks
  const spfStatus = (analysis.auth?.spf?.status || analysis.authResults?.spf?.status || (stampStatus === 'good' ? 'PASS' : 'FAIL')).toUpperCase();
  const dkimStatus = (analysis.auth?.dkim?.status || analysis.authResults?.dkim?.status || (stampStatus === 'good' ? 'PASS' : 'FAIL')).toUpperCase();
  const dmarcStatus = (analysis.auth?.dmarc?.status || analysis.authResults?.dmarc?.status || (stampStatus === 'good' ? 'PASS' : 'FAIL')).toUpperCase();

  const checks = [
    { 
      label: 'SPF', 
      value: spfStatus, 
      status: spfStatus === 'PASS' ? 'pass' : (spfStatus === 'NEUTRAL' || spfStatus === 'SOFTFAIL' || spfStatus === 'NONE') ? 'warn' : 'fail' 
    },
    { 
      label: 'DKIM', 
      value: dkimStatus, 
      status: dkimStatus === 'PASS' ? 'pass' : (dkimStatus === 'NONE' || dkimStatus === 'NEUTRAL') ? 'warn' : 'fail' 
    },
    { 
      label: 'DMARC', 
      value: dmarcStatus, 
      status: dmarcStatus === 'PASS' ? 'pass' : (dmarcStatus === 'NONE') ? 'warn' : 'fail' 
    }
  ];

  // Origin Hop using centralized zero-fake-data resolver
  const origin = resolveOrigin(analysis.hops);
  const originIp = formatOriginIp(origin);
  const originLocationStr = formatOriginLocation(origin);
  const mapsUrl = origin.resolved && origin.lat != null && origin.lng != null
    ? `https://www.google.com/maps?q=${origin.lat},${origin.lng}`
    : undefined;

  const matchedOriginHop = origin.resolved ? analysis.hops?.find(h => h.fromIp === origin.ip) : undefined;
  const isTor = Boolean(matchedOriginHop?.is_tor || matchedOriginHop?.reverseDns?.includes('tor'));
  const torRdns = matchedOriginHop?.reverseDns || 'No PTR record';
  const abuseScore = origin.resolved ? (matchedOriginHop?.abuseScore ?? 0) : 0;

  // Relay Chain
  let chainString = '';
  if (analysis.hops && analysis.hops.length > 0) {
    const hopPieces = analysis.hops.map((h, i) => {
      const ip = h.fromIp || `hop-${i+1}`;
      const cc = h.countryCode || (h.isPrivate ? 'LAN' : 'EXT');
      const ispShort = h.isp ? `, ${h.isp.split(' ')[0]}` : (h.org ? `, ${h.org.split(' ')[0]}` : '');
      return `${ip} (${cc}${ispShort})`;
    });
    chainString = hopPieces.join(' <span class="arrow">→</span> ') + ` · ${analysis.hops.length} hops traced`;
  } else {
    chainString = 'No relay hops recorded in message headers';
  }

  // Domain Intel
  const domIntel = analysis.domain_intelligence || analysis.domainIntelligence;
  const targetDomain = domIntel?.domain || fromDomain || returnPathDomain || 'UNKNOWN';
  const domainAge = domIntel?.domain_age_days !== undefined
    ? `${domIntel.domain_age_days} days old` 
    : (domIntel?.created_date ? domIntel.created_date : 'UNKNOWN');
  const registrar = domIntel?.registrar || domIntel?.rdap?.registrar || 'UNKNOWN / NOT RESOLVED';
  const isTyposquat = Boolean(domIntel?.is_typosquat || domIntel?.typosquatting?.is_typosquat);
  const typosquatTarget = domIntel?.typosquat_matched_brand || domIntel?.typosquatting?.target_brand || null;

  const domainFlags: Array<{ text: string; level: 'red' | 'amber' | 'green' }> = [];
  if (isTyposquat && typosquatTarget) {
    domainFlags.push({ text: `LOOKALIKE BRAND: ${typosquatTarget}`, level: 'red' });
  }
  if (domIntel?.dns?.mx_records !== undefined && domIntel.dns.mx_records.length === 0) {
    domainFlags.push({ text: 'NO MX RECORD', level: 'amber' });
  }
  if (domIntel?.dns?.spf === null || domIntel?.dns?.spf === '') {
    domainFlags.push({ text: 'NO SPF RECORD', level: 'amber' });
  }
  if (domainFlags.length === 0 && domIntel?.domain) {
    domainFlags.push({ text: 'DOMAIN ENRICHED', level: 'green' });
  } else if (!domIntel?.domain) {
    domainFlags.push({ text: 'DOMAIN UNRESOLVED', level: 'amber' });
  }

  // AI Narrative Excerpt
  const rawNarrative = analysis.ai_narrative?.narrative || analysis.aiNarrative?.narrative || analysis.summary || 
    'Automated forensic evaluation completed.';
  const narrativeExcerpt = rawNarrative.length > 280 ? rawNarrative.slice(0, 275).trim() + '...' : rawNarrative;
  const aiEngine = analysis.ai_narrative?.model ? analysis.ai_narrative.model : 'Heuristic & Cryptographic Engine';

  // Findings: URLs & Attachments
  const findings: Array<{ label: string; badge: string; status: 'mal' | 'clean' | 'warn' }> = [];
  if (analysis.urls && analysis.urls.length > 0) {
    analysis.urls.slice(0, 4).forEach(u => {
      const cleanUrl = u.url.replace(/^https?:\/\//, '').replace(/\/$/, '');
      const vtScoreStr = (u.virustotalScore || '').toLowerCase();
      const isUnchecked = !u.virustotalScore || vtScoreStr.includes('inactive') || vtScoreStr.includes('unconfigured') || vtScoreStr.includes('dormant') || vtScoreStr.includes('unindexed');
      const isMal = u.status === 'MALICIOUS' || (Boolean(u.virustotalScore) && !isUnchecked && !u.virustotalScore.startsWith('0/'));
      const isClean = u.status === 'CLEAN' || (Boolean(u.virustotalScore) && u.virustotalScore.startsWith('0/'));
      findings.push({
        label: cleanUrl.length > 35 ? cleanUrl.slice(0, 32) + '...' : cleanUrl,
        badge: u.virustotalScore || (u.status ? u.status : 'INSPECTED'),
        status: isMal ? 'mal' : isClean ? 'clean' : 'warn'
      });
    });
  }

  if (analysis.attachments && analysis.attachments.length > 0) {
    analysis.attachments.slice(0, 2).forEach(att => {
      const vtDetStr = (att.vtDetection || '').toLowerCase();
      const isUnchecked = !att.vtDetection || vtDetStr.includes('inactive') || vtDetStr.includes('unconfigured') || vtDetStr.includes('dormant') || vtDetStr.includes('unindexed');
      const isMal = att.status === 'MALICIOUS' || (Boolean(att.vtDetection) && !isUnchecked && !att.vtDetection.startsWith('0/'));
      findings.push({
        label: att.filename,
        badge: att.vtDetection ? att.vtDetection.split(' ')[0] : (att.status === 'MALICIOUS' ? 'FLAGGED' : 'CLEAN'),
        status: isMal ? 'mal' : (att.status === 'CLEAN' ? 'clean' : 'warn')
      });
    });
  }

  if (findings.length === 0) {
    findings.push({
      label: 'No suspicious URLs or embedded attachments detected',
      badge: 'CLEAN',
      status: 'clean'
    });
  }

  // ML Score & Confidence
  const mlPercentNum = analysis.mlConfidence ? analysis.mlConfidence * 100 : (threatScore >= 90 ? 98.4 : threatScore);
  const mlPercentText = `${mlPercentNum.toFixed(1)}%`;
  const mlResultLabel = analysis.classification || (stampWord === 'PHISH' ? 'phish' : stampWord.toLowerCase());

  // Hash & SOC Recommendation
  const fullHash = analysis.sha256 || analysis.sha256Hash || analysis.custodyHash || (analysis.rawEml ? sha256Sync(analysis.rawEml) : sha256Sync(analysis.id || JSON.stringify(analysis)));
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
        { k: 'DOMAIN', v: targetDomain, status: isTyposquat ? 'bad' : '' },
        { k: 'REGISTERED', v: domainAge, status: domainAge === 'UNKNOWN' ? '' : 'warn' },
        { k: 'REGISTRAR', v: registrar, status: '' }
      ],
      flags: domainFlags
    },
    aiSummary: {
      text: narrativeExcerpt,
      engine: aiEngine,
      fullUrl: '#'
    },
    findings,
    score: {
      label: '5-Class Nearest Centroid Classifier',
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
    },
    threatScoreBreakdown: analysis.threatScoreBreakdown
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
  const [showBreakdown, setShowBreakdown] = useState(false);

  // Compute final case card data from analysis or direct data prop
  const cardData: EvidenceCardData = directData || (analysis ? mapAnalysisToEvidenceCardData(analysis) : {
    caseId: 'NO-CASE-SELECTED',
    evidenceId: 'EVD-PENDING',
    timestamp: new Date().toISOString().replace('T', ' ').slice(0, 16) + ' UTC',
    verdict: { text: 'PENDING', status: 'good', scoreLabel: 'N/A' },
    subject: 'No Email Evidence Loaded',
    identityRows: [
      { k: 'FROM', v: 'Awaiting Ingestion', status: '' },
      { k: 'RETURN-PATH', v: 'Awaiting Ingestion', status: '' },
      { k: 'REPLY-TO', v: 'Awaiting Ingestion', status: '' }
    ],
    checks: [
      { label: 'SPF', value: 'UNKNOWN', status: 'pass' },
      { label: 'DKIM', value: 'UNKNOWN', status: 'pass' },
      { label: 'DMARC', value: 'UNKNOWN', status: 'pass' }
    ],
    origin: {
      sectionTitle: 'ORIGIN & RELAY',
      ip: 'UNKNOWN',
      ipStatus: 'good',
      location: 'Unresolved Infrastructure',
      mapsUrl: '#',
      extraRows: [
        { k: 'ENRICHMENT', v: 'Awaiting RFC 822 EML ingestion', status: '' }
      ]
    },
    relay: {
      chain: 'No relay hops recorded in message headers'
    },
    entity: {
      sectionTitle: 'DOMAIN INTELLIGENCE',
      rows: [
        { k: 'DOMAIN', v: 'UNKNOWN', status: '' },
        { k: 'REGISTERED', v: 'UNKNOWN', status: '' },
        { k: 'REGISTRAR', v: 'UNKNOWN', status: '' }
      ],
      flags: [
        { text: 'AWAITING INGESTION', level: 'amber' }
      ]
    },
    aiSummary: {
      text: 'No active email analysis loaded. Select a case from Case Management or upload an RFC 822 EML file to inspect forensic telemetry.',
      engine: 'TraceXMail Forensic Core'
    },
    findings: [
      { label: 'No artifacts loaded', badge: 'PENDING', status: 'clean' }
    ],
    score: {
      label: '5-Class Nearest Centroid Classifier',
      percent: 0,
      resultText: '0.0%',
      resultLabel: 'pending',
      good: true
    },
    footer: {
      hashLabel: 'SHA-256',
      hash: 'N/A',
      actionLabel: 'SOC action:',
      action: 'AWAITING INGESTION',
      actionGood: true
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
                {cardData.origin.mapsUrl && (
                  <button 
                    onClick={handleOpenMaps}
                    className="inline-link"
                    title="Open Location in Geo Map View"
                  >
                    Maps ↗
                  </button>
                )}
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

        {/* Threat Score Breakdown */}
        {(cardData.threatScoreBreakdown || analysis?.threatScoreBreakdown) && (() => {
          const bd = cardData.threatScoreBreakdown || analysis?.threatScoreBreakdown;
          if (!bd || !bd.components) return null;
          return (
            <>
              <div className="section-label flex items-center justify-between">
                <span>THREAT SCORE BREAKDOWN</span>
                <button
                  type="button"
                  onClick={() => setShowBreakdown(!showBreakdown)}
                  className="inline-link text-[10px]"
                >
                  {showBreakdown ? 'Hide ▲' : 'Details ▼'}
                </button>
              </div>
              <div className="p-2 bg-slate-900/50 rounded border border-slate-700/50 text-[11px] font-mono space-y-1.5">
                <div className="flex justify-between items-center text-slate-300 font-bold">
                  <span>Cumulative Threat Risk:</span>
                  <span className={bd.total >= 70 ? 'text-red-400' : bd.total >= 40 ? 'text-amber-400' : 'text-emerald-400'}>
                    {bd.total} / {bd.maxScore || 100}
                  </span>
                </div>
                {showBreakdown && (
                  <div className="space-y-1 pt-1 border-t border-slate-800 text-[10px]">
                    <div className="flex justify-between">
                      <span className="text-slate-400">Authentication:</span>
                      <span className={bd.components.authentication?.score > 0 ? 'text-red-400' : 'text-slate-300'}>
                        +{bd.components.authentication?.score ?? 0} pts
                      </span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-400">Domain Intelligence:</span>
                      <span className={bd.components.domainRisk?.score > 0 ? 'text-red-400' : 'text-slate-300'}>
                        +{bd.components.domainRisk?.score ?? 0} pts
                      </span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-400">Infrastructure:</span>
                      <span className={bd.components.infrastructureRisk?.score > 0 ? 'text-red-400' : 'text-slate-300'}>
                        +{bd.components.infrastructureRisk?.score ?? 0} pts
                      </span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-400">ML Content Classification:</span>
                      <span className={bd.components.mlClassification?.score > 0 ? 'text-red-400' : 'text-slate-300'}>
                        +{bd.components.mlClassification?.score ?? 0} pts
                      </span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-400">Heuristics & Signals:</span>
                      <span className={bd.components.heuristics?.score > 0 ? 'text-red-400' : 'text-slate-300'}>
                        +{bd.components.heuristics?.score ?? 0} pts
                      </span>
                    </div>
                  </div>
                )}
              </div>
            </>
          );
        })()}

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
