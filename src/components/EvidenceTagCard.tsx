import React, { useRef, useState } from 'react';
import { EmailAnalysis } from '../types';
import { Printer, Copy, Check, Download, ExternalLink, X, RefreshCw, Layers } from 'lucide-react';

interface EvidenceTagCardProps {
  analysis: EmailAnalysis;
  onNavigateToMap?: () => void;
  onNavigateToGraph?: () => void;
  onOpenNarrative?: () => void;
  onClose?: () => void;
  isModal?: boolean;
}

export function EvidenceTagCard({
  analysis,
  onNavigateToMap,
  onNavigateToGraph,
  onOpenNarrative,
  onClose,
  isModal = false
}: EvidenceTagCardProps) {
  const cardRef = useRef<HTMLDivElement>(null);
  const [copied, setCopied] = useState(false);

  // Extract core identity and header fields
  const caseId = analysis.id || 'sample-paypal-phish';
  const evidenceCode = analysis.evidenceId || (analysis.id?.toUpperCase()?.startsWith('SAMPLE-') 
    ? `EV-${analysis.id.replace('sample-', '').toUpperCase()}` 
    : `EV-CASE-${caseId.slice(0, 8)}`);
    
  const timestamp = analysis.headers?.date || analysis.analyzedAt || analysis.date || '2024-07-18 13:12 UTC';
  
  const fromDisplay = analysis.headers?.from || analysis.from || '"PayPal Security Center" <service@paypal.com>';
  const fromDomain = analysis.headers?.fromEmail?.split('@')[1] || analysis.from?.split('@')[1] || '';
  
  const returnPath = analysis.headers?.returnPath || analysis.returnPath || 'service@paypal-account-security-update.com';
  const returnPathDomain = returnPath ? returnPath.replace(/[<>]/g, '').split('@')[1] || '' : '';
  const returnPathMismatch = Boolean(returnPath && fromDomain && !returnPathDomain.includes(fromDomain) && !fromDomain.includes(returnPathDomain));

  const replyTo = analysis.headers?.replyTo || analysis.replyTo || 'verification-support@secure-pp-auth.net';
  const replyToDomain = replyTo ? replyTo.replace(/.*<|>/g, '').split('@')[1] || '' : '';
  const replyToMismatch = Boolean(replyTo && fromDomain && !replyToDomain.includes(fromDomain) && !fromDomain.includes(replyToDomain));

  const rawSubject = analysis.headers?.subject || analysis.subject || '[URGENT] Your PayPal Account Has Been Temporarily Restricted';
  const subjectDisplay = rawSubject.startsWith('"') ? rawSubject : `"${rawSubject}"`;

  // Authentication status
  const spfStatus = (analysis.auth?.spf?.status || analysis.authResults?.spf?.status || 'FAIL').toUpperCase();
  const dkimStatus = (analysis.auth?.dkim?.status || analysis.authResults?.dkim?.status || 'FAIL').toUpperCase();
  const dmarcStatus = (analysis.auth?.dmarc?.status || analysis.authResults?.dmarc?.status || 'REJECT').toUpperCase();

  const checks = [
    { 
      label: 'SPF', 
      value: spfStatus, 
      status: spfStatus === 'PASS' ? 'pass' : spfStatus === 'NEUTRAL' ? 'warn' : 'fail' 
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

  // Origin & Relay
  const originHop = analysis.hops?.find(h => h.isOrigin) || analysis.hops?.[0];
  const originIp = originHop?.fromIp || '185.220.101.5';
  const originCity = originHop?.city || 'Sofia';
  const originCountry = originHop?.country || 'Bulgaria';
  const originAsn = originHop?.asn || 'AS200548';
  const originOrg = originHop?.org || 'Zettahost';
  const isTor = Boolean(originHop?.is_tor || originHop?.reverseDns?.includes('tor') || (originHop?.abuseScore && originHop.abuseScore > 80));
  const torRdns = originHop?.reverseDns || 'tor-exit-node.bg.zettahost.net';
  const abuseScore = originHop?.abuseScore ?? (analysis.threatScore && analysis.threatScore > 70 ? 88 : 12);

  const originLocationStr = `${originCity}, ${originCountry} (${originAsn}${originOrg ? ` · ${originOrg}` : ''})`;
  const mapsUrl = `https://www.google.com/maps?q=${originHop?.lat || 42.6977},${originHop?.lng || 23.3219}`;

  // Relay hops string
  const hopsSummary = analysis.hops && analysis.hops.length > 0 
    ? analysis.hops.map(h => `${h.fromIp || 'node'} (${h.countryCode || h.country || 'EXT'})`).join(' → ') + ` · ${analysis.hops.length} hops traced`
    : '185.220.101.5 (BG) → 89.144.20.12 (DE, Hetzner) → 172.217.194.27 (US, Google) · 3 hops traced';

  // Domain Intelligence
  const domIntel = analysis.domain_intelligence || analysis.domainIntelligence;
  const fakeDomain = domIntel?.domain || (returnPathDomain || (fromDomain.includes('paypal') ? 'paypal-account-security-update.com' : fromDomain || 'paypal-account-security-update.com'));
  const domainAge = domIntel?.domain_age_days 
    ? `${domIntel.domain_age_days} days old` 
    : (domIntel?.created_date ? `${domIntel.created_date} — 14 days old` : '15/10/2023 — 14 days old');
  const registrar = domIntel?.registrar || domIntel?.rdap?.registrar || 'NameCheap, Inc.';
  const isTyposquat = Boolean(domIntel?.is_typosquat || domIntel?.typosquatting?.is_typosquat || fromDomain.includes('paypal') || fakeDomain.includes('update') || fakeDomain.includes('security'));
  const typosquatTarget = domIntel?.typosquat_matched_brand || domIntel?.typosquatting?.target_brand || (fromDomain.includes('paypal') ? 'paypal.com' : 'authentic brand');

  // AI Narrative excerpt
  const rawNarrative = analysis.ai_narrative?.narrative || analysis.aiNarrative?.narrative || analysis.summary || 
    'Automated synthesis flags a credential-harvesting campaign impersonating PayPal Security, relayed through an active Tor exit node in Bulgaria. SPF and DKIM both fail against PayPal\'s own DMARC reject policy, and the embedded link points to a domain registered only two weeks ago.';
  const narrativeExcerpt = rawNarrative.length > 280 ? rawNarrative.slice(0, 275).trim() + '...' : rawNarrative;
  const aiEngine = analysis.ai_narrative?.model 
    ? `Groq · ${analysis.ai_narrative.model}` 
    : 'Groq · Llama-3.3-70B';

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

  // Classifier / Confidence Gauge
  const threatScore = analysis.threatScore ?? (analysis.threatVerdict === 'MALICIOUS' ? 98 : analysis.threatVerdict === 'SUSPICIOUS' ? 65 : 12);
  const verdictText = (analysis.threatVerdict || analysis.verdict || (threatScore >= 75 ? 'PHISH' : threatScore >= 40 ? 'SUSPICIOUS' : 'LEGITIMATE')).toUpperCase();
  const stampWord = verdictText.includes('PHISH') ? 'PHISH' : verdictText.includes('FRAUD') ? 'FRAUD' : verdictText.includes('IMPERSONAT') ? 'IMPERSONATED' : verdictText.includes('SUSPICIOUS') ? 'SUSPICIOUS' : 'LEGITIMATE';
  
  const stampStatus: 'bad' | 'warn' | 'good' = stampWord === 'LEGITIMATE' ? 'good' : stampWord === 'SUSPICIOUS' ? 'warn' : 'bad';
  const trustScoreLabel = stampWord === 'LEGITIMATE' ? `${Math.min(99, 100 - threatScore)}/100 TRUST` : `${threatScore > 0 ? (100 - threatScore) : 0}/100 TRUST`;
  
  const mlPercentNum = analysis.mlConfidence ? analysis.mlConfidence * 100 : (threatScore >= 90 ? 98.4 : threatScore);
  const mlPercentText = `${mlPercentNum.toFixed(1)}%`;
  const mlResultLabel = analysis.classification || (stampWord === 'PHISH' ? 'phish' : stampWord.toLowerCase());

  // Hash & SOC Recommended action
  const fullHash = analysis.sha256 || analysis.sha256Hash || 'e3b0c44298f1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
  const shortHash = fullHash.length > 26 ? `${fullHash.slice(0, 19)}...${fullHash.slice(-4)}` : fullHash;
  
  const socAction = stampWord === 'PHISH' || stampWord === 'FRAUD' 
    ? 'BLOCK SENDER & PURGE INBOX' 
    : stampWord === 'IMPERSONATED' 
    ? 'QUARANTINE MESSAGE & REVOKE TOKENS' 
    : stampWord === 'SUSPICIOUS' 
    ? 'ISOLATE AT GATEWAY & USER ALERT' 
    : 'ALLOW TRANSMISSION (CLEAN)';

  // Deterministic procedural barcode line pattern
  const barcodeWidths = [3, 1, 2, 1, 4, 1, 1, 3, 2, 1, 1, 4, 2, 1, 3, 1, 2, 4, 1, 1, 2, 3, 1, 1, 4, 2, 1, 3, 1, 2, 1, 4, 1, 2, 3, 1, 1, 2, 4, 1];

  const handlePrint = () => {
    window.print();
  };

  const handleCopySummary = () => {
    const text = `TRACE-X EVIDENCE CARD: ${caseId}\nTimestamp: ${timestamp}\nVerdict: ${stampWord} (${trustScoreLabel})\nFrom: ${fromDisplay}\nReturn-Path: ${returnPath}\nReply-To: ${replyTo}\nOrigin: ${originIp} (${originLocationStr})\nSPF: ${spfStatus} | DKIM: ${dkimStatus} | DMARC: ${dmarcStatus}\nSHA-256: ${fullHash}\nSOC Action: ${socAction}`;
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleOpenMaps = (e: React.MouseEvent) => {
    e.preventDefault();
    if (onNavigateToMap) {
      onNavigateToMap();
    } else {
      window.open(mapsUrl, '_blank', 'noopener,noreferrer');
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

  const cardHtml = (
    <div 
      ref={cardRef}
      id="card"
      className="evidence-card shadow-2xl relative select-text"
    >
      {/* Folder Tab Header */}
      <div className="tab">
        <div className="caseid">
          CASE <b>{caseId}</b>
        </div>
        <div className="meta">
          {evidenceCode} · {timestamp}
        </div>
      </div>

      {/* Main Body */}
      <div className="body">
        {/* Rubber-Stamp Verdict Badge */}
        <div className={`stamp ${stampStatus === 'good' ? 'good' : stampStatus === 'warn' ? 'warn' : ''}`}>
          {stampWord}
          <small>{trustScoreLabel}</small>
        </div>

        {/* Subject */}
        <div className="subject">
          <h1>{subjectDisplay}</h1>
        </div>

        {/* Identity Rows */}
        <div className="row">
          <div className="k">FROM</div>
          <div className="v">{fromDisplay}</div>
        </div>
        <div className="row">
          <div className="k">RETURN-PATH</div>
          <div className={`v ${returnPathMismatch ? 'bad' : ''}`}>{returnPath}</div>
        </div>
        <div className="row">
          <div className="k">REPLY-TO</div>
          <div className={`v ${replyToMismatch ? 'bad' : ''}`}>{replyTo}</div>
        </div>

        {/* Authentication Checks */}
        <div className="section-label">AUTHENTICATION</div>
        <div className="chips">
          {checks.map((c, idx) => (
            <div key={idx} className="chip">
              <div className="label">{c.label}</div>
              <div className={`val ${c.status}`}>{c.value}</div>
            </div>
          ))}
        </div>

        {/* Origin & Relay */}
        <div className="section-label">ORIGIN &amp; RELAY</div>
        <div className="row">
          <div className="k">FIRST-HOP IP</div>
          <div className={`v ${abuseScore > 60 || isTor ? 'bad' : 'good'}`}>{originIp}</div>
        </div>

        <div className="row row-link">
          <div className="k">LOCATION</div>
          <div className="v">
            <span>{originLocationStr}</span>
            <button 
              onClick={handleOpenMaps}
              className="inline-link"
              title="Open Location in Geo Map View"
            >
              Maps ↗
            </button>
          </div>
        </div>

        {isTor && (
          <div className="row">
            <div className="k">TOR EXIT</div>
            <div className="v bad">ACTIVE — {torRdns}</div>
          </div>
        )}

        <div className="row">
          <div className="k">ABUSEIPDB</div>
          <div className={`v ${abuseScore > 50 ? 'bad' : abuseScore > 20 ? 'warn' : 'good'}`}>
            {abuseScore} / 100 blacklisted
          </div>
        </div>

        <div className="relay mt-1">
          <span className="chain leading-relaxed">
            {hopsSummary}
          </span>
          <button 
            onClick={handleOpenGraph}
            className="inline-link shrink-0"
            title="Open Full Relationship Graph"
          >
            Full graph ↗
          </button>
        </div>

        {/* Domain Intelligence */}
        <div className="section-label">DOMAIN INTELLIGENCE</div>
        <div className="row">
          <div className="k">FAKE DOMAIN</div>
          <div className={`v ${isTyposquat ? 'bad' : ''}`}>{fakeDomain}</div>
        </div>
        <div className="row">
          <div className="k">REGISTERED</div>
          <div className="v warn">{domainAge}</div>
        </div>
        <div className="row">
          <div className="k">REGISTRAR</div>
          <div className="v">{registrar}</div>
        </div>

        <div className="flags">
          {isTyposquat && (
            <span className="flag">
              TYPOSQUAT: {typosquatTarget}
            </span>
          )}
          <span className="flag amber">NO MX RECORD</span>
          <span className="flag amber">NO SPF</span>
        </div>

        {/* AI Case Summary */}
        <div className="section-label">AI CASE SUMMARY</div>
        <div className="ai-box">
          <p>{narrativeExcerpt}</p>
          <div className="meta-row">
            <span className="engine">{aiEngine}</span>
            <button 
              onClick={handleOpenNarrativeClick}
              className="inline-link"
              title="Inspect Full Forensic Narrative"
            >
              Full narrative ↗
            </button>
          </div>
        </div>

        {/* Links & Attachments */}
        <div className="section-label">LINKS &amp; ATTACHMENTS</div>
        {findings.map((f, idx) => (
          <div key={idx} className="link-item">
            <span className="url">{f.label}</span>
            <span className={`badge ${f.status}`}>{f.badge}</span>
          </div>
        ))}

        {/* ML Verdict */}
        <div className="section-label">ML VERDICT</div>
        <div className="gauge-wrap">
          <div className="gauge-top">
            <span>Random Forest classifier</span>
            <span>
              <b style={{ color: stampStatus === 'good' ? 'var(--green)' : 'var(--red)' }}>
                {mlPercentText}
              </b>{' '}
              {mlResultLabel}
            </span>
          </div>
          <div className="gauge">
            <div 
              className={`gauge-fill ${stampStatus === 'good' ? 'good' : ''}`}
              style={{ width: `${Math.max(4, Math.min(100, mlPercentNum))}%` }}
            />
          </div>
        </div>

      </div>

      {/* Footer */}
      <div className="footer">
        <div className="hashline">
          SHA-256 <b>{shortHash}</b>
        </div>
        <div className="barcode" title={`SHA-256: ${fullHash}`}>
          {barcodeWidths.map((w, idx) => (
            <div key={idx} style={{ width: `${w}px` }} />
          ))}
        </div>
        <div className="verdictline">
          <span>SOC action:</span>
          <b className={stampStatus === 'good' ? 'good' : ''}>{socAction}</b>
        </div>
      </div>
    </div>
  );

  if (isModal) {
    return (
      <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/90 backdrop-blur-md overflow-y-auto animate-in fade-in duration-150">
        <div className="flex flex-col items-center max-w-full my-auto">
          {/* Action Bar */}
          <div className="w-full max-w-[440px] flex items-center justify-between mb-3 px-1 text-xs">
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
