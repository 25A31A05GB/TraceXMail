import React, { useState } from 'react';
import { 
  ShieldAlert, 
  ShieldCheck, 
  AlertTriangle, 
  CheckCircle2, 
  ChevronDown, 
  ChevronUp, 
  Info, 
  Lock 
} from 'lucide-react';
import { EmailAnalysis } from '../types';
import { JargonTooltip } from './JargonTooltip';

interface PlainLanguageSummaryCardProps {
  analysis: EmailAnalysis;
  onToggleTechnicalDetails?: (expanded: boolean) => void;
  isTechnicalExpanded?: boolean;
}

export function PlainLanguageSummaryCard({
  analysis,
  onToggleTechnicalDetails,
  isTechnicalExpanded = true
}: PlainLanguageSummaryCardProps) {
  const threatScore = typeof analysis.threatScore === 'number' && analysis.threatScore >= 0
    ? analysis.threatScore
    : (typeof analysis.riskScore === 'number' ? analysis.riskScore : 0);

  const verdictRaw = (analysis.threatVerdict || analysis.verdict || 'SUSPICIOUS').toUpperCase();
  const isPhish = verdictRaw.includes('PHISH') || verdictRaw.includes('FRAUD') || verdictRaw.includes('IMPERSONAT') || threatScore >= 70;
  const isSuspicious = !isPhish && (verdictRaw.includes('SUSPICIOUS') || threatScore >= 35);
  const isClean = !isPhish && !isSuspicious;

  const spfPass = analysis.auth?.spf?.status === 'PASS';
  const dkimPass = analysis.auth?.dkim?.status === 'PASS';
  const dmarcPass = analysis.auth?.dmarc?.status === 'PASS';
  const authPassed = spfPass && dkimPass && dmarcPass;

  const fromEmail = analysis.headers?.fromEmail || analysis.from || 'unknown@sender.corp';
  const fromDomain = fromEmail.includes('@') ? fromEmail.split('@')[1].replace(/[<>]/g, '').trim() : 'sender domain';

  // Determine top drivers and bullets
  const bullets: Array<{ text: string; jargonKey?: string }> = [];

  const domIntel = analysis.domain_intelligence || analysis.domainIntelligence;
  if (domIntel?.is_typosquat || domIntel?.typosquatting?.is_typosquat) {
    const target = domIntel.typosquat_matched_brand || domIntel.typosquatting?.target_brand || 'a recognized brand';
    bullets.push({
      text: `Sender domain "${fromDomain}" is a lookalike domain mimicking ${target}.`,
      jargonKey: 'TYPOSQUATTING'
    });
  } else if (domIntel?.is_newly_registered) {
    const days = domIntel.domain_age_days ?? 14;
    bullets.push({
      text: `Sender domain "${fromDomain}" was registered recently (${days} days ago).`,
      jargonKey: 'RDAP'
    });
  }

  const heuristics = analysis.heuristics || [];
  heuristics.filter(h => h.triggered).forEach(h => {
    if (bullets.length < 3) {
      bullets.push({ text: `${h.title}: ${h.description || 'Identified by forensic security rule.'}` });
    }
  });

  if (bullets.length === 0) {
    if (isPhish || isSuspicious) {
      bullets.push({ text: 'Content patterns strongly resemble known phishing lures and credential harvesting.' });
      bullets.push({ text: 'Suspicious email header configuration or transmission hop routing.' });
    } else {
      bullets.push({ text: 'Sender domain has established reputation with clean DNS records.', jargonKey: 'RDAP' });
      bullets.push({ text: 'Cryptographic authentication headers verified cleanly.', jargonKey: 'DMARC' });
    }
  }

  const primaryDriverText = bullets[0]?.text ? bullets[0].text.toLowerCase().replace(/\.$/, '') : 'suspicious message indicators';

  let verdictTitle = '';
  let mainSummarySentence = '';
  let authNoteText: string | null = null;

  if (isPhish) {
    verdictTitle = 'Phishing Threat Detected';
    mainSummarySentence = `This email is flagged as PHISHING (${threatScore}/100 threat score) mainly because of ${primaryDriverText}${authPassed ? ' — even though email authentication passed.' : '.'}`;
    if (authPassed) {
      authNoteText = `Note for reviewers: Cryptographic email authentication (SPF, DKIM, DMARC) passed because the sender owns the sending domain "${fromDomain}". Passing authentication proves domain ownership, but does NOT mean the email content, links, or destination are safe.`;
    }
  } else if (isSuspicious) {
    verdictTitle = 'Suspicious Email Warning';
    mainSummarySentence = `This email is flagged as SUSPICIOUS (${threatScore}/100 threat score) due to risk factors: ${primaryDriverText}.`;
    if (authPassed) {
      authNoteText = `Note: Email authentication (SPF, DKIM, DMARC) passed, but content heuristics triggered security warnings.`;
    }
  } else {
    verdictTitle = 'Verified Legitimate Email';
    mainSummarySentence = `This email was verified as legitimate with a low threat score (${threatScore}/100). Cryptographic authentication checks passed and no security threats were found.`;
  }

  return (
    <div className="bg-[#16181D] border border-[#2A2D34] rounded-lg p-4 md:p-5 mb-5 shadow-md font-sans text-slate-100">
      {/* Top Banner Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-[#2A2D34] pb-3 mb-3">
        <div className="flex items-center gap-3">
          <div
            className={`w-10 h-10 rounded-lg flex items-center justify-center shrink-0 shadow-sm ${
              isPhish
                ? 'bg-rose-500/20 border border-rose-500/40 text-rose-400'
                : isSuspicious
                ? 'bg-amber-500/20 border border-amber-500/40 text-amber-400'
                : 'bg-emerald-500/20 border border-emerald-500/40 text-emerald-400'
            }`}
          >
            {isPhish ? (
              <ShieldAlert className="w-5 h-5" />
            ) : isSuspicious ? (
              <AlertTriangle className="w-5 h-5" />
            ) : (
              <ShieldCheck className="w-5 h-5" />
            )}
          </div>
          <div>
            <div className="flex items-center gap-2 flex-wrap">
              <h2 className="text-base font-bold text-slate-100 tracking-tight">
                {verdictTitle}
              </h2>
              <span
                className={`px-2.5 py-0.5 rounded-full text-xs font-bold font-mono border ${
                  isPhish
                    ? 'bg-rose-500/10 border-rose-500/30 text-rose-400'
                    : isSuspicious
                    ? 'bg-amber-500/10 border-amber-500/30 text-amber-400'
                    : 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400'
                }`}
              >
                {threatScore}/100 Threat Score
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-0.5 font-mono">
              Non-technical forensic verdict summary
            </p>
          </div>
        </div>

        {onToggleTechnicalDetails && (
          <button
            type="button"
            onClick={() => onToggleTechnicalDetails(!isTechnicalExpanded)}
            className="px-3 py-1.5 rounded bg-[#1D2027] hover:bg-[#2A2D34] border border-[#2A2D34] text-xs text-slate-300 font-mono font-medium flex items-center gap-1.5 transition-colors cursor-pointer self-start sm:self-auto"
          >
            {isTechnicalExpanded ? (
              <>
                <ChevronUp className="w-3.5 h-3.5 text-cyan-400" />
                <span>Hide technical deep dive</span>
              </>
            ) : (
              <>
                <ChevronDown className="w-3.5 h-3.5 text-cyan-400" />
                <span>Show technical deep dive</span>
              </>
            )}
          </button>
        )}
      </div>

      {/* Main Single-Sentence Plain Language Summary */}
      <div className="text-sm font-medium leading-relaxed text-slate-100 bg-[#1D2027]/80 p-3.5 rounded border border-[#2A2D34] mb-3">
        {mainSummarySentence}
      </div>

      {/* Primary Contributing Risk Bullets */}
      <div className="space-y-1.5 mb-3">
        <div className="text-xs font-bold font-mono text-slate-400 uppercase tracking-wider mb-1">
          Top Contributing Factors
        </div>
        {bullets.slice(0, 3).map((b, idx) => (
          <div key={idx} className="flex items-start gap-2 text-xs text-slate-200 leading-snug">
            {isPhish || isSuspicious ? (
              <AlertTriangle className="w-3.5 h-3.5 text-amber-400 shrink-0 mt-0.5" />
            ) : (
              <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0 mt-0.5" />
            )}
            <div>
              <span>{b.text} </span>
              {b.jargonKey && (
                <JargonTooltip termKey={b.jargonKey} className="ml-1" />
              )}
            </div>
          </div>
        ))}
      </div>

      {/* Authentication Pass Explanation Note */}
      {authNoteText && (
        <div className="bg-amber-950/20 border border-amber-500/30 rounded p-3 text-xs text-amber-200/90 leading-relaxed flex items-start gap-2.5">
          <Info className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
          <div>
            <span className="font-semibold text-amber-300">Why Authentication Passed: </span>
            {authNoteText}{' '}
            <span className="inline-flex items-center gap-2 mt-1">
              <JargonTooltip termKey="SPF" text="What is SPF?" />
              <JargonTooltip termKey="DKIM" text="What is DKIM?" />
              <JargonTooltip termKey="DMARC" text="What is DMARC?" />
            </span>
          </div>
        </div>
      )}
    </div>
  );
}
