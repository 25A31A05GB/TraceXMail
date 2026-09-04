import React, { useState } from 'react';
import { HelpCircle } from 'lucide-react';

const JARGON_MAP: Record<string, { term: string; definition: string }> = {
  SPF: {
    term: 'SPF (Sender Policy Framework)',
    definition: 'Checks if sender is authorized by domain owner.'
  },
  DKIM: {
    term: 'DKIM (DomainKeys Identified Mail)',
    definition: 'Verifies message was not altered in transit.'
  },
  DMARC: {
    term: 'DMARC (Domain-based Message Authentication)',
    definition: 'Tells receivers what to do if authentication fails.'
  },
  ASN: {
    term: 'ASN (Autonomous System Number)',
    definition: 'Identifies the network operator or datacenter hosting the sending server.'
  },
  CIDR: {
    term: 'CIDR (Classless Inter-Domain Routing)',
    definition: 'Standard IP subnet notation defining an address range.'
  },
  RDAP: {
    term: 'RDAP (Domain Registry Intelligence)',
    definition: 'Queries authoritative registry records for domain creation age, registrar, and ownership.'
  },
  NXDOMAIN: {
    term: 'NXDOMAIN (Non-Existent Domain)',
    definition: 'Indicates the domain name does not exist in authoritative public DNS servers.'
  },
  TYPOSQUATTING: {
    term: 'Typosquatting (Lookalike Domain)',
    definition: 'A deceptive domain name registered with deliberate typos to trick recipients (e.g. paypa1.com).'
  },
  TOR: {
    term: 'Tor Exit Node',
    definition: 'Anonymized routing relay often abused by threat actors to conceal origin network location.'
  },
  BEC: {
    term: 'BEC (Business Email Compromise)',
    definition: 'Impersonation attack targeting employees to authorize fraudulent wire transfers or disclose credentials.'
  }
};

interface JargonTooltipProps {
  termKey: string;
  text?: string;
  className?: string;
}

export function JargonTooltip({ termKey, text, className = '' }: JargonTooltipProps) {
  const [show, setShow] = useState(false);
  const info = JARGON_MAP[termKey.toUpperCase()];

  if (!info) {
    return <span className={className}>{text || termKey}</span>;
  }

  return (
    <span className={`inline-flex items-center gap-1 relative group cursor-help ${className}`}>
      <span className="underline decoration-dotted decoration-slate-400 font-medium text-slate-200 hover:text-cyan-300 transition-colors">
        {text || info.term}
      </span>
      <button
        type="button"
        onClick={(e) => {
          e.stopPropagation();
          setShow(!show);
        }}
        onMouseEnter={() => setShow(true)}
        onMouseLeave={() => setShow(false)}
        className="text-slate-400 hover:text-cyan-400 transition-colors p-0.5 rounded cursor-pointer"
        title={info.definition}
        aria-label={`Explanation for ${info.term}`}
      >
        <HelpCircle className="w-3.5 h-3.5 inline-block" />
      </button>
      {show && (
        <span className="absolute bottom-full left-1/2 -translate-x-1/2 mb-2 w-64 p-3 bg-slate-900 border border-cyan-500/50 text-slate-100 text-xs font-sans leading-relaxed rounded-md shadow-2xl z-50 pointer-events-none">
          <strong className="block text-cyan-300 font-semibold mb-1 border-b border-slate-700/80 pb-1">
            {info.term}
          </strong>
          <span className="text-slate-300">{info.definition}</span>
        </span>
      )}
    </span>
  );
}
