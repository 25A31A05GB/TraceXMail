import React, { useState } from 'react';
import { HelpCircle } from 'lucide-react';

const JARGON_MAP: Record<string, { term: string; definition: string }> = {
  SPF: {
    term: 'Sender Policy Framework (SPF)',
    definition: 'Validates that the sending server IP is explicitly authorized by the domain owner in DNS.'
  },
  DKIM: {
    term: 'DomainKeys Identified Mail (DKIM)',
    definition: 'A digital cryptographic signature ensuring the email message body and headers were not altered in transit.'
  },
  DMARC: {
    term: 'Domain-based Message Authentication (DMARC)',
    definition: 'Specifies how email receivers should handle messages that fail SPF or DKIM policy checks (e.g., reject or quarantine).'
  },
  ASN: {
    term: 'Autonomous System Number (ASN)',
    definition: 'A unique identifier for the network operator or datacenter infrastructure hosting the sending IP address.'
  },
  RDAP: {
    term: 'Registration Data Access Protocol (RDAP)',
    definition: 'Modern protocol used to query official domain ownership, creation age, and registrar records.'
  },
  NXDOMAIN: {
    term: 'Non-Existent Domain (NXDOMAIN)',
    definition: 'Indicates the domain name does not exist in public Domain Name System (DNS) servers.'
  },
  TYPOSQUATTING: {
    term: 'Typosquatting / Lookalike Domain',
    definition: 'Registering a domain name closely mimicking a trusted brand (e.g. paypa1.com instead of paypal.com).'
  },
  BEC: {
    term: 'Business Email Compromise (BEC)',
    definition: 'Social engineering attack impersonating executives or vendors to request unauthorized wire transfers or payroll changes.'
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
