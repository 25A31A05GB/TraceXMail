import React, { useState } from 'react';
import { ChevronDown, ChevronUp, HelpCircle, ShieldCheck, AlertCircle, Link2, ListChecks } from 'lucide-react';
import { WhyExplanation } from '../types';

interface WhyAffordanceProps {
  why?: WhyExplanation;
  title?: string;
  badgeLabel?: string;
  defaultExpanded?: boolean;
}

export function WhyAffordance({
  why,
  title = 'Forensic Explanation & Evidence Chain',
  badgeLabel = 'Reasoning',
  defaultExpanded = false
}: WhyAffordanceProps) {
  const [isOpen, setIsOpen] = useState(defaultExpanded);

  if (!why) return null;

  return (
    <div className="rounded-lg border border-slate-700 bg-slate-900/80 overflow-hidden text-xs">
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="w-full px-3 py-2 flex items-center justify-between bg-slate-800/60 hover:bg-slate-800 transition-colors text-left"
      >
        <div className="flex items-center gap-2 min-w-0">
          <HelpCircle className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
          <span className="font-semibold text-slate-200 truncate">{title}</span>
          <span className="px-1.5 py-0.2 rounded bg-cyan-950/60 border border-cyan-800/80 text-[10px] text-cyan-400 font-mono">
            {badgeLabel}
          </span>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          {why.confidence !== undefined && (
            <span className="text-[10px] text-slate-400 font-mono">
              {(why.confidence * 100).toFixed(0)}% conf
            </span>
          )}
          {isOpen ? <ChevronUp className="w-3.5 h-3.5 text-slate-400" /> : <ChevronDown className="w-3.5 h-3.5 text-slate-400" />}
        </div>
      </button>

      {isOpen && (
        <div className="p-3 space-y-2.5 border-t border-slate-800 text-slate-300">
          {why.why && (
            <div>
              <div className="text-[10px] uppercase font-bold text-slate-400 mb-0.5">Summary Logic:</div>
              <p className="leading-relaxed text-slate-200">{why.why}</p>
            </div>
          )}

          {why.evidence_chain && why.evidence_chain.length > 0 && (
            <div>
              <div className="text-[10px] uppercase font-bold text-slate-400 mb-1 flex items-center gap-1">
                <ListChecks className="w-3 h-3 text-cyan-400" />
                <span>Evidence Chain ({why.evidence_chain.length}):</span>
              </div>
              <ul className="space-y-1 pl-2">
                {why.evidence_chain.map((item, idx) => (
                  <li key={idx} className="flex items-start gap-1.5 text-slate-300">
                    <span className="text-cyan-400">•</span>
                    <span className="break-words">{item}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {why.limitation && (
            <div className="p-2 rounded bg-amber-950/20 border border-amber-800/40 text-[11px] text-amber-300 flex items-start gap-1.5">
              <AlertCircle className="w-3.5 h-3.5 text-amber-400 shrink-0 mt-0.5" />
              <div>
                <span className="font-bold">Limitation / Caveat: </span>
                <span>{why.limitation}</span>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
