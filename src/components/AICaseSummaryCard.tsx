import { Sparkles, Info } from 'lucide-react';
import { AINarrative } from '../types';

interface AICaseSummaryCardProps {
  aiNarrative?: AINarrative | null;
  ai_narrative?: AINarrative | null;
}

export function AICaseSummaryCard({ aiNarrative, ai_narrative }: AICaseSummaryCardProps) {
  const data = aiNarrative || ai_narrative;

  if (!data || !data.narrative) {
    return null;
  }

  return (
    <div className="bg-[#1a1712] border border-[#3a352c] rounded-lg p-5 shadow-sm relative overflow-hidden">
      <div className="flex items-center justify-between border-b border-[#3a352c] pb-3">
        <div className="flex items-center gap-2.5">
          <div className="w-8 h-8 rounded bg-[#b23a2e]/20 border border-[#b23a2e]/40 flex items-center justify-center text-[#d97768] font-bold">
            <Sparkles className="w-4 h-4 text-[#d97768]" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-xs font-bold text-amber-200/90 uppercase tracking-wider font-mono">
                AI Case Summary
              </span>
              <span className="px-2 py-0.5 rounded text-[10px] font-sans font-semibold bg-[#b23a2e]/20 text-[#ede6d8] border border-[#b23a2e]/40">
                FORENSIC AI NARRATIVE SYNTHESIS
              </span>
            </div>
            {data.model && (
              <div className="text-[11px] text-slate-400 font-mono mt-0.5">
                Model: <span className="text-amber-300">{data.model}</span>
              </div>
            )}
          </div>
        </div>
      </div>

      <div className="mt-3 text-xs text-[#ede6d8] leading-relaxed font-sans bg-[#14120f] p-4 rounded border border-[#3a352c] whitespace-pre-line">
        {data.narrative}
      </div>

      {data.disclaimer && (
        <div className="mt-2.5 flex items-start gap-1.5 text-[10px] text-slate-400 italic font-mono">
          <Info className="w-3.5 h-3.5 text-purple-400 shrink-0 mt-0.5" />
          <span>{data.disclaimer}</span>
        </div>
      )}
    </div>
  );
}
