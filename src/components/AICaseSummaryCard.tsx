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
    <div className="bg-[#1E293B] border border-purple-500/40 rounded-lg p-5 shadow-sm relative overflow-hidden bg-gradient-to-r from-[#1E293B] via-purple-950/20 to-slate-900">
      <div className="flex items-center justify-between border-b border-purple-500/30 pb-3">
        <div className="flex items-center gap-2.5">
          <div className="w-8 h-8 rounded bg-purple-500/20 border border-purple-500/40 flex items-center justify-center text-purple-300 font-bold">
            <Sparkles className="w-4 h-4 text-purple-300" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-xs font-bold text-purple-200 uppercase tracking-wider font-mono">
                AI Case Summary
              </span>
              <span className="px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-purple-500/20 text-purple-300 border border-purple-500/40">
                GROQ NARRATIVE SYNTHESIS
              </span>
            </div>
            {data.model && (
              <div className="text-[11px] text-slate-400 font-mono mt-0.5">
                Model: <span className="text-purple-300">{data.model}</span>
              </div>
            )}
          </div>
        </div>
      </div>

      <div className="mt-3 text-xs text-slate-200 leading-relaxed font-sans bg-slate-950/50 p-4 rounded border border-purple-900/40 whitespace-pre-line">
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
