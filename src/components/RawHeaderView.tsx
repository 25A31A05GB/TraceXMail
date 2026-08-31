import React, { useState } from 'react';
import { FileText, Copy, Check, Terminal, Filter, Code, Eye } from 'lucide-react';
import { EmailAnalysis } from '../types';

interface RawHeaderViewProps {
  analysis: EmailAnalysis;
}

export function RawHeaderView({ analysis }: RawHeaderViewProps) {
  const [copied, setCopied] = useState(false);
  const [filterQuery, setFilterQuery] = useState('');
  const [viewMode, setViewMode] = useState<'parsed' | 'raw'>('parsed');

  const rawText = analysis.rawHeaders || 'No raw headers available for this analysis.';

  const handleCopy = () => {
    navigator.clipboard.writeText(rawText);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  // Parse headers into key-value pairs
  const headerLines = rawText.split('\n');
  const parsedHeaders: { key: string; value: string }[] = [];
  let currentKey = '';
  let currentValue = '';

  for (const line of headerLines) {
    const match = line.match(/^([A-Za-z0-9-_]+):\s*(.*)$/);
    if (match) {
      if (currentKey) {
        parsedHeaders.push({ key: currentKey, value: currentValue.trim() });
      }
      currentKey = match[1];
      currentValue = match[2];
    } else if (line.startsWith(' ') || line.startsWith('\t')) {
      currentValue += ' ' + line.trim();
    }
  }
  if (currentKey) {
    parsedHeaders.push({ key: currentKey, value: currentValue.trim() });
  }

  const filteredHeaders = parsedHeaders.filter(
    h => h.key.toLowerCase().includes(filterQuery.toLowerCase()) || 
         h.value.toLowerCase().includes(filterQuery.toLowerCase())
  );

  return (
    <div className="flex-1 flex flex-col h-full bg-[#0F172A] overflow-hidden p-6 space-y-4">
      {/* Top Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 bg-slate-900 border border-slate-800 rounded-2xl p-4 shadow-xl">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-cyan-950/80 border border-cyan-800/80 flex items-center justify-center">
            <FileText className="w-5 h-5 text-cyan-400" />
          </div>
          <div>
            <h2 className="text-base font-bold text-slate-100 flex items-center gap-2">
              <span>RFC822 / RFC5322 Raw Header Forensics</span>
            </h2>
            <p className="text-xs text-slate-400">Inspecting immutable email envelope headers and routing signatures</p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <div className="flex bg-slate-950 rounded-lg p-1 border border-slate-800">
            <button
              onClick={() => setViewMode('parsed')}
              className={`px-3 py-1 rounded text-xs font-semibold transition-colors ${
                viewMode === 'parsed' ? 'bg-cyan-600 text-white' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Key-Value Table
            </button>
            <button
              onClick={() => setViewMode('raw')}
              className={`px-3 py-1 rounded text-xs font-semibold transition-colors ${
                viewMode === 'raw' ? 'bg-cyan-600 text-white' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Raw Text
            </button>
          </div>

          <button
            onClick={handleCopy}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-slate-200 border border-slate-700 transition-colors"
          >
            {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
            <span>{copied ? 'Copied' : 'Copy Headers'}</span>
          </button>
        </div>
      </div>

      {/* Main Display Area */}
      <div className="flex-1 flex flex-col min-h-0 bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden shadow-xl">
        {viewMode === 'parsed' ? (
          <div className="flex-1 flex flex-col min-h-0">
            <div className="p-3 border-b border-slate-800 bg-slate-950/40">
              <input
                type="text"
                value={filterQuery}
                onChange={(e) => setFilterQuery(e.target.value)}
                placeholder="Filter headers by key or value (e.g. Received, Authentication-Results, DKIM)..."
                className="w-full px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-700 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
              />
            </div>
            <div className="flex-1 overflow-y-auto divide-y divide-slate-800 font-mono text-xs">
              {filteredHeaders.map((h, i) => {
                const isCriticalHeader = ['received', 'authentication-results', 'dkim-signature', 'message-id', 'from', 'return-path'].includes(h.key.toLowerCase());
                return (
                  <div key={i} className={`p-3 flex flex-col md:flex-row gap-2 hover:bg-slate-850 transition-colors ${
                    isCriticalHeader ? 'bg-cyan-950/10' : ''
                  }`}>
                    <div className="md:w-56 shrink-0 font-bold text-cyan-400 truncate">
                      {h.key}:
                    </div>
                    <div className="text-slate-300 break-all flex-1 select-all">
                      {h.value}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        ) : (
          <div className="flex-1 overflow-y-auto p-4 bg-slate-950 font-mono text-xs text-slate-300 leading-relaxed whitespace-pre-wrap select-all">
            {rawText}
          </div>
        )}
      </div>
    </div>
  );
}
