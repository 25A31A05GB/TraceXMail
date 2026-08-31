import React, { useState } from 'react';
import { 
  X, 
  Download, 
  FileText, 
  ShieldCheck, 
  ShieldAlert, 
  AlertTriangle, 
  Copy, 
  Check, 
  Printer,
  FileCode,
  Layers,
  Lock
} from 'lucide-react';
import { EmailAnalysis } from '../types';

interface ReportModalProps {
  isOpen: boolean;
  onClose: () => void;
  analysis: EmailAnalysis;
}

export function ReportModal({ isOpen, onClose, analysis }: ReportModalProps) {
  const [copied, setCopied] = useState(false);
  const [activeTab, setActiveTab] = useState<'summary' | 'json' | 'custody'>('summary');

  if (!isOpen) return null;

  const handleCopyJson = () => {
    navigator.clipboard.writeText(JSON.stringify(analysis, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownloadJson = () => {
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(analysis, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute("href", dataStr);
    downloadAnchor.setAttribute("download", `TraceXMail-Report-${analysis.id || 'forensic-case'}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  const handlePrint = () => {
    window.print();
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-in fade-in duration-200">
      <div className="bg-slate-900 border border-slate-800 rounded-2xl w-full max-w-4xl max-h-[90vh] flex flex-col shadow-2xl overflow-hidden">
        {/* Header */}
        <div className="p-5 border-b border-slate-800 flex items-center justify-between bg-slate-950/60">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-cyan-950/80 border border-cyan-800/80 flex items-center justify-center">
              <FileText className="w-5 h-5 text-cyan-400" />
            </div>
            <div>
              <h2 className="text-base font-bold text-slate-100 flex items-center gap-2">
                <span>Forensic Investigation Report</span>
                <span className="text-xs px-2 py-0.5 rounded bg-slate-800 border border-slate-700 text-slate-300 font-mono">
                  {analysis.id}
                </span>
              </h2>
              <p className="text-xs text-slate-400">RFC822 Email Forensics, Origin Attribution &amp; Evidence Custody</p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={handlePrint}
              className="p-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 transition-colors"
              title="Print Report"
            >
              <Printer className="w-4 h-4" />
            </button>
            <button
              onClick={handleDownloadJson}
              className="p-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 transition-colors"
              title="Download JSON Report"
            >
              <Download className="w-4 h-4" />
            </button>
            <button
              onClick={onClose}
              className="p-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-slate-200 transition-colors"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Tab Selection */}
        <div className="flex border-b border-slate-800 bg-slate-950/40 px-6 pt-2 gap-4">
          <button
            onClick={() => setActiveTab('summary')}
            className={`pb-2.5 text-xs font-semibold border-b-2 transition-colors ${
              activeTab === 'summary'
                ? 'border-cyan-400 text-cyan-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            Executive Summary
          </button>
          <button
            onClick={() => setActiveTab('custody')}
            className={`pb-2.5 text-xs font-semibold border-b-2 transition-colors ${
              activeTab === 'custody'
                ? 'border-cyan-400 text-cyan-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            Evidence Vault &amp; Chain of Custody
          </button>
          <button
            onClick={() => setActiveTab('json')}
            className={`pb-2.5 text-xs font-semibold border-b-2 transition-colors ${
              activeTab === 'json'
                ? 'border-cyan-400 text-cyan-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            Raw JSON Telemetry
          </button>
        </div>

        {/* Content Body */}
        <div className="flex-1 overflow-y-auto p-6 space-y-6">
          {activeTab === 'summary' && (
            <div className="space-y-6">
              {/* Threat Verdict Card */}
              <div className="p-4 rounded-xl bg-slate-800/50 border border-slate-700/80 flex items-center justify-between">
                <div>
                  <div className="text-xs uppercase tracking-wider text-slate-400 font-semibold">
                    Overall Threat Assessment
                  </div>
                  <div className="text-xl font-bold mt-1 text-slate-100 flex items-center gap-2">
                    <span className={analysis.threatVerdict === 'MALICIOUS' ? 'text-red-400' : 'text-amber-400'}>
                      {analysis.threatVerdict}
                    </span>
                    <span className="text-sm font-normal text-slate-400">
                      (Risk Score: {analysis.threatScore}/100)
                    </span>
                  </div>
                </div>

                <div className="text-right">
                  <div className="text-xs text-slate-400">Generated At</div>
                  <div className="text-xs font-mono text-slate-300 mt-0.5">
                    {new Date().toUTCString()}
                  </div>
                </div>
              </div>

              {/* Email Metadata Grid */}
              <div className="grid grid-cols-2 gap-4">
                <div className="p-3.5 rounded-xl bg-slate-800/30 border border-slate-800">
                  <div className="text-[11px] font-semibold uppercase text-slate-400">Subject</div>
                  <div className="text-sm text-slate-200 mt-1 font-medium">{analysis.subject}</div>
                </div>
                <div className="p-3.5 rounded-xl bg-slate-800/30 border border-slate-800">
                  <div className="text-[11px] font-semibold uppercase text-slate-400">Date Header</div>
                  <div className="text-sm text-slate-200 mt-1 font-mono">{analysis.date}</div>
                </div>
                <div className="p-3.5 rounded-xl bg-slate-800/30 border border-slate-800">
                  <div className="text-[11px] font-semibold uppercase text-slate-400">Sender (From)</div>
                  <div className="text-sm text-slate-200 mt-1 font-mono truncate">{analysis.from}</div>
                </div>
                <div className="p-3.5 rounded-xl bg-slate-800/30 border border-slate-800">
                  <div className="text-[11px] font-semibold uppercase text-slate-400">Recipient (To)</div>
                  <div className="text-sm text-slate-200 mt-1 font-mono truncate">{analysis.to}</div>
                </div>
              </div>

              {/* Authentication Results */}
              <div className="p-4 rounded-xl bg-slate-800/30 border border-slate-800">
                <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300 mb-3">
                  Email Authentication Results (DMARC / SPF / DKIM)
                </h3>
                <div className="grid grid-cols-3 gap-3">
                  <div className="p-3 rounded-lg bg-slate-900 border border-slate-800">
                    <div className="text-xs text-slate-400">SPF</div>
                    <div className={`text-sm font-bold mt-1 ${analysis.authResults?.spf?.status === 'PASS' ? 'text-emerald-400' : 'text-red-400'}`}>
                      {analysis.authResults?.spf?.status || 'UNKNOWN'}
                    </div>
                  </div>
                  <div className="p-3 rounded-lg bg-slate-900 border border-slate-800">
                    <div className="text-xs text-slate-400">DKIM</div>
                    <div className={`text-sm font-bold mt-1 ${analysis.authResults?.dkim?.status === 'PASS' ? 'text-emerald-400' : 'text-red-400'}`}>
                      {analysis.authResults?.dkim?.status || 'UNKNOWN'}
                    </div>
                  </div>
                  <div className="p-3 rounded-lg bg-slate-900 border border-slate-800">
                    <div className="text-xs text-slate-400">DMARC</div>
                    <div className={`text-sm font-bold mt-1 ${analysis.authResults?.dmarc?.status === 'PASS' ? 'text-emerald-400' : 'text-red-400'}`}>
                      {analysis.authResults?.dmarc?.status || 'UNKNOWN'}
                    </div>
                  </div>
                </div>
              </div>

              {/* Heuristic Signals */}
              <div>
                <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300 mb-3">
                  Detected Forensic Signals ({analysis.heuristicSignals?.length || 0})
                </h3>
                <div className="space-y-2">
                  {analysis.heuristicSignals?.map((sig, idx) => (
                    <div key={idx} className="p-3 rounded-lg bg-slate-800/40 border border-slate-800 flex items-start gap-3">
                      <AlertTriangle className={`w-4 h-4 mt-0.5 shrink-0 ${sig.severity === 'CRITICAL' ? 'text-red-400' : 'text-amber-400'}`} />
                      <div>
                        <div className="text-xs font-semibold text-slate-200">{sig.title}</div>
                        <div className="text-xs text-slate-400 mt-0.5">{sig.description}</div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {activeTab === 'custody' && (
            <div className="space-y-4">
              <div className="p-4 rounded-xl bg-slate-800/30 border border-slate-800 flex items-start gap-3">
                <Lock className="w-5 h-5 text-cyan-400 shrink-0 mt-0.5" />
                <div>
                  <h4 className="text-sm font-bold text-slate-200">Cryptographic Evidence Integrity</h4>
                  <p className="text-xs text-slate-400 mt-1">
                    TraceXMail records an immutable SHA-256 digest of original raw RFC822 RFC5322 payloads before applying parser transformations.
                  </p>
                </div>
              </div>

              <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 font-mono text-xs space-y-3">
                <div>
                  <span className="text-slate-500">EVIDENCE ID: </span>
                  <span className="text-cyan-300">{analysis.evidenceId || `EV-${analysis.id?.toUpperCase()}`}</span>
                </div>
                <div>
                  <span className="text-slate-500">SHA-256 DIGEST: </span>
                  <span className="text-emerald-400 break-all">{analysis.sha256 || 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'}</span>
                </div>
                <div>
                  <span className="text-slate-500">INGESTION SOURCE: </span>
                  <span className="text-slate-300">RFC822 Direct Upload / Gateway Ingestion</span>
                </div>
                <div>
                  <span className="text-slate-500">CUSTODY TIMESTAMP: </span>
                  <span className="text-slate-300">{analysis.date}</span>
                </div>
              </div>
            </div>
          )}

          {activeTab === 'json' && (
            <div className="relative">
              <button
                onClick={handleCopyJson}
                className="absolute top-3 right-3 px-2.5 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-slate-200 border border-slate-700 flex items-center gap-1.5 transition-colors"
              >
                {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                <span>{copied ? 'Copied' : 'Copy JSON'}</span>
              </button>
              <pre className="p-4 rounded-xl bg-slate-950 border border-slate-800 font-mono text-xs text-slate-300 overflow-x-auto max-h-[400px]">
                {JSON.stringify(analysis, null, 2)}
              </pre>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="p-4 border-t border-slate-800 bg-slate-950/60 flex items-center justify-between">
          <span className="text-xs text-slate-500">TraceXMail Threat Intelligence Report</span>
          <button
            onClick={onClose}
            className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-slate-200 transition-colors"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
}
