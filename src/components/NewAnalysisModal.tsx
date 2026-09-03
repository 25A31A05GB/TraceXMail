import { useState, useRef, ChangeEvent } from 'react';
import { 
  X, 
  Upload, 
  FileText, 
  Server, 
  ArrowRight, 
  AlertCircle,
  CheckCircle2,
  Cpu
} from 'lucide-react';
import { EmailAnalysis } from '../types';
import { SAMPLE_ANALYSES } from '../data/samples';
import { parseRawEml, parseRawEmlViaFastApi, mapBackendCaseToAnalysis } from '../utils/parser';

interface NewAnalysisModalProps {
  isOpen: boolean;
  onClose: () => void;
  onAnalysisCreated: (analysis: EmailAnalysis) => void;
}

export function NewAnalysisModal({
  isOpen,
  onClose,
  onAnalysisCreated,
}: NewAnalysisModalProps) {
  const [tab, setTab] = useState<'paste' | 'upload' | 'preset'>('paste');
  const [pastedRaw, setPastedRaw] = useState<string>('');
  const [fileName, setFileName] = useState<string>('custom_submission.eml');
  const [isProcessing, setIsProcessing] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  const fileInputRef = useRef<HTMLInputElement>(null);

  if (!isOpen) return null;

  const handleProcessRaw = async () => {
    if (!pastedRaw.trim()) {
      setError('Please paste raw email headers or RFC822 message text');
      return;
    }
    setError(null);
    setIsProcessing(true);

    try {
      // 1. Post to backend Evidence Vault & Ingestion endpoint
      const formData = new FormData();
      formData.append('raw_email', pastedRaw);
      formData.append('filename', fileName);
      formData.append('source', 'api');

      let apiResponse: any = null;
      try {
        const res = await fetch('/api/v1/analyze', {
          method: 'POST',
          body: formData
        });
        if (res.ok) {
          apiResponse = await res.json();
        }
      } catch (e) {
        console.warn('API Analyze fallback:', e);
      }

      const parsed = apiResponse
        ? mapBackendCaseToAnalysis(apiResponse, pastedRaw, fileName)
        : await parseRawEmlViaFastApi(pastedRaw, fileName);

      onAnalysisCreated(parsed);
      setIsProcessing(false);
      onClose();
    } catch (err: any) {
      setError(err?.message || 'Failed to parse raw RFC822 headers.');
      setIsProcessing(false);
    }
  };

  const handleFileUpload = (e: ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    setFileName(file.name);
    const reader = new FileReader();
    reader.onload = async (event) => {
      const content = event.target?.result as string;
      setPastedRaw(content);
      setIsProcessing(true);
      try {
        const formData = new FormData();
        formData.append('file', file);
        formData.append('source', 'email_upload');

        let apiResponse: any = null;
        try {
          const res = await fetch('/api/v1/analyze', {
            method: 'POST',
            body: formData
          });
          if (res.ok) {
            apiResponse = await res.json();
          }
        } catch (e) {
          console.warn('API Analyze upload fallback:', e);
        }

        const parsed = apiResponse
          ? mapBackendCaseToAnalysis(apiResponse, content, file.name)
          : await parseRawEmlViaFastApi(content, file.name);

        onAnalysisCreated(parsed);
        setIsProcessing(false);
        onClose();
      } catch (err: any) {
        setError('Failed to parse uploaded .eml file structure.');
        setIsProcessing(false);
      }
    };
    reader.readAsText(file);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm">
      <div className="bg-[#1E293B] border border-slate-700 w-full max-w-2xl rounded-xl shadow-2xl overflow-hidden flex flex-col max-h-[90vh]">
        {/* Modal Header */}
        <div className="p-5 border-b border-slate-700 flex items-center justify-between bg-slate-800/60">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded bg-blue-600/20 border border-blue-500/30 flex items-center justify-center text-blue-400">
              <Cpu className="w-4 h-4" />
            </div>
            <div>
              <h3 className="text-base font-semibold text-white">Ingest New Email for Forensic Analysis</h3>
              <p className="text-xs text-slate-400 font-mono">
                Supports RFC822 (.eml, .msg), raw headers, and simulated threats
              </p>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <div className="hidden sm:flex items-center gap-1.5 px-2 py-0.5 rounded bg-blue-950/80 border border-blue-600/40 text-blue-300 text-[10px] font-mono">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></span>
              <span>FastAPI Offload</span>
            </div>
            <button
              onClick={onClose}
              className="text-slate-400 hover:text-white p-1 rounded-md hover:bg-slate-700/80 cursor-pointer"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Modal Tab Switcher */}
        <div className="flex border-b border-slate-700 bg-slate-900/50 px-5 pt-3 gap-2">
          <button
            onClick={() => setTab('paste')}
            className={`pb-3 px-3 text-xs font-semibold border-b-2 transition-colors cursor-pointer flex items-center gap-1.5 ${
              tab === 'paste'
                ? 'border-blue-500 text-blue-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <FileText className="w-3.5 h-3.5" />
            <span>Paste Headers / Raw EML</span>
          </button>
          <button
            onClick={() => setTab('upload')}
            className={`pb-3 px-3 text-xs font-semibold border-b-2 transition-colors cursor-pointer flex items-center gap-1.5 ${
              tab === 'upload'
                ? 'border-blue-500 text-blue-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Upload className="w-3.5 h-3.5" />
            <span>Upload .EML File</span>
          </button>
          <button
            onClick={() => setTab('preset')}
            className={`pb-3 px-3 text-xs font-semibold border-b-2 transition-colors cursor-pointer flex items-center gap-1.5 ${
              tab === 'preset'
                ? 'border-blue-500 text-blue-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Server className="w-3.5 h-3.5" />
            <span>Threat Presets</span>
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-6 overflow-y-auto space-y-4 flex-1">
          {error && (
            <div className="p-3 bg-rose-950/40 border border-rose-500/50 rounded-lg text-rose-300 text-xs flex items-center gap-2">
              <AlertCircle className="w-4 h-4 shrink-0" />
              <span>{error}</span>
            </div>
          )}

          {tab === 'paste' && (
            <div className="space-y-3">
              <label className="text-xs text-slate-300 font-semibold block">
                Paste RFC822 Raw Headers or Full MIME stream:
              </label>
              <textarea
                value={pastedRaw}
                onChange={(e) => setPastedRaw(e.target.value)}
                placeholder="Delivered-To: victim@domain.com
Received: from mail.attacker-server.com (185.220.101.5) by mx.google.com
Authentication-Results: mx.google.com; spf=fail; dkim=fail; dmarc=reject
From: 'PayPal Support' <service@paypal.com>
Subject: [URGENT] Account Action Required
..."
                rows={10}
                className="w-full bg-[#0F172A] border border-slate-700 rounded-lg p-3 text-xs font-mono text-slate-200 focus:outline-none focus:border-blue-500 placeholder:text-slate-600 resize-none"
              ></textarea>
            </div>
          )}

          {tab === 'upload' && (
            <div className="border-2 border-dashed border-slate-700 hover:border-blue-500/70 bg-[#0F172A]/60 rounded-xl p-8 text-center flex flex-col items-center justify-center gap-3 transition-colors">
              <input
                ref={fileInputRef}
                type="file"
                accept=".eml,.txt,.msg"
                onChange={handleFileUpload}
                className="hidden"
              />
              <div className="w-12 h-12 rounded-full bg-blue-600/20 border border-blue-500/30 flex items-center justify-center text-blue-400">
                <Upload className="w-6 h-6" />
              </div>
              <div>
                <p className="text-sm font-semibold text-slate-200">
                  Click to select or drag & drop an .EML message
                </p>
                <p className="text-xs text-slate-400 font-mono mt-1">
                  Supports standard RFC822 format exported from Outlook, Gmail, Thunderbird, Apple Mail
                </p>
              </div>
              <button
                onClick={() => fileInputRef.current?.click()}
                className="mt-2 bg-blue-600 hover:bg-blue-500 text-white px-4 py-2 rounded-lg text-xs font-semibold cursor-pointer transition-colors shadow-md shadow-blue-600/20"
              >
                Choose File from Computer
              </button>
            </div>
          )}

          {tab === 'preset' && (
            <div className="space-y-2.5">
              <div className="text-xs text-slate-400 uppercase font-semibold">
                Select from Analyzed Threat Intelligence Corpora:
              </div>
              {SAMPLE_ANALYSES.map((sample) => (
                <div
                  key={sample.id}
                  onClick={async () => {
                    try {
                      // Trigger backend ingestion so cases, SIEM alerts, and Slack dispatch occur
                      const rawContent = sample.rawHeaders || `From: ${sample.headers.from}\nTo: ${sample.headers.to}\nSubject: ${sample.headers.subject}\nDate: ${sample.headers.date}\nMessage-ID: ${sample.headers.messageId}\n\n${sample.name}`;
                      const formData = new FormData();
                      formData.append('raw_email', rawContent);
                      formData.append('filename', `${sample.id}.eml`);
                      formData.append('source', 'threat_intelligence_preset');
                      fetch('/api/v1/analyze', { method: 'POST', body: formData }).catch(console.warn);
                    } catch (e) {
                      console.warn('Preset ingestion error:', e);
                    }
                    onAnalysisCreated(sample);
                    onClose();
                  }}
                  className="p-3.5 bg-slate-900/70 hover:bg-slate-800 border border-slate-700/80 rounded-lg cursor-pointer transition-all flex items-center justify-between gap-3"
                >
                  <div className="space-y-0.5">
                    <div className="text-xs font-semibold text-slate-200">{sample.name}</div>
                    <div className="text-[11px] text-slate-400 font-mono truncate max-w-md">
                      {sample.headers.subject}
                    </div>
                  </div>
                  <span
                    className={`text-[9px] font-bold px-2 py-0.5 rounded font-mono ${
                      sample.verdict === 'MALICIOUS PHISH'
                        ? 'bg-rose-600 text-white'
                        : 'bg-emerald-600 text-white'
                    }`}
                  >
                    {sample.verdict}
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Modal Footer */}
        {tab === 'paste' && (
          <div className="p-4 border-t border-slate-700 bg-slate-900/60 flex items-center justify-between">
            <span className="text-[11px] text-slate-400 font-mono">
              Auto-extracts Hops, SPF/DKIM/DMARC & URLs
            </span>
            <div className="flex items-center gap-3">
              <button
                onClick={onClose}
                className="px-4 py-1.5 rounded text-xs font-medium text-slate-300 hover:text-white cursor-pointer"
              >
                Cancel
              </button>
              <button
                onClick={handleProcessRaw}
                disabled={isProcessing}
                className="bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white px-5 py-1.5 rounded-lg text-xs font-semibold flex items-center gap-2 shadow-md shadow-blue-600/30 cursor-pointer"
              >
                {isProcessing ? 'Analyzing Stream...' : 'Execute Forensics'}
                <ArrowRight className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
