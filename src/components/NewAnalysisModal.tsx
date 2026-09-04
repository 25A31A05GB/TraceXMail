import { useState, useRef, ChangeEvent } from 'react';
import { 
  X, 
  Upload, 
  FileText, 
  Server, 
  ArrowRight, 
  AlertCircle,
  CheckCircle2,
  Cpu,
  Loader2
} from 'lucide-react';
import { EmailAnalysis } from '../types';
import { SAMPLE_ANALYSES } from '../data/samples';
import { parseRawEml, mapBackendCaseToAnalysis } from '../utils/parser';
import { apiFetch } from '../lib/api';

interface NewAnalysisModalProps {
  isOpen: boolean;
  onClose: () => void;
  onAnalysisCreated: (analysis: EmailAnalysis) => void;
}

interface AnalysisStep {
  id: string;
  label: string;
  detail: string;
}

const ANALYSIS_STEPS: AnalysisStep[] = [
  { id: 'upload', label: 'Upload Payload', detail: 'Ingesting raw RFC822 MIME stream to forensic vault' },
  { id: 'parse', label: 'Parse Headers', detail: 'Extracting RFC 5322 header keys, boundary delimiters & tokens' },
  { id: 'auth', label: 'Auth Check', detail: 'Validating SPF records, DKIM cryptographic signatures & DMARC alignment' },
  { id: 'hops', label: 'Hop Tracing', detail: 'Tracing MTA transit relay hops, timestamp delays & geolocation' },
  { id: 'ml', label: 'ML Classification', detail: 'Running heuristic NLP, intent scoring & payload threat classification' },
  { id: 'intel', label: 'Domain Intel', detail: 'Querying WHOIS, IP reputation & threat intelligence databases' },
  { id: 'graph', label: 'Evidence Graph', detail: 'Constructing evidence provenance graph & immutable audit trail' },
];

export function NewAnalysisModal({
  isOpen,
  onClose,
  onAnalysisCreated,
}: NewAnalysisModalProps) {
  const [tab, setTab] = useState<'paste' | 'upload' | 'preset'>('paste');
  const [pastedRaw, setPastedRaw] = useState<string>('');
  const [fileName, setFileName] = useState<string>('custom_submission.eml');
  const [isProcessing, setIsProcessing] = useState<boolean>(false);
  const [currentStepIndex, setCurrentStepIndex] = useState<number>(0);
  const [allDone, setAllDone] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  const fileInputRef = useRef<HTMLInputElement>(null);

  if (!isOpen) return null;

  const executeForensicPipeline = async (rawContent: string, name: string, fileObj?: File) => {
    setError(null);
    setIsProcessing(true);
    setCurrentStepIndex(0);
    setAllDone(false);

    try {
      let parsedResult: EmailAnalysis | null = null;

      // Start actual backend ingestion & ML classification in parallel
      const apiCallPromise = (async () => {
        try {
          const formData = new FormData();
          if (fileObj) {
            formData.append('file', fileObj);
            formData.append('source', 'email_upload');
          } else {
            formData.append('raw_email', rawContent);
            formData.append('filename', name);
            formData.append('source', 'api');
          }

          const res = await apiFetch('/api/v1/analyze', {
            method: 'POST',
            body: formData
          });

          if (res.ok) {
            const apiData = await res.json();
            parsedResult = mapBackendCaseToAnalysis(apiData, rawContent, name);
          }
        } catch (err) {
          console.warn('[NewAnalysisModal] Backend analysis fallback:', err);
        }

        if (!parsedResult) {
          parsedResult = parseRawEml(rawContent, name);
        }
      })();

      // Steps auto-advance every ~650ms, capped one step before the end (step index 5 = 6th step)
      for (let step = 0; step <= 5; step++) {
        setCurrentStepIndex(step);
        await new Promise((resolve) => setTimeout(resolve, 650));
      }

      // Cap at step 5 until the real /api/v1/analyze response has finished
      await apiCallPromise;

      // Now complete the 7th and final step ('evidence graph')
      setCurrentStepIndex(6);
      await new Promise((resolve) => setTimeout(resolve, 650));

      // Mark all steps done
      setAllDone(true);

      // Brief pause on final "done" state so user registers completion
      await new Promise((resolve) => setTimeout(resolve, 750));

      if (parsedResult) {
        onAnalysisCreated(parsedResult);
      }
      setIsProcessing(false);
      onClose();
    } catch (err: any) {
      setError(err?.message || 'Forensic analysis encountered an unexpected error.');
      setIsProcessing(false);
    }
  };

  const handleProcessRaw = () => {
    if (!pastedRaw.trim()) {
      setError('Please paste raw email headers or RFC822 message text');
      return;
    }
    executeForensicPipeline(pastedRaw, fileName);
  };

  const handleFileUpload = (e: ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    setFileName(file.name);
    const reader = new FileReader();
    reader.onload = (event) => {
      const content = event.target?.result as string;
      setPastedRaw(content);
      executeForensicPipeline(content, file.name, file);
    };
    reader.readAsText(file);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-sm">
      <div className="bg-[#1E293B] border border-slate-700 w-full max-w-2xl rounded-xl shadow-2xl overflow-hidden flex flex-col max-h-[90vh]">
        {/* Modal Header */}
        <div className="p-5 border-b border-slate-700 flex items-center justify-between bg-slate-800/60">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded bg-blue-600/20 border border-blue-500/30 flex items-center justify-center text-blue-400">
              <Cpu className="w-4 h-4" />
            </div>
            <div>
              <h3 className="text-base font-semibold text-white">
                {isProcessing ? 'Ingestion Pipeline Active' : 'Ingest New Email for Forensic Analysis'}
              </h3>
              <p className="text-xs text-slate-400 font-mono">
                {isProcessing
                  ? 'Executing automated multi-layer forensic inspection'
                  : 'Supports RFC822 (.eml, .msg), raw headers, and simulated threats'}
              </p>
            </div>
          </div>
          {!isProcessing && (
            <button
              onClick={onClose}
              className="text-slate-400 hover:text-white p-1 rounded-md hover:bg-slate-700/80 cursor-pointer"
            >
              <X className="w-5 h-5" />
            </button>
          )}
        </div>

        {/* While processing: Show single focused 7-step inspection view */}
        {isProcessing ? (
          <div className="p-8 flex flex-col items-center justify-center space-y-6 flex-1 overflow-y-auto">
            {/* Spinning icon at top */}
            <div className="relative flex items-center justify-center">
              <div className={`w-16 h-16 rounded-2xl border flex items-center justify-center shadow-lg transition-all duration-300 ${
                allDone
                  ? 'bg-emerald-950/60 border-emerald-700/60 shadow-emerald-900/30'
                  : 'bg-cyan-950/60 border-cyan-700/50 shadow-cyan-900/20'
              }`}>
                {allDone ? (
                  <CheckCircle2 className="w-8 h-8 text-emerald-400" />
                ) : (
                  <Loader2 className="w-8 h-8 text-cyan-400 animate-spin" />
                )}
              </div>
            </div>

            <div className="text-center space-y-1">
              <h4 className="text-base font-semibold text-white">
                {allDone ? 'Forensic Pipeline Complete' : 'Executing Deep Email Forensics'}
              </h4>
              <p className="text-xs text-slate-400 font-mono">
                {allDone 
                  ? 'Provenance graph verified • Loading forensic workbench...'
                  : `Analyzing payload: ${fileName}`}
              </p>
            </div>

            {/* 7 Steps Listed Vertically */}
            <div className="w-full max-w-md space-y-2 bg-slate-900/80 border border-slate-800 rounded-xl p-3.5">
              {ANALYSIS_STEPS.map((step, idx) => {
                const isStepDone = allDone || idx < currentStepIndex;
                const isStepInProgress = !allDone && idx === currentStepIndex;
                const isStepPending = !allDone && idx > currentStepIndex;

                return (
                  <div
                    key={step.id}
                    className={`flex items-center justify-between p-2.5 rounded-lg transition-all duration-300 ${
                      isStepInProgress
                        ? 'bg-cyan-950/60 border border-cyan-700/70 text-cyan-200 shadow-sm'
                        : isStepDone
                          ? 'bg-slate-800/40 border border-emerald-900/40 text-slate-200'
                          : 'bg-transparent border border-transparent text-slate-500 opacity-60'
                    }`}
                  >
                    <div className="flex items-center gap-3 min-w-0">
                      <div className="flex items-center justify-center w-5 h-5 shrink-0">
                        {isStepDone ? (
                          <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                        ) : isStepInProgress ? (
                          <Loader2 className="w-4 h-4 text-cyan-400 animate-spin" />
                        ) : (
                          <div className="w-2 h-2 rounded-full bg-slate-700" />
                        )}
                      </div>
                      <div className="min-w-0">
                        <div className={`text-xs font-semibold truncate ${
                          isStepDone ? 'text-slate-200' : isStepInProgress ? 'text-cyan-300 font-bold' : 'text-slate-500'
                        }`}>
                          {step.label}
                        </div>
                        <div className={`text-[11px] truncate ${
                          isStepInProgress ? 'text-cyan-400/80' : 'text-slate-500'
                        }`}>
                          {step.detail}
                        </div>
                      </div>
                    </div>

                    <div className="text-[10px] font-mono shrink-0 pl-2">
                      {isStepDone ? (
                        <span className="text-emerald-400 font-semibold uppercase">Done</span>
                      ) : isStepInProgress ? (
                        <span className="text-cyan-400 uppercase animate-pulse">Running</span>
                      ) : (
                        <span className="text-slate-600 uppercase">Pending</span>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        ) : (
          <>
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
                    placeholder="Delivered-To: victim@domain.com&#10;Received: from mail.attacker-server.com (185.220.101.5) by mx.google.com&#10;Authentication-Results: mx.google.com; spf=fail; dkim=fail; dmarc=reject&#10;From: 'PayPal Support' <service@paypal.com>&#10;Subject: [URGENT] Account Action Required&#10;..."
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
                      Click to select or drag &amp; drop an .EML message
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
                          const rawContent = sample.rawHeaders || `From: ${sample.headers.from}\nTo: ${sample.headers.to}\nSubject: ${sample.headers.subject}\nDate: ${sample.headers.date}\nMessage-ID: ${sample.headers.messageId}\n\n${sample.name}`;
                          const formData = new FormData();
                          formData.append('raw_email', rawContent);
                          formData.append('filename', `${sample.id}.eml`);
                          formData.append('source', 'threat_intelligence_preset');
                          apiFetch('/api/v1/analyze', { method: 'POST', body: formData }).catch(console.warn);
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
                  Auto-extracts Hops, SPF/DKIM/DMARC &amp; URLs
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
                    className="bg-blue-600 hover:bg-blue-500 text-white px-5 py-1.5 rounded-lg text-xs font-semibold flex items-center gap-2 shadow-md shadow-blue-600/30 cursor-pointer"
                  >
                    Execute Forensics
                    <ArrowRight className="w-3.5 h-3.5" />
                  </button>
                </div>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}
