import { useState, useRef, ChangeEvent, DragEvent } from 'react';
import { 
  X, 
  Upload, 
  FileText, 
  Server, 
  ArrowRight, 
  AlertCircle,
  Cpu
} from 'lucide-react';
import { EmailAnalysis } from '../types';
import { SAMPLE_ANALYSES } from '../data/samples';
import { parseRawEml, mapBackendCaseToAnalysis } from '../utils/parser';
import { apiFetch } from '../lib/api';
import { AnalysisProgressPanel, useAnalysisProgress } from './AnalysisProgressPanel';

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
  const [isDragging, setIsDragging] = useState<boolean>(false);
  const [batchStatus, setBatchStatus] = useState<{
    total: number;
    current: number;
    currentFilename: string;
    results: EmailAnalysis[];
  } | null>(null);

  const progress = useAnalysisProgress();
  const fileInputRef = useRef<HTMLInputElement>(null);

  if (!isOpen) return null;

  const executeBatchPipeline = async (files: File[]) => {
    if (files.length === 0) return;
    setError(null);
    setIsProcessing(true);
    setBatchStatus({
      total: files.length,
      current: 1,
      currentFilename: files[0].name,
      results: []
    });

    const results: EmailAnalysis[] = [];

    for (let i = 0; i < files.length; i++) {
      const file = files[i];
      setBatchStatus({
        total: files.length,
        current: i + 1,
        currentFilename: file.name,
        results: [...results]
      });

      try {
        const rawContent = await new Promise<string>((resolve, reject) => {
          const reader = new FileReader();
          reader.onload = (e) => resolve((e.target?.result as string) || '');
          reader.onerror = () => reject(new Error(`Failed to read file ${file.name}`));
          reader.readAsText(file);
        });

        let parsedResult: EmailAnalysis | null = null;
        try {
          const formData = new FormData();
          formData.append('file', file);
          formData.append('source', 'batch_email_upload');
          formData.append('filename', file.name);

          const res = await apiFetch('/api/v1/analyze', {
            method: 'POST',
            body: formData
          });

          if (res.ok) {
            const apiData = await res.json();
            parsedResult = mapBackendCaseToAnalysis(apiData, rawContent, file.name);
          }
        } catch (err) {
          console.warn(`[BatchIngest] Backend API fallback for ${file.name}:`, err);
        }

        if (!parsedResult) {
          parsedResult = parseRawEml(rawContent, file.name);
        }

        results.push(parsedResult);
      } catch (err) {
        console.error(`Error processing batch file ${file.name}:`, err);
      }
    }

    setBatchStatus({
      total: files.length,
      current: files.length,
      currentFilename: 'Completed',
      results
    });

    await new Promise((r) => setTimeout(r, 500));

    if (results.length > 0) {
      const sortedByThreat = [...results].sort((a, b) => (b.threatScore || 0) - (a.threatScore || 0));
      onAnalysisCreated(sortedByThreat[0]);
    }

    setIsProcessing(false);
    setBatchStatus(null);
    onClose();
  };

  const executeForensicPipeline = async (rawContent: string, name: string, fileObj?: File) => {
    if (fileObj) {
      await executeBatchPipeline([fileObj]);
      return;
    }

    setError(null);
    setIsProcessing(true);
    const requestId = progress.start();

    try {
      let parsedResult: EmailAnalysis | null = null;

      try {
        const formData = new FormData();
        formData.append('raw_email', rawContent);
        formData.append('filename', name);
        formData.append('source', 'api');
        formData.append('requestId', requestId);

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

      // Mark pipeline complete
      progress.finish();
      await new Promise((resolve) => setTimeout(resolve, 400));

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
    const files = Array.from(e.target.files || []) as File[];
    if (files.length === 0) return;
    executeBatchPipeline(files);
  };

  const handleDropFiles = (e: DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    setIsDragging(false);
    const files = Array.from(e.dataTransfer.files || []) as File[];
    if (files.length === 0) return;
    executeBatchPipeline(files);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-sm">
      <div className="bg-[#1a1712] border border-[#3a352c] w-full max-w-2xl rounded-xl shadow-2xl overflow-hidden flex flex-col max-h-[90vh]">
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

        {/* While processing: Show real-time WebSocket analysis progress panel or batch progress */}
        {isProcessing ? (
          <div className="p-6 flex flex-col flex-1 overflow-y-auto space-y-4">
            {batchStatus ? (
              <div className="space-y-4 bg-slate-900 border border-slate-700/80 rounded-xl p-5 shadow-lg">
                <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                  <div className="flex items-center gap-2.5">
                    <div className="w-8 h-8 rounded-lg bg-blue-600/20 border border-blue-500/30 flex items-center justify-center text-blue-400">
                      <Upload className="w-4 h-4 animate-bounce" />
                    </div>
                    <div>
                      <h4 className="text-sm font-bold text-white uppercase tracking-tight">
                        Batch Email Ingestion Engine
                      </h4>
                      <p className="text-xs text-slate-400 font-mono">
                        Processing {batchStatus.current} of {batchStatus.total} email files
                      </p>
                    </div>
                  </div>
                  <span className="text-xs font-mono font-bold px-2.5 py-1 rounded bg-blue-950 border border-blue-600/60 text-blue-300">
                    {Math.round((batchStatus.current / batchStatus.total) * 100)}%
                  </span>
                </div>

                {/* Progress bar */}
                <div className="w-full bg-slate-950 rounded-full h-2.5 overflow-hidden border border-slate-800">
                  <div
                    className="bg-gradient-to-r from-blue-500 to-cyan-400 h-full transition-all duration-300"
                    style={{ width: `${(batchStatus.current / batchStatus.total) * 100}%` }}
                  />
                </div>

                <div className="text-xs text-slate-300 font-mono truncate">
                  <span className="text-slate-500">Active File:</span> {batchStatus.currentFilename}
                </div>

                {/* Results list */}
                {batchStatus.results.length > 0 && (
                  <div className="space-y-2 pt-2 border-t border-slate-800">
                    <div className="text-[11px] font-bold text-slate-400 uppercase">
                      Analyzed Ingestion Batch ({batchStatus.results.length} ready):
                    </div>
                    <div className="max-h-40 overflow-y-auto space-y-1.5 pr-1">
                      {batchStatus.results.map((res, idx) => (
                        <div
                          key={res.id || idx}
                          className="p-2 rounded bg-slate-950 border border-slate-800 text-xs flex items-center justify-between gap-2"
                        >
                          <div className="min-w-0 flex-1">
                            <div className="font-semibold text-slate-200 truncate">{res.subject || res.name}</div>
                            <div className="text-[10px] text-slate-500 font-mono truncate">{res.id} • {res.from}</div>
                          </div>
                          <span className={`text-[10px] font-mono font-bold px-1.5 py-0.5 rounded border ${
                            (res.threatScore || 0) >= 80
                              ? 'bg-rose-950 text-rose-300 border-rose-700'
                              : (res.threatScore || 0) >= 50
                              ? 'bg-amber-950 text-amber-300 border-amber-700'
                              : 'bg-emerald-950 text-emerald-300 border-emerald-700'
                          }`}>
                            Score: {res.threatScore || 0}/100
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            ) : (
              <AnalysisProgressPanel
                stageStatus={progress.stageStatus}
                stageDetail={progress.stageDetail}
                startedAt={progress.startedAt}
              />
            )}
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
                <span>Upload .EML Files (Batch)</span>
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
                    className="w-full bg-[#14120f] border border-[#3a352c] rounded-lg p-3 text-xs font-mono text-slate-200 focus:outline-none focus:border-[#b23a2e] placeholder:text-slate-600 resize-none"
                  ></textarea>
                </div>
              )}

              {tab === 'upload' && (
                <div
                  onDragOver={(e) => { e.preventDefault(); setIsDragging(true); }}
                  onDragLeave={() => setIsDragging(false)}
                  onDrop={handleDropFiles}
                  className={`border-2 border-dashed rounded-xl p-8 text-center flex flex-col items-center justify-center gap-3 transition-colors ${
                    isDragging
                      ? 'border-blue-400 bg-blue-950/30'
                      : 'border-[#3a352c] hover:border-[#b23a2e]/70 bg-[#14120f]'
                  }`}
                >
                  <input
                    ref={fileInputRef}
                    type="file"
                    multiple
                    accept=".eml,.txt,.msg"
                    onChange={handleFileUpload}
                    className="hidden"
                  />
                  <div className="w-12 h-12 rounded-full bg-blue-600/20 border border-blue-500/30 flex items-center justify-center text-blue-400">
                    <Upload className="w-6 h-6" />
                  </div>
                  <div>
                    <p className="text-sm font-semibold text-slate-200">
                      Click to select or drag &amp; drop single or multiple .EML files
                    </p>
                    <p className="text-xs text-slate-400 font-mono mt-1">
                      Batch ingestion mode supported — select multiple files to analyze simultaneously
                    </p>
                  </div>
                  <button
                    onClick={() => fileInputRef.current?.click()}
                    className="mt-2 bg-blue-600 hover:bg-blue-500 text-white px-4 py-2 rounded-lg text-xs font-semibold cursor-pointer transition-colors shadow-md shadow-blue-600/20"
                  >
                    Select Email Files (Batch Upload)
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
