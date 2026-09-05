import React, { useState, useRef, ChangeEvent, DragEvent } from 'react';
import { 
  Database, 
  Upload, 
  FileText, 
  CheckCircle2, 
  AlertCircle, 
  ArrowRight, 
  Layers, 
  ShieldCheck, 
  Cpu, 
  Lock, 
  Activity,
  Sparkles
} from 'lucide-react';
import { EmailAnalysis } from '../types';
import { SAMPLE_ANALYSES } from '../data/samples';
import { parseRawEml, mapBackendCaseToAnalysis } from '../utils/parser';
import { apiFetch } from '../lib/api';
import { AnalysisProgressPanel, useAnalysisProgress } from './AnalysisProgressPanel';

interface IngestionPipelineViewProps {
  onSelectAnalysis: (analysis: EmailAnalysis) => void;
  onNavigateToOverview: () => void;
}

export function IngestionPipelineView({
  onSelectAnalysis,
  onNavigateToOverview
}: IngestionPipelineViewProps) {
  const [activeTab, setActiveTab] = useState<'paste' | 'upload' | 'batch'>('paste');
  const [rawText, setRawText] = useState('');
  const [fileName, setFileName] = useState('raw_email.eml');
  const [isProcessing, setIsProcessing] = useState(false);
  const [isDragging, setIsDragging] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [batchStatus, setBatchStatus] = useState<{
    total: number;
    current: number;
    currentFilename: string;
    results: EmailAnalysis[];
  } | null>(null);

  const progress = useAnalysisProgress();
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleProcessBatch = async (files: File[]) => {
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
        const content = await new Promise<string>((resolve, reject) => {
          const reader = new FileReader();
          reader.onload = (e) => resolve((e.target?.result as string) || '');
          reader.onerror = () => reject(new Error(`Failed to read ${file.name}`));
          reader.readAsText(file);
        });

        let backendResult: any = null;
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
            backendResult = await res.json();
          }
        } catch (err) {
          console.warn(`[IngestionPipeline] Backend direct call failed for ${file.name}:`, err);
        }

        let finalAnalysis: EmailAnalysis;
        if (backendResult?.analysis || backendResult?.case) {
          finalAnalysis = mapBackendCaseToAnalysis(backendResult.analysis || backendResult, content, file.name);
        } else {
          finalAnalysis = parseRawEml(content, file.name);
        }

        results.push(finalAnalysis);
      } catch (err: any) {
        console.error(`Error processing ${file.name}:`, err);
      }
    }

    setBatchStatus({
      total: files.length,
      current: files.length,
      currentFilename: 'Completed Batch Analysis',
      results
    });

    await new Promise((r) => setTimeout(r, 600));

    if (results.length > 0) {
      const sortedByThreat = [...results].sort((a, b) => (b.threatScore || 0) - (a.threatScore || 0));
      onSelectAnalysis(sortedByThreat[0]);
      onNavigateToOverview();
    }

    setIsProcessing(false);
    setBatchStatus(null);
  };

  const handleProcessEmail = async (content: string, name: string) => {
    if (!content.trim()) {
      setError('Please provide valid raw RFC822 email content or headers.');
      return;
    }
    setError(null);
    setIsProcessing(true);
    const requestId = progress.start();

    try {
      let backendResult: any = null;
      try {
        const formData = new FormData();
        formData.append('raw_email', content);
        formData.append('filename', name);
        formData.append('source', 'email_upload');
        formData.append('requestId', requestId);

        const res = await apiFetch('/api/v1/analyze', {
          method: 'POST',
          body: formData
        });
        if (res.ok) {
          backendResult = await res.json();
        }
      } catch (err) {
        console.warn('[IngestionPipeline] Backend direct call failed, using client-side engine:', err);
      }

      progress.finish();
      await new Promise((r) => setTimeout(r, 400));

      let finalAnalysis: EmailAnalysis;
      if (backendResult?.analysis || backendResult?.case) {
        finalAnalysis = mapBackendCaseToAnalysis(backendResult.analysis || backendResult, content, name);
      } else {
        finalAnalysis = parseRawEml(content, name);
      }

      setIsProcessing(false);
      onSelectAnalysis(finalAnalysis);
      onNavigateToOverview();
    } catch (err: any) {
      setIsProcessing(false);
      setError(err.message || 'Error processing email file');
    }
  };

  const handleFileUpload = (e: ChangeEvent<HTMLInputElement>) => {
    const files = Array.from(e.target.files || []) as File[];
    if (files.length === 0) return;
    handleProcessBatch(files);
  };

  const handleDrop = (e: DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    setIsDragging(false);
    const files = Array.from(e.dataTransfer.files || []) as File[];
    if (files.length === 0) return;
    handleProcessBatch(files);
  };

  return (
    <div className="flex-1 flex flex-col h-full bg-[#0F172A] overflow-y-auto p-6 space-y-6">
      {/* Top Banner */}
      <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 shadow-xl flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div className="flex items-center gap-4">
          <div className="w-12 h-12 rounded-2xl bg-cyan-950/80 border border-cyan-800/80 flex items-center justify-center">
            <Database className="w-6 h-6 text-cyan-400" />
          </div>
          <div>
            <h2 className="text-lg font-bold text-slate-100 flex items-center gap-2">
              <span>Email Ingestion &amp; Evidence Pipeline</span>
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Ingest raw RFC822 (.eml, .msg, .txt) email files through the multi-stage forensic analysis engine.
            </p>
          </div>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={onNavigateToOverview}
            className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 hover:text-white text-xs font-semibold rounded-xl border border-slate-700 flex items-center gap-2 transition-all cursor-pointer shadow-sm"
          >
            <span>View Message Overview</span>
            <ArrowRight className="w-3.5 h-3.5 text-cyan-400" />
          </button>
        </div>
      </div>

      {/* Real-Time Forensic Pipeline Telemetry (Visible during active ingestion) */}
      {isProcessing && (
        <div className="animate-in fade-in duration-200">
          {batchStatus ? (
            <div className="space-y-4 bg-slate-900 border border-slate-800 rounded-2xl p-6 shadow-xl">
              <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                <div className="flex items-center gap-3">
                  <div className="w-10 h-10 rounded-xl bg-cyan-950/80 border border-cyan-800 flex items-center justify-center text-cyan-400">
                    <Database className="w-5 h-5 animate-pulse" />
                  </div>
                  <div>
                    <h3 className="text-sm font-bold text-slate-100 uppercase tracking-wide">
                      Multi-File Ingestion Pipeline
                    </h3>
                    <p className="text-xs text-slate-400 font-mono">
                      Ingesting &amp; Analyzing File {batchStatus.current} of {batchStatus.total}
                    </p>
                  </div>
                </div>
                <span className="text-xs font-mono font-bold px-3 py-1 rounded-full bg-cyan-950 border border-cyan-700/80 text-cyan-300">
                  {Math.round((batchStatus.current / batchStatus.total) * 100)}% Complete
                </span>
              </div>

              {/* Progress bar */}
              <div className="w-full bg-slate-950 rounded-full h-3 overflow-hidden border border-slate-800">
                <div
                  className="bg-gradient-to-r from-cyan-500 via-blue-500 to-indigo-500 h-full transition-all duration-300"
                  style={{ width: `${(batchStatus.current / batchStatus.total) * 100}%` }}
                />
              </div>

              <div className="text-xs text-slate-300 font-mono truncate">
                <span className="text-slate-500">Current EML Stream:</span> {batchStatus.currentFilename}
              </div>

              {batchStatus.results.length > 0 && (
                <div className="space-y-2 pt-3 border-t border-slate-800/80">
                  <div className="text-xs font-bold text-slate-400 uppercase tracking-wider">
                    Batch Ingestion Queue ({batchStatus.results.length} processed):
                  </div>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-2 max-h-48 overflow-y-auto pr-1">
                    {batchStatus.results.map((res, idx) => (
                      <div
                        key={res.id || idx}
                        className="p-3 rounded-xl bg-slate-950 border border-slate-800 text-xs flex items-center justify-between gap-2"
                      >
                        <div className="min-w-0 flex-1">
                          <div className="font-semibold text-slate-200 truncate">{res.subject || res.name}</div>
                          <div className="text-[10px] text-slate-500 font-mono truncate">{res.id} • {res.from}</div>
                        </div>
                        <span className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded border shrink-0 ${
                          (res.threatScore || 0) >= 80
                            ? 'bg-rose-950 text-rose-300 border-rose-800'
                            : (res.threatScore || 0) >= 50
                            ? 'bg-amber-950 text-amber-300 border-amber-800'
                            : 'bg-emerald-950 text-emerald-300 border-emerald-800'
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
      )}

      {error && (
        <div className="p-4 rounded-xl bg-red-950/40 border border-red-800 text-red-300 text-xs flex items-center gap-2">
          <AlertCircle className="w-4 h-4 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Main Ingestion Box */}
      <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 shadow-xl space-y-4">
        <div className="flex border-b border-slate-800 gap-4">
          <button
            onClick={() => setActiveTab('paste')}
            className={`pb-3 text-xs font-bold border-b-2 transition-colors ${
              activeTab === 'paste'
                ? 'border-cyan-400 text-cyan-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            Paste Raw RFC822 / Headers
          </button>
          <button
            onClick={() => setActiveTab('upload')}
            className={`pb-3 text-xs font-bold border-b-2 transition-colors ${
              activeTab === 'upload'
                ? 'border-cyan-400 text-cyan-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            Upload Files (.eml / .msg / Batch)
          </button>
          <button
            onClick={() => setActiveTab('batch')}
            className={`pb-3 text-xs font-bold border-b-2 transition-colors ${
              activeTab === 'batch'
                ? 'border-cyan-400 text-cyan-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            Quick Forensic Samples
          </button>
        </div>

        {activeTab === 'paste' && (
          <div className="space-y-4">
            <textarea
              value={rawText}
              onChange={(e) => setRawText(e.target.value)}
              placeholder="Paste raw email headers (Received, From, To, Subject, Authentication-Results, etc.)..."
              rows={12}
              className="w-full p-4 rounded-xl bg-slate-950 border border-slate-800 font-mono text-xs text-slate-200 placeholder-slate-600 focus:outline-none focus:border-cyan-500 transition-colors"
            />
            <div className="flex justify-end">
              <button
                disabled={isProcessing || !rawText.trim()}
                onClick={() => handleProcessEmail(rawText, 'pasted_message.eml')}
                className="flex items-center gap-2 px-5 py-2.5 rounded-xl bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white text-xs font-semibold shadow-lg shadow-cyan-950/40 disabled:opacity-50 transition-all cursor-pointer"
              >
                <span>Execute Forensic Pipeline</span>
                <ArrowRight className="w-4 h-4" />
              </button>
            </div>
          </div>
        )}

        {activeTab === 'upload' && (
          <div className="space-y-4">
            <div
              onDragOver={(e) => { e.preventDefault(); setIsDragging(true); }}
              onDragLeave={() => setIsDragging(false)}
              onDrop={handleDrop}
              onClick={() => fileInputRef.current?.click()}
              className={`p-12 border-2 border-dashed rounded-2xl text-center cursor-pointer transition-all ${
                isDragging
                  ? 'border-cyan-500 bg-cyan-950/20'
                  : 'border-slate-800 hover:border-slate-700 bg-slate-950/60'
              }`}
            >
              <Upload className="w-10 h-10 mx-auto text-cyan-400 mb-3 opacity-80" />
              <p className="text-sm font-semibold text-slate-200">
                Click to browse or drag &amp; drop single or multiple email files here
              </p>
              <p className="text-xs text-slate-400 font-mono mt-1">
                Multi-file batch ingestion enabled — select multiple .eml, .msg, or .txt files
              </p>
              <input
                type="file"
                ref={fileInputRef}
                multiple
                onChange={handleFileUpload}
                accept=".eml,.msg,.txt"
                className="hidden"
              />
            </div>
          </div>
        )}

        {activeTab === 'batch' && (
          <div className="space-y-3">
            <p className="text-xs text-slate-400">
              Select one of the pre-loaded forensic threat campaign samples to run through the pipeline:
            </p>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {SAMPLE_ANALYSES.map((sample) => (
                <div
                  key={sample.id}
                  onClick={() => {
                    onSelectAnalysis(sample);
                    onNavigateToOverview();
                  }}
                  className="p-4 rounded-xl bg-slate-950 border border-slate-800 hover:border-cyan-500/50 cursor-pointer transition-colors space-y-1.5"
                >
                  <div className="flex items-center justify-between">
                    <span className="text-[11px] font-bold uppercase text-red-400 bg-red-950/60 border border-red-800/80 px-2 py-0.5 rounded">
                      {sample.threatVerdict}
                    </span>
                    <span className="text-xs font-mono text-slate-500">{sample.id}</span>
                  </div>
                  <div className="text-xs font-semibold text-slate-200 truncate">{sample.subject}</div>
                  <div className="text-[11px] text-slate-400 font-mono truncate">{sample.from}</div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
