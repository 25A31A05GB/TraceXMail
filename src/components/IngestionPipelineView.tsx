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

  const progress = useAnalysisProgress();
  const fileInputRef = useRef<HTMLInputElement>(null);

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
      await new Promise(r => setTimeout(r, 400));

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
    const file = e.target.files?.[0];
    if (!file) return;
    setFileName(file.name);
    const reader = new FileReader();
    reader.onload = (event) => {
      const content = event.target?.result as string;
      setRawText(content);
      handleProcessEmail(content, file.name);
    };
    reader.readAsText(file);
  };

  const handleDrop = (e: DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    setIsDragging(false);
    const file = e.dataTransfer.files?.[0];
    if (file) {
      setFileName(file.name);
      const reader = new FileReader();
      reader.onload = (event) => {
        const content = event.target?.result as string;
        setRawText(content);
        handleProcessEmail(content, file.name);
      };
      reader.readAsText(file);
    }
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
          <AnalysisProgressPanel
            stageStatus={progress.stageStatus}
            stageDetail={progress.stageDetail}
            startedAt={progress.startedAt}
          />
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
            Upload File (.eml / .msg)
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
                className="flex items-center gap-2 px-5 py-2.5 rounded-xl bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white text-xs font-semibold shadow-lg shadow-cyan-950/40 disabled:opacity-50 transition-all"
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
                Click to browse or drag &amp; drop an email file here
              </p>
              <p className="text-xs text-slate-500 mt-1">
                Supports .eml, .msg, .txt RFC822 files up to 25MB
              </p>
              <input
                type="file"
                ref={fileInputRef}
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
