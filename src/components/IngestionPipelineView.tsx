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
  const [currentStep, setCurrentStep] = useState<number>(0);
  const [isDragging, setIsDragging] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const fileInputRef = useRef<HTMLInputElement>(null);

  const steps = [
    { label: 'Evidence Vault Custody (SHA-256 Digest)', icon: Lock },
    { label: 'RFC822 MIME & Header Parsing', icon: FileText },
    { label: 'MaxMind GeoIP & ASN Hop Traceroute', icon: Activity },
    { label: 'Authentication & Threat Intelligence (VT / Groq)', icon: Cpu },
  ];

  const handleProcessEmail = async (content: string, name: string) => {
    if (!content.trim()) {
      setError('Please provide valid raw RFC822 email content or headers.');
      return;
    }
    setError(null);
    setIsProcessing(true);
    setCurrentStep(1);

    try {
      // Step 1: Simulated Pipeline progression
      await new Promise(r => setTimeout(r, 200));
      setCurrentStep(2);

      // Attempt FastAPI backend call
      let backendResult: any = null;
      try {
        const formData = new FormData();
        formData.append('raw_email', content);
        formData.append('filename', name);
        formData.append('source', 'email_upload');

        const res = await fetch('/api/v1/analyze', {
          method: 'POST',
          body: formData
        });
        if (res.ok) {
          backendResult = await res.json();
        }
      } catch (err) {
        console.warn('[IngestionPipeline] Backend direct call failed, using client-side engine:', err);
      }

      setCurrentStep(3);
      await new Promise(r => setTimeout(r, 200));
      setCurrentStep(4);

      let finalAnalysis: EmailAnalysis;
      if (backendResult?.case) {
        finalAnalysis = mapBackendCaseToAnalysis(backendResult.case);
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
      </div>

      {/* Processing Stepper (Visible during active ingestion) */}
      {isProcessing && (
        <div className="p-6 rounded-2xl bg-cyan-950/20 border border-cyan-800/60 shadow-xl space-y-4 animate-in fade-in duration-200">
          <h3 className="text-xs font-bold uppercase tracking-wider text-cyan-400">
            Pipeline Execution in Progress
          </h3>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
            {steps.map((step, idx) => {
              const StepIcon = step.icon;
              const isDone = currentStep > idx;
              const isCurrent = currentStep === idx + 1;
              return (
                <div
                  key={idx}
                  className={`p-3.5 rounded-xl border flex items-center gap-3 transition-all ${
                    isDone
                      ? 'bg-emerald-950/40 border-emerald-800 text-emerald-300'
                      : isCurrent
                      ? 'bg-cyan-950/60 border-cyan-600 text-cyan-300 animate-pulse'
                      : 'bg-slate-900/60 border-slate-800 text-slate-500'
                  }`}
                >
                  <StepIcon className="w-4 h-4 shrink-0" />
                  <span className="text-xs font-medium">{step.label}</span>
                </div>
              );
            })}
          </div>
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
