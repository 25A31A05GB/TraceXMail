import React, { useState, useEffect } from 'react';
import { 
  ShieldAlert, 
  ShieldCheck, 
  AlertTriangle, 
  Plus, 
  FileDown, 
  ChevronDown, 
  Activity, 
  Search,
  ExternalLink,
  Shield,
  Scale,
  EyeOff,
  FlaskConical,
  UserCheck
} from 'lucide-react';
import { EmailAnalysis } from '../types';
import { SAMPLE_ANALYSES } from '../data/samples';
import { PrivacyConfig } from '../utils/privacyCompliance';
import { subscribeSession, SessionUser } from '../lib/api';

interface HeaderProps {
  currentAnalysis: EmailAnalysis;
  onSelectAnalysis: (analysis: EmailAnalysis) => void;
  onOpenNewModal: () => void;
  onOpenReportModal: () => void;
  onOpenPrivacyModal?: () => void;
  privacyConfig?: PrivacyConfig;
  showDemoCases?: boolean;
  onToggleDemoCases?: () => void;
}

export function Header({
  currentAnalysis,
  onSelectAnalysis,
  onOpenNewModal,
  onOpenReportModal,
  onOpenPrivacyModal,
  privacyConfig,
  showDemoCases = false,
  onToggleDemoCases
}: HeaderProps) {
  const [dropdownOpen, setDropdownOpen] = useState(false);
  const [sessionUser, setSessionUser] = useState<SessionUser | null>(null);

  useEffect(() => {
    return subscribeSession((sess) => {
      setSessionUser(sess.user);
    });
  }, []);

  const getVerdictBadge = (verdict: string) => {
    switch (verdict?.toUpperCase()) {
      case 'MALICIOUS':
      case 'PHISHING':
        return {
          bg: 'bg-red-950/60 border-red-800/80 text-red-400',
          icon: ShieldAlert,
          label: 'MALICIOUS / PHISHING'
        };
      case 'SUSPICIOUS':
        return {
          bg: 'bg-amber-950/60 border-amber-800/80 text-amber-400',
          icon: AlertTriangle,
          label: 'SUSPICIOUS'
        };
      default:
        return {
          bg: 'bg-emerald-950/60 border-emerald-800/80 text-emerald-400',
          icon: ShieldCheck,
          label: 'LEGITIMATE / CLEAN'
        };
    }
  };

  const badge = getVerdictBadge(currentAnalysis.threatVerdict || 'MALICIOUS');
  const BadgeIcon = badge.icon;

  return (
    <header className="h-16 border-b border-slate-800 bg-[#0F172A]/90 backdrop-blur px-6 flex items-center justify-between shrink-0 z-20">
      {/* Left: Active Case Switcher & Title */}
      <div className="flex items-center gap-4 min-w-0">
        <div className="relative">
          <button
            onClick={() => setDropdownOpen(!dropdownOpen)}
            className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-800/80 border border-slate-700 hover:border-slate-600 text-sm font-medium text-slate-200 transition-colors"
          >
            <Shield className="w-4 h-4 text-cyan-400" />
            <span className="max-w-[200px] truncate font-mono text-xs text-slate-300">
              {currentAnalysis.id || 'CASE-ACTIVE'}
            </span>
            <ChevronDown className="w-3.5 h-3.5 text-slate-400" />
          </button>

          {dropdownOpen && (
            <div className="absolute left-0 mt-2 w-72 rounded-xl bg-slate-900 border border-slate-800 shadow-2xl p-2 z-50">
              <div className="text-[11px] font-semibold uppercase text-slate-500 px-2 py-1 tracking-wider">
                Preset Forensic Samples
              </div>
              <div className="space-y-1 mt-1">
                {SAMPLE_ANALYSES.map((sample) => (
                  <button
                    key={sample.id}
                    onClick={() => {
                      onSelectAnalysis(sample);
                      setDropdownOpen(false);
                    }}
                    className={`w-full text-left px-2.5 py-2 rounded-lg text-xs transition-colors flex flex-col gap-0.5 ${
                      sample.id === currentAnalysis.id
                        ? 'bg-cyan-950/60 border border-cyan-800/60 text-cyan-300'
                        : 'hover:bg-slate-800 text-slate-300'
                    }`}
                  >
                    <span className="font-semibold truncate">{sample.subject}</span>
                    <span className="text-[10px] text-slate-500 font-mono truncate">{sample.from}</span>
                  </button>
                ))}
              </div>
            </div>
          )}
        </div>

        <div className="hidden md:flex flex-col min-w-0">
          <h1 className="text-sm font-semibold text-slate-100 truncate max-w-md">
            {currentAnalysis.subject || 'Forensic Case View'}
          </h1>
          <span className="text-xs text-slate-400 truncate">
            From: <span className="text-slate-300 font-mono">{currentAnalysis.from}</span>
          </span>
        </div>

        {/* Verdict Pill */}
        <div className={`hidden sm:flex items-center gap-1.5 px-2.5 py-1 rounded-full border text-xs font-semibold ${badge.bg}`}>
          <BadgeIcon className="w-3.5 h-3.5" />
          <span>{badge.label}</span>
          <span className="opacity-80">({currentAnalysis.threatScore || 0}/100)</span>
        </div>
      </div>

      {/* Right: Actions */}
      <div className="flex items-center gap-2.5">
        {/* Active Authenticated Session Badge */}
        {false && (
          <div
            className="hidden xl:flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg border bg-emerald-950/40 border-emerald-700/60 text-emerald-300 text-xs shadow-sm"
            title={`Active Verified Session: ${sessionUser?.email || 'analyst@acmedefense.sec'}\nRole: ${sessionUser?.role || 'analyst'} (JWT in-memory)\nPII Access: Full Forensic Clearance`}
          >
            <UserCheck className="w-3.5 h-3.5 text-emerald-400" />
            <span className="text-slate-400 font-sans text-[11px]">Identity:</span>
            <span className="font-semibold text-emerald-300 font-sans">
              {sessionUser?.label || 'Security Analyst'}
            </span>
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse ml-0.5" />
          </div>
        )}

        {false && onToggleDemoCases && (
          <button
            onClick={onToggleDemoCases}
            className={`flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg border text-xs font-medium transition-colors ${
              showDemoCases
                ? 'bg-amber-950/70 border-amber-600/80 text-amber-300'
                : 'bg-slate-800/80 hover:bg-slate-700/80 border-slate-700 text-slate-400'
            }`}
            title={showDemoCases ? 'Sample Datasets Included (Click to toggle)' : 'Live Cases Only (Click to include sample cases)'}
          >
            <FlaskConical className={`w-3.5 h-3.5 ${showDemoCases ? 'text-amber-400' : 'text-slate-500'}`} />
            <span>Sample Data: <strong className={showDemoCases ? 'text-amber-200 font-bold' : 'text-slate-300 font-semibold'}>{showDemoCases ? 'Active' : 'Hidden'}</strong></span>
          </button>
        )}

        {onOpenPrivacyModal && (
          <button
            onClick={onOpenPrivacyModal}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg border text-xs font-medium transition-colors ${
              privacyConfig?.maskingEnabled
                ? 'bg-purple-950/70 border-purple-700 text-purple-200'
                : 'bg-slate-800 hover:bg-slate-700 border-slate-700 text-slate-300'
            }`}
            title="Configure Privacy Safeguards, Retention & PII Masking"
          >
            <Scale className="w-3.5 h-3.5 text-purple-400" />
            <span className="hidden lg:inline">Privacy &amp; Compliance</span>
            {privacyConfig?.maskingEnabled && (
              <span className="w-1.5 h-1.5 rounded-full bg-purple-400 animate-pulse" />
            )}
          </button>
        )}

        <button
          onClick={onOpenReportModal}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700 text-xs font-medium text-slate-200 transition-colors"
        >
          <FileDown className="w-3.5 h-3.5 text-cyan-400" />
          <span className="hidden sm:inline">Export Forensic Report</span>
        </button>

        <button
          onClick={onOpenNewModal}
          className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-xs font-semibold text-white shadow-lg shadow-cyan-950/30 transition-all"
        >
          <Plus className="w-4 h-4" />
          <span>New Analysis</span>
        </button>
      </div>
    </header>
  );
}
