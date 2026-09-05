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
  UserCheck,
  FileText,
  Image as ImageIcon,
  Loader2
} from 'lucide-react';
import { EmailAnalysis } from '../types';
import { SAMPLE_ANALYSES } from '../data/samples';
import { PrivacyConfig } from '../utils/privacyCompliance';
import { subscribeSession, SessionUser } from '../lib/api';
import { exportEvidenceAsPdf, exportEvidenceAsImage } from '../utils/exportEvidence';
import { EvidenceTagCard } from './EvidenceTagCard';
import { AuthModal } from './AuthModal';
import { UserRole } from '../hooks/useSession';
import { LogOut } from 'lucide-react';

interface HeaderProps {
  currentAnalysis: EmailAnalysis;
  onSelectAnalysis: (analysis: EmailAnalysis) => void;
  onOpenNewModal: () => void;
  onOpenReportModal: () => void;
  onOpenPrivacyModal?: () => void;
  privacyConfig?: PrivacyConfig;
  showDemoCases?: boolean;
  onToggleDemoCases?: () => void;
  role?: UserRole;
  userLabel?: string;
  onSignOut?: () => void;
  onSwitchRole?: (newRole: UserRole) => void;
}

export function Header({
  currentAnalysis,
  onSelectAnalysis,
  onOpenNewModal,
  onOpenReportModal,
  onOpenPrivacyModal,
  privacyConfig,
  showDemoCases = false,
  onToggleDemoCases,
  role = 'analyst',
  userLabel = 'SA',
  onSignOut,
  onSwitchRole
}: HeaderProps) {
  const [dropdownOpen, setDropdownOpen] = useState(false);
  const [sessionUser, setSessionUser] = useState<SessionUser | null>(null);
  const [exportingPdf, setExportingPdf] = useState(false);
  const [exportingPng, setExportingPng] = useState(false);
  const [isAuthModalOpen, setIsAuthModalOpen] = useState(false);
  const [userDropdownOpen, setUserDropdownOpen] = useState(false);

  useEffect(() => {
    return subscribeSession((sess) => {
      setSessionUser(sess.user);
    });
  }, []);

  const getExportTargetElement = (): HTMLElement | null => {
    // Prefer visible .evidence-card or #card in main view first, fallback to header target card
    const visibleCard = document.querySelector('main .evidence-card') as HTMLElement || 
                        document.querySelector('.evidence-card') as HTMLElement || 
                        document.getElementById('card');
    if (visibleCard) return visibleCard;

    const headerHiddenCard = document.getElementById('header-evidence-export-target')?.querySelector('.evidence-card') as HTMLElement;
    return headerHiddenCard || null;
  };

  const handleExportPdf = async () => {
    const target = getExportTargetElement();
    setExportingPdf(true);
    try {
      const filename = `TraceXMail-Evidence-${currentAnalysis.id || 'case'}.pdf`;
      await exportEvidenceAsPdf(target!, filename, {
        caseId: currentAnalysis.id,
        evidenceId: currentAnalysis.evidenceId || currentAnalysis.id,
        title: currentAnalysis.subject,
        analysis: currentAnalysis
      });
    } catch (err) {
      console.error('Failed to export Evidence as PDF:', err);
    } finally {
      setExportingPdf(false);
    }
  };

  const handleExportPng = async () => {
    const target = getExportTargetElement();
    setExportingPng(true);
    try {
      const filename = `TraceXMail-Evidence-${currentAnalysis.id || 'case'}.png`;
      await exportEvidenceAsImage(target!, filename, {
        caseId: currentAnalysis.id,
        evidenceId: currentAnalysis.evidenceId || currentAnalysis.id,
        title: currentAnalysis.subject,
        analysis: currentAnalysis
      });
    } catch (err) {
      console.error('Failed to export Evidence as PNG:', err);
    } finally {
      setExportingPng(false);
    }
  };

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
    <header className="h-16 border-b border-[#3a352c] bg-[#14120f]/90 backdrop-blur px-6 flex items-center justify-between shrink-0 z-20 select-none">
      {/* Left: Active Case Switcher & Title */}
      <div className="flex items-center gap-4 min-w-0">
        <div className="relative">
          <button
            onClick={() => setDropdownOpen(!dropdownOpen)}
            className="flex items-center gap-2 px-3 py-1.5 rounded-md bg-[#221e17] border border-[#3a352c] hover:border-[#b9af9c] text-sm font-medium text-[#ede6d8] transition-colors cursor-pointer"
          >
            <Shield className="w-4 h-4 text-[#7fa3ba]" />
            <span className="max-w-[200px] truncate font-mono text-xs text-[#ede6d8]">
              {currentAnalysis.id || 'CASE-ACTIVE'}
            </span>
            <ChevronDown className="w-3.5 h-3.5 text-[#8a8070]" />
          </button>

          {dropdownOpen && (
            <div className="absolute left-0 mt-2 w-72 rounded-lg bg-[#1a1712] border border-[#3a352c] shadow-2xl p-2 z-50">
              <div className="text-[10px] font-mono font-semibold uppercase text-[#8a8070] px-2 py-1 tracking-wider">
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
                    className={`w-full text-left px-2.5 py-2 rounded text-xs transition-colors flex flex-col gap-0.5 cursor-pointer ${
                      sample.id === currentAnalysis.id
                        ? 'bg-[#b23a2e]/20 border border-[#b23a2e]/40 text-[#ede6d8]'
                        : 'hover:bg-[#221e17] text-[#b9af9c]'
                    }`}
                  >
                    <span className="font-display font-semibold truncate text-[#ede6d8]">{sample.subject}</span>
                    <span className="text-[10px] text-[#8a8070] font-mono truncate">{sample.from}</span>
                  </button>
                ))}
              </div>
            </div>
          )}
        </div>

        <div className="hidden md:flex flex-col min-w-0">
          <h1 className="font-display text-sm font-semibold text-[#ede6d8] truncate max-w-md">
            {currentAnalysis.subject || 'Forensic Case View'}
          </h1>
          <span className="text-xs text-[#8a8070] truncate">
            From: <span className="text-[#b9af9c] font-mono">{currentAnalysis.from}</span>
          </span>
        </div>

        {/* Verdict Pill */}
        <div className={`hidden sm:flex items-center gap-1.5 px-2.5 py-1 rounded-full border text-xs font-semibold ${badge.bg}`}>
          <BadgeIcon className="w-3.5 h-3.5" />
          <span>{badge.label}</span>
          <span className="opacity-80 font-mono">({currentAnalysis.threatScore || 0}/100)</span>
        </div>
      </div>

      {/* Right: Actions */}
      <div className="flex items-center gap-2.5">
        {/* Role-Differentiated Clearance Badge & Avatar matching design */}
        <div className="relative">
          <div 
            onClick={() => setUserDropdownOpen(!userDropdownOpen)}
            className="flex items-center gap-2 px-2 py-1 rounded-lg hover:bg-[#171b24] transition-colors cursor-pointer border border-transparent hover:border-[#232833]"
            title={`Clearance: ${role.toUpperCase()} | User: ${sessionUser?.email || userLabel}`}
          >
            <span className={`font-mono text-[10.5px] px-2 py-0.5 rounded font-medium tracking-wide ${
              role === 'admin'
                ? 'bg-[#c9a227]/15 text-[#c9a227] border border-[#c9a227]/30'
                : role === 'read_only'
                  ? 'bg-[#7d8794]/20 text-[#7d8794] border border-[#7d8794]/30'
                  : 'bg-[#5b8dd6]/15 text-[#5b8dd6] border border-[#5b8dd6]/30'
            }`}>
              {role === 'read_only' ? 'READ-ONLY' : role.toUpperCase()}
            </span>
            <div className="w-7 h-7 rounded-full bg-[#171b24] border border-[#232833] flex items-center justify-center text-[11px] font-mono text-[#e7ebf1] font-semibold select-none">
              {userLabel}
            </div>
          </div>

          {userDropdownOpen && (
            <div className="absolute right-0 mt-1 w-60 bg-[#12151c] border border-[#232833] rounded-lg shadow-xl py-1.5 z-50 text-xs text-[#e7ebf1] animate-in fade-in zoom-in-95 duration-100 divide-y divide-[#232833]">
              <div className="px-3 py-2 text-[11px] text-[#7d8794]">
                <div className="font-mono text-[10px] uppercase text-[#4f5763]">Operator Identity</div>
                <div className="truncate text-[#e7ebf1] font-medium mt-0.5">{sessionUser?.email || userLabel}</div>
                <div className="font-mono text-[10px] text-[#5b8dd6] mt-0.5">Role: <span className="font-semibold uppercase text-[#e7ebf1]">{role}</span></div>
              </div>

              {/* Role Switcher */}
              {onSwitchRole && (
                <div className="px-2 py-1.5 space-y-1">
                  <div className="px-1 text-[10px] font-mono text-[#7d8794] uppercase">Switch Enclave Role:</div>
                  <div className="grid grid-cols-3 gap-1">
                    <button
                      onClick={() => {
                        onSwitchRole('admin');
                        setUserDropdownOpen(false);
                      }}
                      className={`px-1.5 py-1 text-[10px] font-mono rounded text-center transition-colors cursor-pointer ${
                        role === 'admin' 
                          ? 'bg-[#c9a227]/30 text-[#c9a227] font-bold border border-[#c9a227]/50' 
                          : 'bg-[#1a1e27] text-[#7d8794] hover:text-[#e7ebf1]'
                      }`}
                    >
                      ADMIN
                    </button>
                    <button
                      onClick={() => {
                        onSwitchRole('analyst');
                        setUserDropdownOpen(false);
                      }}
                      className={`px-1.5 py-1 text-[10px] font-mono rounded text-center transition-colors cursor-pointer ${
                        role === 'analyst' 
                          ? 'bg-[#5b8dd6]/30 text-[#5b8dd6] font-bold border border-[#5b8dd6]/50' 
                          : 'bg-[#1a1e27] text-[#7d8794] hover:text-[#e7ebf1]'
                      }`}
                    >
                      ANALYST
                    </button>
                    <button
                      onClick={() => {
                        onSwitchRole('read_only');
                        setUserDropdownOpen(false);
                      }}
                      className={`px-1.5 py-1 text-[10px] font-mono rounded text-center transition-colors cursor-pointer ${
                        role === 'read_only' 
                          ? 'bg-[#7d8794]/30 text-[#7d8794] font-bold border border-[#7d8794]/50' 
                          : 'bg-[#1a1e27] text-[#7d8794] hover:text-[#e7ebf1]'
                      }`}
                    >
                      AUDITOR
                    </button>
                  </div>
                </div>
              )}

              {onSignOut && (
                <div className="py-1">
                  <button
                    onClick={() => {
                      setUserDropdownOpen(false);
                      onSignOut();
                    }}
                    className="w-full text-left px-3 py-1.5 text-[#c25a4a] hover:bg-[#c25a4a]/10 flex items-center gap-2 cursor-pointer transition-colors"
                  >
                    <LogOut className="w-3.5 h-3.5" />
                    <span>Sign out of enclave</span>
                  </button>
                </div>
              )}
            </div>
          )}
        </div>

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
          onClick={handleExportPdf}
          disabled={exportingPdf}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800/90 hover:bg-slate-700 border border-slate-700/90 hover:border-cyan-500/50 text-xs font-medium text-slate-200 transition-all cursor-pointer disabled:opacity-50"
          title="Export Evidence Card as PDF Dossier"
        >
          {exportingPdf ? (
            <Loader2 className="w-3.5 h-3.5 text-cyan-400 animate-spin" />
          ) : (
            <FileText className="w-3.5 h-3.5 text-rose-400" />
          )}
          <span className="hidden sm:inline font-sans">Export as PDF</span>
          <span className="sm:hidden font-sans">PDF</span>
        </button>

        <button
          onClick={handleExportPng}
          disabled={exportingPng}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800/90 hover:bg-slate-700 border border-slate-700/90 hover:border-cyan-500/50 text-xs font-medium text-slate-200 transition-all cursor-pointer disabled:opacity-50"
          title="Export Evidence Card as PNG Image"
        >
          {exportingPng ? (
            <Loader2 className="w-3.5 h-3.5 text-cyan-400 animate-spin" />
          ) : (
            <ImageIcon className="w-3.5 h-3.5 text-emerald-400" />
          )}
          <span className="hidden sm:inline font-sans">Export as PNG</span>
          <span className="sm:hidden font-sans">PNG</span>
        </button>

        <button
          onClick={onOpenReportModal}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700 text-xs font-medium text-slate-200 transition-colors"
        >
          <FileDown className="w-3.5 h-3.5 text-cyan-400" />
          <span className="hidden xl:inline">Export Forensic Report</span>
        </button>

        <button
          onClick={onOpenNewModal}
          className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-xs font-semibold text-white shadow-lg shadow-cyan-950/30 transition-all"
        >
          <Plus className="w-4 h-4" />
          <span>New Analysis</span>
        </button>
      </div>

      {/* Hidden Evidence Card Export Target Container */}
      <div 
        id="header-evidence-export-target" 
        className="fixed -left-[9999px] -top-[9999px] w-[720px] pointer-events-none opacity-0 z-[-9999] aria-hidden"
        aria-hidden="true"
      >
        <EvidenceTagCard analysis={currentAnalysis} />
      </div>

      <AuthModal
        isOpen={isAuthModalOpen}
        onClose={() => setIsAuthModalOpen(false)}
        currentUser={sessionUser}
      />
    </header>
  );
}
