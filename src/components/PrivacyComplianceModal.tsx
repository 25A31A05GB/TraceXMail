import React from 'react';
import { 
  ShieldCheck, 
  Lock, 
  EyeOff, 
  Clock, 
  Trash2, 
  X, 
  Check, 
  AlertCircle, 
  FileLock2, 
  Scale, 
  CheckCircle2,
  Sliders,
  Sparkles
} from 'lucide-react';
import { 
  PrivacyConfig, 
  RetentionPolicy, 
  MaskingMode, 
  getRetentionPurgeDate 
} from '../utils/privacyCompliance';

interface PrivacyComplianceModalProps {
  isOpen: boolean;
  onClose: () => void;
  config: PrivacyConfig;
  onChangeConfig: (newConfig: PrivacyConfig) => void;
  currentDate?: string;
}

export function PrivacyComplianceModal({
  isOpen,
  onClose,
  config,
  onChangeConfig,
  currentDate
}: PrivacyComplianceModalProps) {
  if (!isOpen) return null;

  const purgeInfo = getRetentionPurgeDate(config.retentionPolicy, currentDate);

  const handleToggleMasking = () => {
    onChangeConfig({ ...config, maskingEnabled: !config.maskingEnabled });
  };

  const handleRetentionChange = (policy: RetentionPolicy) => {
    onChangeConfig({ ...config, retentionPolicy: policy });
  };

  const handleMaskingModeChange = (mode: MaskingMode) => {
    onChangeConfig({ ...config, maskingMode: mode });
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-in fade-in duration-200">
      <div className="bg-slate-900 border border-slate-800 rounded-2xl w-full max-w-2xl max-h-[90vh] flex flex-col shadow-2xl overflow-hidden">
        {/* Header */}
        <div className="p-5 border-b border-slate-800 flex items-center justify-between bg-slate-950/60">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-purple-950/80 border border-purple-800/80 flex items-center justify-center">
              <Scale className="w-5 h-5 text-purple-400" />
            </div>
            <div>
              <h2 className="text-base font-bold text-slate-100 flex items-center gap-2">
                <span>Privacy, Legal &amp; Compliance Controls</span>
                <span className="text-[10px] px-2 py-0.5 rounded bg-purple-950 border border-purple-800 text-purple-300 font-mono">
                  {config.complianceStandard}
                </span>
              </h2>
              <p className="text-xs text-slate-400">
                Controlled data handling, configurable retention &amp; sensitive data masking
              </p>
            </div>
          </div>

          <button
            onClick={onClose}
            className="p-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-slate-200 transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Content */}
        <div className="flex-1 overflow-y-auto p-6 space-y-6 text-slate-300 text-sm">
          {/* Top Master Toggle: Sensitive Data Masking */}
          <div className="p-4 rounded-xl bg-slate-800/40 border border-slate-800 flex items-center justify-between">
            <div className="flex items-start gap-3">
              <EyeOff className={`w-5 h-5 mt-0.5 ${config.maskingEnabled ? 'text-purple-400' : 'text-slate-500'}`} />
              <div>
                <div className="font-semibold text-slate-100 flex items-center gap-2">
                  <span>Sensitive Communication Data Masking</span>
                  {config.maskingEnabled && (
                    <span className="text-[10px] px-2 py-0.5 rounded-full bg-emerald-950 border border-emerald-800 text-emerald-300 font-medium">
                      ACTIVE IN UI &amp; EXPORT
                    </span>
                  )}
                </div>
                <div className="text-xs text-slate-400 mt-0.5">
                  Redacts personally identifiable information (PII), recipient addresses, and private network topologies according to data minimization principles.
                </div>
              </div>
            </div>

            <button
              onClick={handleToggleMasking}
              className={`relative inline-flex h-6 w-11 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none ${
                config.maskingEnabled ? 'bg-purple-600' : 'bg-slate-700'
              }`}
            >
              <span
                className={`pointer-events-none inline-block h-5 w-5 transform rounded-full bg-white shadow ring-0 transition duration-200 ease-in-out ${
                  config.maskingEnabled ? 'translate-x-5' : 'translate-x-0'
                }`}
              />
            </button>
          </div>

          {/* Granular Masking Options (Shown if masking enabled) */}
          {config.maskingEnabled && (
            <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800 space-y-4">
              <div className="text-xs font-bold uppercase tracking-wider text-slate-400 flex items-center gap-2">
                <Sliders className="w-3.5 h-3.5 text-purple-400" />
                <span>Masking Granularity &amp; Redaction Style</span>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
                <button
                  type="button"
                  onClick={() => handleMaskingModeChange('pseudonymized')}
                  className={`p-2.5 rounded-lg border text-left transition-colors ${
                    config.maskingMode === 'pseudonymized'
                      ? 'bg-purple-950/50 border-purple-500 text-purple-200'
                      : 'bg-slate-900 border-slate-800 text-slate-400 hover:text-slate-200'
                  }`}
                >
                  <div className="text-xs font-semibold">Pseudonymized</div>
                  <div className="text-[10px] text-slate-500 mt-0.5">j***e@domain.com</div>
                </button>

                <button
                  type="button"
                  onClick={() => handleMaskingModeChange('strict_redaction')}
                  className={`p-2.5 rounded-lg border text-left transition-colors ${
                    config.maskingMode === 'strict_redaction'
                      ? 'bg-purple-950/50 border-purple-500 text-purple-200'
                      : 'bg-slate-900 border-slate-800 text-slate-400 hover:text-slate-200'
                  }`}
                >
                  <div className="text-xs font-semibold">Strict Redaction</div>
                  <div className="text-[10px] text-slate-500 mt-0.5">[REDACTED_EMAIL]</div>
                </button>

                <button
                  type="button"
                  onClick={() => handleMaskingModeChange('anonymized')}
                  className={`p-2.5 rounded-lg border text-left transition-colors ${
                    config.maskingMode === 'anonymized'
                      ? 'bg-purple-950/50 border-purple-500 text-purple-200'
                      : 'bg-slate-900 border-slate-800 text-slate-400 hover:text-slate-200'
                  }`}
                >
                  <div className="text-xs font-semibold">Anonymized</div>
                  <div className="text-[10px] text-slate-500 mt-0.5">masked@domain.com</div>
                </button>
              </div>

              <div className="space-y-2 pt-2 border-t border-slate-800/80 text-xs">
                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={config.maskSenderRecipient}
                    onChange={(e) => onChangeConfig({ ...config, maskSenderRecipient: e.target.checked })}
                    className="rounded bg-slate-900 border-slate-700 text-purple-600 focus:ring-purple-500"
                  />
                  <span>Mask Sender and Recipient Email Addresses &amp; Names</span>
                </label>

                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={config.maskInternalIps}
                    onChange={(e) => onChangeConfig({ ...config, maskInternalIps: e.target.checked })}
                    className="rounded bg-slate-900 border-slate-700 text-purple-600 focus:ring-purple-500"
                  />
                  <span>Mask RFC 1918 Internal Network Subnets (e.g. 10.***.***.45)</span>
                </label>

                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={config.maskSubjectAndBody}
                    onChange={(e) => onChangeConfig({ ...config, maskSubjectAndBody: e.target.checked })}
                    className="rounded bg-slate-900 border-slate-700 text-purple-600 focus:ring-purple-500"
                  />
                  <span>Redact Financial Wire Identifiers, Amounts &amp; Credential Phrases</span>
                </label>
              </div>
            </div>
          )}

          {/* Configurable Retention Section */}
          <div className="p-4 rounded-xl bg-slate-800/40 border border-slate-800 space-y-4">
            <div className="flex items-start justify-between">
              <div className="flex items-center gap-2.5">
                <Clock className="w-5 h-5 text-cyan-400" />
                <div>
                  <div className="font-semibold text-slate-100">Configurable Data Retention Policy</div>
                  <div className="text-xs text-slate-400">
                    Defines automated lifecycle purging and evidence vault archiving.
                  </div>
                </div>
              </div>

              <span className="text-xs font-mono px-2 py-0.5 rounded bg-slate-800 text-cyan-300 border border-slate-700">
                {purgeInfo.daysRemaining === 9999 ? 'LOCKED' : `${purgeInfo.daysRemaining} days remaining`}
              </span>
            </div>

            <div className="grid grid-cols-2 sm:grid-cols-5 gap-2 pt-1">
              {[
                { id: 'ephemeral' as const, label: 'Ephemeral', sub: 'Zero-Retention' },
                { id: '30_days' as const, label: '30 Days', sub: 'Rapid Triage' },
                { id: '90_days' as const, label: '90 Days', sub: 'Standard Cycle' },
                { id: '365_days' as const, label: '1 Year', sub: 'Extended Cycle' },
                { id: 'legal_hold' as const, label: 'Legal Hold', sub: 'Subpoena Lock' }
              ].map((item) => (
                <button
                  key={item.id}
                  type="button"
                  onClick={() => handleRetentionChange(item.id)}
                  className={`p-2.5 rounded-lg border text-center transition-colors ${
                    config.retentionPolicy === item.id
                      ? 'bg-cyan-950/60 border-cyan-400 text-cyan-200 shadow-sm'
                      : 'bg-slate-900 border-slate-800 text-slate-400 hover:text-slate-200'
                  }`}
                >
                  <div className="text-xs font-semibold">{item.label}</div>
                  <div className="text-[10px] text-slate-500 mt-0.5">{item.sub}</div>
                </button>
              ))}
            </div>

            <div className="p-3 rounded-lg bg-slate-900/90 border border-slate-800 flex items-center justify-between text-xs">
              <div className="text-slate-400">
                <span>Scheduled Purge / Review Date: </span>
                <span className="font-mono text-slate-200 font-semibold">{purgeInfo.date}</span>
              </div>
              <div className="flex items-center gap-1 text-emerald-400 text-[11px] font-medium">
                <CheckCircle2 className="w-3.5 h-3.5" />
                <span>Lifecycle Rule Active</span>
              </div>
            </div>
          </div>

          {/* Evidence Preservation & Chain of Custody Box */}
          <div className="p-4 rounded-xl bg-slate-800/20 border border-slate-800 flex items-start gap-3">
            <FileLock2 className="w-5 h-5 text-emerald-400 shrink-0 mt-0.5" />
            <div className="text-xs space-y-1">
              <div className="font-semibold text-slate-200">Evidence Preservation &amp; Chain-of-Custody Standard</div>
              <div className="text-slate-400">
                Regardless of retention schedule, cryptographic SHA-256 integrity digests and evidence custody timestamps are maintained in the immutable audit log ({config.complianceStandard}).
              </div>
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="p-4 border-t border-slate-800 bg-slate-950/60 flex items-center justify-between">
          <div className="text-xs text-slate-500 flex items-center gap-2">
            <span>Investigator Operator:</span>
            <span className="font-mono text-slate-400">{config.operatorId}</span>
          </div>

          <button
            onClick={onClose}
            className="px-4 py-2 rounded-lg bg-purple-600 hover:bg-purple-500 text-xs font-semibold text-white transition-colors"
          >
            Apply Safeguards
          </button>
        </div>
      </div>
    </div>
  );
}
