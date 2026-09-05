import React, { useState, FormEvent } from 'react';
import { supabase, isSupabaseConfigured } from '../lib/supabaseClient';
import { Loader2, AlertCircle, ArrowLeft, Shield, CheckCircle2, UserCheck, KeyRound, ShieldAlert, Eye, Terminal } from 'lucide-react';
import { UserRole } from '../hooks/useSession';

interface LoginViewProps {
  onBackToGate?: () => void;
  onBackToIntro?: () => void;
  onRequestAccess?: () => void;
  onSuccess?: () => void;
  onSelectRoleLogin?: (role: UserRole, options?: { email?: string; fullName?: string; orgName?: string }) => void;
}

export function LoginView({ 
  onBackToGate, 
  onBackToIntro,
  onRequestAccess, 
  onSuccess,
  onSelectRoleLogin 
}: LoginViewProps) {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const handleBack = onBackToIntro || onBackToGate;

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    if (!email || !password) {
      setErrorMsg('Please enter both your work email and password.');
      return;
    }

    setLoading(true);
    setErrorMsg(null);

    try {
      // If Supabase is configured, use real Supabase authentication
      if (isSupabaseConfigured && supabase) {
        const { data, error } = await supabase.auth.signInWithPassword({
          email: email.trim(),
          password
        });

        if (error) {
          setErrorMsg(error.message || 'Authentication failed. Please verify your credentials.');
          setLoading(false);
          return;
        }

        if (data.session) {
          if (onSuccess) onSuccess();
          return;
        }
      }

      // Enclave / Direct role verification fallback
      let determinedRole: UserRole = 'analyst';
      const lowerEmail = email.toLowerCase();
      if (lowerEmail.includes('admin') || lowerEmail.includes('lead') || lowerEmail.includes('commander')) {
        determinedRole = 'admin';
      } else if (lowerEmail.includes('audit') || lowerEmail.includes('readonly') || lowerEmail.includes('guest')) {
        determinedRole = 'read_only';
      }

      if (onSelectRoleLogin) {
        onSelectRoleLogin(determinedRole, {
          email: email.trim(),
          fullName: email.split('@')[0].replace(/[._]/g, ' ').replace(/\b\w/g, c => c.toUpperCase()),
          orgName: 'Enterprise Security Enclave'
        });
      } else if (onSuccess) {
        onSuccess();
      }
    } catch (err: any) {
      console.error('[Login] Authentication error:', err);
      setErrorMsg(err.message || 'An unexpected error occurred during sign in.');
      setLoading(false);
    }
  };

  const handleQuickRole = (role: UserRole, roleName: string, roleEmail: string) => {
    if (onSelectRoleLogin) {
      onSelectRoleLogin(role, {
        email: roleEmail,
        fullName: roleName,
        orgName: 'Acme Cyber Defense SOC'
      });
    } else if (onSuccess) {
      onSuccess();
    }
  };

  return (
    <div className="min-h-screen w-screen flex items-center justify-center bg-[var(--ink)] bg-[radial-gradient(ellipse_900px_500px_at_50%_-10%,rgba(178,58,46,0.08),transparent_60%)] p-4 text-[var(--paper)] font-sans select-text relative">
      {/* Background Subtle Forensic Grid */}
      <div 
        className="absolute inset-0 pointer-events-none opacity-20"
        style={{
          backgroundImage: 'radial-gradient(circle at 1px 1px, #3a352c 1px, transparent 0)',
          backgroundSize: '32px 32px'
        }}
      />

      <div className="w-full max-w-[460px] bg-[var(--ink-2)] border border-[var(--line)] rounded-sm p-7 md:p-8 shadow-[0_30px_70px_rgba(0,0,0,0.7)] animate-in fade-in zoom-in-95 duration-200 relative z-10">
        
        {/* Top bar with back button & Case ID stamp */}
        <div className="flex items-center justify-between mb-5 border-b border-[var(--line)] pb-3">
          {handleBack && (
            <button
              onClick={handleBack}
              className="text-[var(--paper-dim)] hover:text-[var(--paper)] text-xs flex items-center gap-1.5 transition-colors cursor-pointer"
              title="Return to Intro Page"
            >
              <ArrowLeft className="w-3.5 h-3.5 text-[var(--thread)]" />
              <span>Back to Intro Page</span>
            </button>
          )}

          <div className="font-mono text-[10.5px] text-[var(--stamp)] uppercase tracking-wider ml-auto flex items-center gap-1">
            <span className="w-1.5 h-1.5 rounded-full bg-[var(--stamp)] animate-pulse" />
            <span>AUTH · RESTRICTED</span>
          </div>
        </div>

        {/* Brand Header */}
        <div className="flex items-center gap-2.5 mb-1.5">
          <div className="w-5 h-5 rounded-full border-[1.5px] border-[var(--thread)] relative shrink-0">
            <div className="absolute inset-1 rounded-full bg-[var(--thread)]" />
          </div>
          <span className="font-display font-bold text-xl text-[var(--paper)] tracking-tight">
            TraceXMail Enclave
          </span>
          <span className="font-mono text-[10px] px-1.5 py-0.5 rounded-[2px] bg-[rgba(127,163,186,0.15)] text-[var(--slate)] border border-[rgba(127,163,186,0.3)] ml-auto">
            ZERO-TRUST
          </span>
        </div>

        <div className="text-[var(--paper-dim)] text-[13px] mb-5 font-normal">
          Email forensic intelligence — sign in with your credentials or verify active SOC clearance
        </div>

        {errorMsg && (
          <div className="mb-4 p-3 rounded-[2px] bg-[rgba(178,58,46,0.15)] border border-[var(--thread)] text-[var(--rose-300)] text-xs flex items-start gap-2.5">
            <AlertCircle className="w-4 h-4 shrink-0 mt-0.5 text-[var(--thread)]" />
            <div className="leading-relaxed font-sans">{errorMsg}</div>
          </div>
        )}

        {/* Quick Role Verification Presets */}
        <div className="mb-5 p-3.5 rounded-[2px] bg-[var(--ink)] border border-[var(--line)]">
          <div className="flex items-center justify-between mb-2.5">
            <span className="text-[11px] font-mono text-[var(--paper-dim)] uppercase tracking-wider flex items-center gap-1.5">
              <KeyRound className="w-3 h-3 text-[var(--slate)]" />
              Select Clearance Tier:
            </span>
            <span className="text-[10px] font-mono text-[var(--forensic-green)] flex items-center gap-1">
              <span className="w-1.5 h-1.5 rounded-full bg-[var(--forensic-green)]" />
              Instant Grant
            </span>
          </div>

          <div className="grid grid-cols-3 gap-2">
            <button
              type="button"
              onClick={() => handleQuickRole('admin', 'Commander Alex Vance', 'admin@tracexmail.sec')}
              className="p-2.5 rounded-[2px] border border-[rgba(201,162,39,0.35)] bg-[rgba(201,162,39,0.08)] hover:bg-[rgba(201,162,39,0.18)] hover:border-[var(--stamp)] text-left transition-all cursor-pointer group"
            >
              <div className="flex items-center justify-between mb-1">
                <span className="font-mono text-[10px] font-bold text-[var(--stamp)]">ADMIN</span>
                <ShieldAlert className="w-3 h-3 text-[var(--stamp)] opacity-80 group-hover:opacity-100" />
              </div>
              <div className="text-[11px] text-[var(--paper)] truncate font-semibold">Commander</div>
              <div className="text-[9px] text-[var(--paper-dim)] font-mono truncate">Full Enclave</div>
            </button>

            <button
              type="button"
              onClick={() => handleQuickRole('analyst', 'Senior Analyst Sarah Chen', 'analyst@tracexmail.sec')}
              className="p-2.5 rounded-[2px] border border-[rgba(127,163,186,0.35)] bg-[rgba(127,163,186,0.08)] hover:bg-[rgba(127,163,186,0.18)] hover:border-[var(--slate)] text-left transition-all cursor-pointer group"
            >
              <div className="flex items-center justify-between mb-1">
                <span className="font-mono text-[10px] font-bold text-[var(--slate)]">ANALYST</span>
                <Shield className="w-3 h-3 text-[var(--slate)] opacity-80 group-hover:opacity-100" />
              </div>
              <div className="text-[11px] text-[var(--paper)] truncate font-semibold">Tier 2 SOC</div>
              <div className="text-[9px] text-[var(--paper-dim)] font-mono truncate">Forensics</div>
            </button>

            <button
              type="button"
              onClick={() => handleQuickRole('read_only', 'Auditor Marcus Reed', 'auditor@tracexmail.sec')}
              className="p-2.5 rounded-[2px] border border-[var(--line)] bg-[var(--ink-2)] hover:bg-[rgba(237,230,216,0.08)] hover:border-[var(--paper-dim)] text-left transition-all cursor-pointer group"
            >
              <div className="flex items-center justify-between mb-1">
                <span className="font-mono text-[10px] font-bold text-[var(--paper-dim)]">AUDITOR</span>
                <Eye className="w-3 h-3 text-[var(--paper-dim)] opacity-80 group-hover:opacity-100" />
              </div>
              <div className="text-[11px] text-[var(--paper)] truncate font-semibold">Read-Only</div>
              <div className="text-[9px] text-[var(--paper-dim)] font-mono truncate">PII Masked</div>
            </button>
          </div>
        </div>

        <div className="flex items-center gap-3 my-3 text-xs text-[var(--line)]">
          <div className="flex-1 h-px bg-[var(--line)]" />
          <span className="font-mono text-[10px] uppercase text-[var(--paper-muted)] tracking-wider">or sign in with credentials</span>
          <div className="flex-1 h-px bg-[var(--line)]" />
        </div>

        <form onSubmit={handleSubmit} className="space-y-3.5">
          <div className="space-y-1">
            <label className="block text-xs text-[var(--paper-dim)] font-medium" htmlFor="login-email">
              Work email / Operator ID
            </label>
            <input
              id="login-email"
              type="email"
              required
              autoComplete="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="operator@defense.sec"
              disabled={loading}
              className="w-full bg-[var(--ink)] border border-[var(--line)] focus:border-[var(--slate)] focus:outline-hidden rounded-[2px] px-3.5 py-2 text-sm text-[var(--paper)] placeholder-[var(--paper-muted)] transition-colors disabled:opacity-50 font-sans"
            />
          </div>

          <div className="space-y-1">
            <label className="block text-xs text-[var(--paper-dim)] font-medium" htmlFor="login-password">
              Password
            </label>
            <input
              id="login-password"
              type="password"
              required
              autoComplete="current-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="••••••••••••"
              disabled={loading}
              className="w-full bg-[var(--ink)] border border-[var(--line)] focus:border-[var(--slate)] focus:outline-hidden rounded-[2px] px-3.5 py-2 text-sm text-[var(--paper)] placeholder-[var(--paper-muted)] transition-colors disabled:opacity-50 font-sans"
            />
          </div>

          <button
            type="submit"
            disabled={loading}
            className="btn-primary w-full mt-2 text-center flex items-center justify-center gap-2 cursor-pointer disabled:opacity-50"
          >
            {loading ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin text-[var(--paper)]" />
                <span>Verifying Credentials…</span>
              </>
            ) : (
              <span>Sign In &amp; Access Enclave</span>
            )}
          </button>
        </form>

        {onRequestAccess && (
          <div className="mt-4 pt-3.5 border-t border-[var(--line)] text-center">
            <button
              type="button"
              onClick={onRequestAccess}
              className="text-xs text-[var(--slate)] hover:text-[var(--paper)] hover:underline cursor-pointer transition-colors"
            >
              Need clearance? Request access for your organization →
            </button>
          </div>
        )}

        <div className="mt-4 text-[11px] font-mono text-[var(--paper-muted)] text-center tracking-wide">
          MIL-STD / NIST SP 800-86 RESTRICTED FORENSIC ENCLAVE
        </div>
      </div>
    </div>
  );
}
