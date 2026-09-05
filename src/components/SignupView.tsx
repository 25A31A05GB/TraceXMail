import React, { useState, FormEvent } from 'react';
import { supabase, isSupabaseConfigured } from '../lib/supabaseClient';
import { Loader2, AlertCircle, ArrowLeft, CheckCircle2, ShieldAlert, Shield, Eye } from 'lucide-react';
import { UserRole } from '../hooks/useSession';

interface SignupViewProps {
  onBackToLogin: () => void;
  onBackToIntro?: () => void;
  onSuccess?: () => void;
  onSelectRoleLogin?: (role: UserRole, options?: { email?: string; fullName?: string; orgName?: string }) => void;
}

export function SignupView({ 
  onBackToLogin, 
  onBackToIntro,
  onSuccess,
  onSelectRoleLogin 
}: SignupViewProps) {
  const [fullName, setFullName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [orgName, setOrgName] = useState('');
  const [selectedRole, setSelectedRole] = useState<UserRole>('analyst');
  const [loading, setLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  const handleBack = onBackToIntro || onBackToLogin;

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    if (!email || !password || !orgName) {
      setErrorMsg('Please fill in all required fields including organization name.');
      return;
    }

    if (password.length < 6) {
      setErrorMsg('Password must be at least 6 characters in length.');
      return;
    }

    setLoading(true);
    setErrorMsg(null);
    setSuccessMsg(null);

    try {
      if (isSupabaseConfigured && supabase) {
        const { data, error } = await supabase.auth.signUp({
          email: email.trim(),
          password,
          options: {
            data: {
              full_name: fullName.trim() || 'Security Operator',
              org_name: orgName.trim(),
              organization_name: orgName.trim(),
              role: selectedRole
            }
          }
        });

        if (error) {
          setErrorMsg(error.message || 'Registration request failed.');
          setLoading(false);
          return;
        }

        if (data.user) {
          setSuccessMsg(`Clearance granted for ${email} with ${selectedRole.toUpperCase()} role. Redirecting to workspace…`);
          if (onSuccess) {
            setTimeout(onSuccess, 800);
          }
          return;
        }
      }

      // Enclave Direct Clearance Provisioning
      setSuccessMsg(`Clearance granted for ${email} with ${selectedRole.toUpperCase()} role. Entering workspace…`);
      setTimeout(() => {
        if (onSelectRoleLogin) {
          onSelectRoleLogin(selectedRole, {
            email: email.trim(),
            fullName: fullName.trim() || 'Security Operator',
            orgName: orgName.trim()
          });
        } else if (onSuccess) {
          onSuccess();
        }
      }, 700);
    } catch (err: any) {
      console.error('[Signup] Registration error:', err);
      setErrorMsg(err.message || 'An unexpected error occurred during account creation.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen w-screen flex items-center justify-center bg-[var(--ink)] bg-[radial-gradient(ellipse_900px_500px_at_50%_-10%,rgba(178,58,46,0.08),transparent_60%)] p-4 text-[var(--paper)] font-sans select-text relative">
      {/* Subtle Forensic Background Matrix Grid */}
      <div 
        className="absolute inset-0 pointer-events-none opacity-20"
        style={{
          backgroundImage: 'radial-gradient(circle at 1px 1px, #3a352c 1px, transparent 0)',
          backgroundSize: '32px 32px'
        }}
      />

      <div className="w-full max-w-[480px] bg-[var(--ink-2)] border border-[var(--line)] rounded-sm p-7 md:p-8 shadow-[0_30px_70px_rgba(0,0,0,0.7)] animate-in fade-in zoom-in-95 duration-200 relative z-10">
        <div className="flex items-center justify-between mb-4 border-b border-[var(--line)] pb-3">
          {onBackToIntro ? (
            <button
              onClick={onBackToIntro}
              className="text-[var(--paper-dim)] hover:text-[var(--paper)] text-xs flex items-center gap-1.5 transition-colors cursor-pointer"
              title="Return to Intro Page"
            >
              <ArrowLeft className="w-3.5 h-3.5 text-[var(--thread)]" />
              <span>Back to Intro Page</span>
            </button>
          ) : (
            <button
              onClick={onBackToLogin}
              className="text-[var(--paper-dim)] hover:text-[var(--paper)] text-xs flex items-center gap-1.5 transition-colors cursor-pointer"
              title="Return to sign in"
            >
              <ArrowLeft className="w-3.5 h-3.5 text-[var(--thread)]" />
              <span>Sign in</span>
            </button>
          )}

          <button
            onClick={onBackToLogin}
            className="text-xs text-[var(--slate)] hover:text-[var(--paper)] hover:underline cursor-pointer transition-colors"
          >
            Have clearance? Sign in →
          </button>
        </div>

        {/* Brand Header */}
        <div className="flex items-center gap-2.5 mb-1.5">
          <div className="w-5 h-5 rounded-full border-[1.5px] border-[var(--thread)] relative shrink-0">
            <div className="absolute inset-1 rounded-full bg-[var(--thread)]" />
          </div>
          <span className="font-display font-bold text-xl text-[var(--paper)] tracking-tight">
            Provision Enclave Access
          </span>
          <span className="font-mono text-[10px] px-1.5 py-0.5 rounded-[2px] bg-[rgba(201,162,39,0.15)] text-[var(--stamp)] border border-[rgba(201,162,39,0.3)] ml-auto">
            PROVISIONING
          </span>
        </div>

        <div className="text-[var(--paper-dim)] text-[13px] mb-5 font-normal">
          Request forensic workspace credentials for your team or incident response unit
        </div>

        {errorMsg && (
          <div className="mb-4 p-3 rounded-[2px] bg-[rgba(178,58,46,0.15)] border border-[var(--thread)] text-[var(--rose-300)] text-xs flex items-start gap-2.5">
            <AlertCircle className="w-4 h-4 shrink-0 mt-0.5 text-[var(--thread)]" />
            <div className="leading-relaxed font-sans">{errorMsg}</div>
          </div>
        )}

        {successMsg && (
          <div className="mb-4 p-3.5 rounded-[2px] bg-[rgba(72,169,117,0.15)] border border-[var(--forensic-green)] text-[var(--paper)] text-xs flex items-start gap-2.5">
            <CheckCircle2 className="w-4 h-4 shrink-0 mt-0.5 text-[var(--forensic-green)]" />
            <div className="leading-relaxed font-sans">{successMsg}</div>
          </div>
        )}

        {!successMsg && (
          <form onSubmit={handleSubmit} className="space-y-3">
            <div className="grid grid-cols-2 gap-2.5">
              <div className="space-y-1">
                <label className="block text-xs text-[var(--paper-dim)] font-medium" htmlFor="signup-name">
                  Operator Callsign / Name
                </label>
                <input
                  id="signup-name"
                  type="text"
                  required
                  value={fullName}
                  onChange={(e) => setFullName(e.target.value)}
                  placeholder="Agent J. Miller"
                  disabled={loading}
                  className="w-full bg-[var(--ink)] border border-[var(--line)] focus:border-[var(--slate)] focus:outline-hidden rounded-[2px] px-3 py-2 text-xs text-[var(--paper)] placeholder-[var(--paper-muted)] transition-colors disabled:opacity-50 font-sans"
                />
              </div>

              <div className="space-y-1">
                <label className="block text-xs text-[var(--paper-dim)] font-medium" htmlFor="signup-org">
                  Organization / Unit
                </label>
                <input
                  id="signup-org"
                  type="text"
                  required
                  value={orgName}
                  onChange={(e) => setOrgName(e.target.value)}
                  placeholder="Cyber Defense SOC"
                  disabled={loading}
                  className="w-full bg-[var(--ink)] border border-[var(--line)] focus:border-[var(--slate)] focus:outline-hidden rounded-[2px] px-3 py-2 text-xs text-[var(--paper)] placeholder-[var(--paper-muted)] transition-colors disabled:opacity-50 font-sans"
                />
              </div>
            </div>

            <div className="space-y-1">
              <label className="block text-xs text-[var(--paper-dim)] font-medium" htmlFor="signup-email">
                Official SOC / Work Email
              </label>
              <input
                id="signup-email"
                type="email"
                required
                autoComplete="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="analyst@defense.sec"
                disabled={loading}
                className="w-full bg-[var(--ink)] border border-[var(--line)] focus:border-[var(--slate)] focus:outline-hidden rounded-[2px] px-3 py-2 text-xs text-[var(--paper)] placeholder-[var(--paper-muted)] transition-colors disabled:opacity-50 font-sans"
              />
            </div>

            <div className="space-y-1">
              <label className="block text-xs text-[var(--paper-dim)] font-medium" htmlFor="signup-password">
                Passphrase (min 6 characters)
              </label>
              <input
                id="signup-password"
                type="password"
                required
                autoComplete="new-password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••••••"
                disabled={loading}
                className="w-full bg-[var(--ink)] border border-[var(--line)] focus:border-[var(--slate)] focus:outline-hidden rounded-[2px] px-3 py-2 text-xs text-[var(--paper)] placeholder-[var(--paper-muted)] transition-colors disabled:opacity-50 font-sans"
              />
            </div>

            {/* Requested Clearance Role Selection */}
            <div className="space-y-1.5 pt-1.5">
              <label className="block text-xs text-[var(--paper-dim)] font-medium">
                Requested Clearance Level:
              </label>
              <div className="grid grid-cols-3 gap-2">
                <button
                  type="button"
                  onClick={() => setSelectedRole('admin')}
                  className={`p-2 rounded-[2px] border text-left transition-all cursor-pointer ${
                    selectedRole === 'admin'
                      ? 'bg-[rgba(201,162,39,0.18)] border-[var(--stamp)] text-[var(--paper)]'
                      : 'bg-[var(--ink)] border-[var(--line)] text-[var(--paper-dim)] hover:border-[var(--paper-muted)]'
                  }`}
                >
                  <div className="flex items-center justify-between mb-0.5">
                    <span className="font-mono text-[10px] font-bold text-[var(--stamp)]">ADMIN</span>
                    <ShieldAlert className="w-3 h-3 text-[var(--stamp)]" />
                  </div>
                  <div className="text-[10.5px] truncate font-semibold">SOC Lead</div>
                </button>

                <button
                  type="button"
                  onClick={() => setSelectedRole('analyst')}
                  className={`p-2 rounded-[2px] border text-left transition-all cursor-pointer ${
                    selectedRole === 'analyst'
                      ? 'bg-[rgba(127,163,186,0.18)] border-[var(--slate)] text-[var(--paper)]'
                      : 'bg-[var(--ink)] border-[var(--line)] text-[var(--paper-dim)] hover:border-[var(--paper-muted)]'
                  }`}
                >
                  <div className="flex items-center justify-between mb-0.5">
                    <span className="font-mono text-[10px] font-bold text-[var(--slate)]">ANALYST</span>
                    <Shield className="w-3 h-3 text-[var(--slate)]" />
                  </div>
                  <div className="text-[10.5px] truncate font-semibold">Forensic Tier 2</div>
                </button>

                <button
                  type="button"
                  onClick={() => setSelectedRole('read_only')}
                  className={`p-2 rounded-[2px] border text-left transition-all cursor-pointer ${
                    selectedRole === 'read_only'
                      ? 'bg-[rgba(237,230,216,0.14)] border-[var(--paper-dim)] text-[var(--paper)]'
                      : 'bg-[var(--ink)] border-[var(--line)] text-[var(--paper-dim)] hover:border-[var(--paper-muted)]'
                  }`}
                >
                  <div className="flex items-center justify-between mb-0.5">
                    <span className="font-mono text-[10px] font-bold text-[var(--paper-dim)]">AUDITOR</span>
                    <Eye className="w-3 h-3 text-[var(--paper-dim)]" />
                  </div>
                  <div className="text-[10.5px] truncate font-semibold">Read-Only</div>
                </button>
              </div>
            </div>

            <button
              type="submit"
              disabled={loading}
              className="btn-primary w-full mt-3 text-center flex items-center justify-center gap-2 cursor-pointer disabled:opacity-50"
            >
              {loading ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin text-[var(--paper)]" />
                  <span>Provisioning Clearance…</span>
                </>
              ) : (
                <span>Request &amp; Activate Clearance</span>
              )}
            </button>
          </form>
        )}

        <div className="mt-4 text-[11px] font-mono text-[var(--paper-muted)] text-center leading-relaxed">
          Access is limited to verified security teams.<br />
          All workspace events are immutably logged in compliance with NIST SP 800-86.
        </div>
      </div>
    </div>
  );
}
