import React, { useState } from 'react';
import { CheckShieldIcon, AlertTriangleIcon, ShieldAlertIcon, CopyIcon, CheckIcon } from './icons';

export default function VerdictBanner({ verdict, tag, primaryReason, summary, subtitle, target }) {
  const [copied, setCopied] = useState(false);

  const reason = typeof primaryReason === 'string'
    ? {
        label: verdict === 'safe'
          ? 'Classification basis:'
          : verdict === 'review'
          ? 'Why review is required:'
          : "Why it's flagged as Suspicious:",
        text: primaryReason
      }
    : (primaryReason || (summary ? { label: 'Primary Reason:', text: summary } : null));

  const handleCopyAudit = async () => {
    const verdictUpper = (verdict || 'UNKNOWN').toUpperCase();
    const reasonText = reason?.text || summary || 'No deception signals detected.';
    const tagText = tag || (verdict === 'safe' ? 'NO RED FLAGS' : verdictUpper);
    const targetText = target || 'Inspected Target';

    const report = [
      `[LINK SENTINEL VERDICT: ${verdictUpper}]`,
      `Target: ${targetText}`,
      `Classification: ${tagText}`,
      `Reason: ${reasonText}`,
      `Telemetry: 0 network requests (Offline deterministic inspection)`
    ].join('\n');

    try {
      if (typeof navigator !== 'undefined' && navigator.clipboard && navigator.clipboard.writeText) {
        await navigator.clipboard.writeText(report);
      } else {
        const textarea = document.createElement('textarea');
        textarea.value = report;
        textarea.style.position = 'fixed';
        textarea.style.opacity = '0';
        document.body.appendChild(textarea);
        textarea.select();
        document.execCommand('copy');
        document.body.removeChild(textarea);
      }
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch (err) {
      console.warn('Failed to copy audit report:', err);
    }
  };

  const renderCopyButton = () => (
    <button
      type="button"
      onClick={handleCopyAudit}
      className="px-2.5 py-1 rounded-lg bg-slate-900/60 hover:bg-slate-800/80 border border-slate-700/60 hover:border-cyan-500/40 text-xs font-mono text-slate-300 hover:text-cyan-300 transition-all flex items-center gap-1.5 cursor-pointer focus:outline-none focus:ring-1 focus:ring-cyan-500/40 shrink-0"
      aria-label="Copy audit summary to clipboard"
      title="Copy audit summary report"
    >
      {copied ? (
        <>
          <CheckIcon className="w-3.5 h-3.5 text-emerald-400" />
          <span className="text-emerald-300 font-bold">Copied</span>
        </>
      ) : (
        <>
          <CopyIcon className="w-3.5 h-3.5 text-slate-400" />
          <span className="hidden sm:inline">Copy Audit Summary</span>
          <span className="sm:hidden">Copy</span>
        </>
      )}
    </button>
  );

  if (verdict === 'safe') {
    return (
      <div className="rounded-2xl p-5 bg-[#06241a] border-2 border-emerald-500 shadow-[0_0_32px_rgba(16,185,129,0.25)] flex flex-col gap-4 transition-all duration-200 ease-out">
        <div className="flex items-center justify-between gap-3 flex-wrap sm:flex-nowrap">
          <div className="flex items-center gap-4 min-w-0">
            <div className="w-12 h-12 rounded-xl bg-emerald-950/80 border border-emerald-500/50 flex items-center justify-center text-emerald-400 shadow-[0_0_16px_rgba(16,185,129,0.3)] shrink-0">
              <CheckShieldIcon className="w-7 h-7" />
            </div>
            <div className="flex flex-col min-w-0">
              <span className="text-xs font-mono uppercase text-emerald-400 font-bold tracking-wider">
                Analysis Cleared
              </span>
              <h2 className="text-2xl sm:text-3xl font-extrabold text-emerald-400 tracking-tight">
                SAFE
              </h2>
            </div>
          </div>
          <div className="flex items-center gap-2 self-start sm:self-auto shrink-0">
            {renderCopyButton()}
            <span className="px-3 py-1 rounded bg-emerald-950 border border-emerald-500/40 text-emerald-300 text-xs font-mono font-bold">
              {tag || 'NO RED FLAGS'}
            </span>
          </div>
        </div>

        {/* Dedicated Classification Basis Callout */}
        <div className="rounded-xl p-3.5 sm:p-4 bg-emerald-950/60 border border-emerald-500/40 text-emerald-100 flex flex-col gap-1.5 shadow-sm">
          <span className="text-xs font-bold uppercase tracking-wider text-emerald-300 font-sans">
            {reason?.label || 'Classification basis:'}
          </span>
          <p className="text-xs sm:text-sm text-slate-200 leading-relaxed break-words font-sans">
            {reason?.text || 'No deception signals detected — Standard authority formatting and valid HTTPS protocol with no homoglyphs, credentials, or redirection patterns found.'}
          </p>
        </div>

        <p className="text-xs sm:text-sm text-slate-300 border-t border-emerald-900/60 pt-2.5 font-sans">
          No deception signals found. This is not a guarantee.
        </p>
      </div>
    );
  }

  if (verdict === 'review') {
    return (
      <div className="rounded-2xl p-5 bg-[#2b1f06] border-2 border-amber-500 shadow-[0_0_32px_rgba(245,158,11,0.25)] flex flex-col gap-4 transition-all duration-200 ease-out">
        <div className="flex items-center justify-between gap-3 flex-wrap sm:flex-nowrap">
          <div className="flex items-center gap-4 min-w-0">
            <div className="w-12 h-12 rounded-xl bg-amber-950/80 border border-amber-500/50 flex items-center justify-center text-amber-400 shadow-[0_0_16px_rgba(245,158,11,0.3)] shrink-0">
              <AlertTriangleIcon className="w-7 h-7" />
            </div>
            <div className="flex flex-col min-w-0">
              <span className="text-xs font-mono uppercase text-amber-400 font-bold tracking-wider">
                Caution Required
              </span>
              <h2 className="text-2xl sm:text-3xl font-extrabold text-amber-400 tracking-tight">
                REVIEW NEEDED
              </h2>
            </div>
          </div>
          <div className="flex items-center gap-2 self-start sm:self-auto shrink-0">
            {renderCopyButton()}
            <span className="px-3 py-1 rounded bg-amber-950 border border-amber-500/40 text-amber-300 text-xs font-mono font-bold">
              {tag || 'REVIEW'}
            </span>
          </div>
        </div>

        {/* Dedicated Review Requirement Callout */}
        {reason?.text && (
          <div className="rounded-xl p-3.5 sm:p-4 bg-amber-950/60 border border-amber-500/40 text-amber-100 flex flex-col gap-1.5 shadow-sm">
            <span className="text-xs font-bold uppercase tracking-wider text-amber-300 font-sans">
              {reason.label || 'Why review is required:'}
            </span>
            <p className="text-xs sm:text-sm text-slate-200 leading-relaxed break-words font-sans">
              {reason.text}
            </p>
          </div>
        )}
      </div>
    );
  }

  // Suspicious (default fallback)
  return (
    <div className="rounded-2xl p-5 bg-[#26080b] border-2 border-red-500 shadow-[0_0_36px_rgba(239,68,68,0.35)] flex flex-col gap-4 transition-all duration-200 ease-out">
      <div className="flex items-center justify-between gap-3 flex-wrap sm:flex-nowrap">
        <div className="flex items-center gap-4 min-w-0">
          <div className="w-12 h-12 rounded-xl bg-red-950/80 border border-red-500/50 flex items-center justify-center text-red-400 shadow-[0_0_20px_rgba(239,68,68,0.3)] animate-pulse shrink-0">
            <ShieldAlertIcon className="w-7 h-7" />
          </div>
          <div className="flex flex-col min-w-0">
            <span className="text-xs font-mono uppercase text-red-400 font-bold tracking-wider">
              Deception Detected
            </span>
            <h2 className="text-2xl sm:text-3xl font-extrabold text-red-500 tracking-tight">
              SUSPICIOUS
            </h2>
          </div>
        </div>
        <div className="flex items-center gap-2 self-start sm:self-auto shrink-0">
          {renderCopyButton()}
          <span className="px-3 py-1 rounded bg-red-950 border border-red-500/40 text-red-400 text-xs font-mono font-bold uppercase">
            {tag || 'SUSPICIOUS'}
          </span>
        </div>
      </div>

      {/* Dedicated Suspicious Trigger Callout */}
      {reason?.text && (
        <div className="rounded-xl p-3.5 sm:p-4 bg-red-950/60 border border-red-500/40 text-red-100 flex flex-col gap-1.5 shadow-sm">
          <span className="text-xs font-bold uppercase tracking-wider text-red-300 font-sans">
            {reason.label || "Why it's flagged as Suspicious:"}
          </span>
          <p className="text-xs sm:text-sm text-slate-200 leading-relaxed break-words font-sans">
            {reason.text}
          </p>
        </div>
      )}
    </div>
  );
}
