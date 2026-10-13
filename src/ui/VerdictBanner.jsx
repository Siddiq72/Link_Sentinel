import React from 'react';
import { CheckShieldIcon, AlertTriangleIcon, ShieldAlertIcon } from './icons';

export default function VerdictBanner({ verdict, tag, summary, subtitle }) {
  const displaySummary = summary || subtitle;

  if (verdict === 'safe') {
    return (
      <div className="rounded-2xl p-5 bg-[#06241a] border-2 border-emerald-500 shadow-[0_0_32px_rgba(16,185,129,0.25)] flex flex-col gap-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-4">
            <div className="w-12 h-12 rounded-xl bg-emerald-950/80 border border-emerald-500/50 flex items-center justify-center text-emerald-400 shadow-[0_0_16px_rgba(16,185,129,0.3)] shrink-0">
              <CheckShieldIcon className="w-7 h-7" />
            </div>
            <div className="flex flex-col">
              <span className="text-xs font-mono uppercase text-emerald-400 font-bold tracking-wider">
                Analysis Cleared
              </span>
              <h2 className="text-2xl sm:text-3xl font-extrabold text-emerald-400 tracking-tight">
                SAFE
              </h2>
            </div>
          </div>
          <span className="px-3 py-1 rounded bg-emerald-950 border border-emerald-500/40 text-emerald-300 text-xs font-mono font-bold">
            {tag || 'NO RED FLAGS'}
          </span>
        </div>
        <p className="text-xs sm:text-sm text-slate-300 border-t border-emerald-900/60 pt-2.5">
          {displaySummary || 'No deception signals found. This is not a guarantee.'}
        </p>
      </div>
    );
  }

  if (verdict === 'review') {
    return (
      <div className="rounded-2xl p-5 bg-[#2b1f06] border-2 border-amber-500 shadow-[0_0_32px_rgba(245,158,11,0.25)] flex flex-col gap-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-4">
            <div className="w-12 h-12 rounded-xl bg-amber-950/80 border border-amber-500/50 flex items-center justify-center text-amber-400 shadow-[0_0_16px_rgba(245,158,11,0.3)] shrink-0">
              <AlertTriangleIcon className="w-7 h-7" />
            </div>
            <div className="flex flex-col">
              <span className="text-xs font-mono uppercase text-amber-400 font-bold tracking-wider">
                Caution Required
              </span>
              <h2 className="text-2xl sm:text-3xl font-extrabold text-amber-400 tracking-tight">
                REVIEW NEEDED
              </h2>
            </div>
          </div>
          <span className="px-3 py-1 rounded bg-amber-950 border border-amber-500/40 text-amber-300 text-xs font-mono font-bold">
            {tag || 'REVIEW'}
          </span>
        </div>
        {displaySummary && (
          <p className="text-xs sm:text-sm text-slate-300 border-t border-amber-900/60 pt-2.5">
            {displaySummary}
          </p>
        )}
      </div>
    );
  }

  // Suspicious (default fallback)
  return (
    <div className="rounded-2xl p-5 bg-[#26080b] border-2 border-red-500 shadow-[0_0_36px_rgba(239,68,68,0.35)] flex flex-col gap-3">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <div className="w-12 h-12 rounded-xl bg-red-950/80 border border-red-500/50 flex items-center justify-center text-red-400 shadow-[0_0_20px_rgba(239,68,68,0.3)] animate-pulse shrink-0">
            <ShieldAlertIcon className="w-7 h-7" />
          </div>
          <div className="flex flex-col">
            <span className="text-xs font-mono uppercase text-red-400 font-bold tracking-wider">
              Deception Detected
            </span>
            <h2 className="text-2xl sm:text-3xl font-extrabold text-red-500 tracking-tight">
              SUSPICIOUS
            </h2>
          </div>
        </div>
        <span className="px-3 py-1 rounded bg-red-950 border border-red-500/40 text-red-400 text-xs font-mono font-bold uppercase">
          {tag || 'SUSPICIOUS'}
        </span>
      </div>
      {displaySummary && (
        <p className="text-xs sm:text-sm text-slate-300 border-t border-red-900/60 pt-2.5">
          {displaySummary}
        </p>
      )}
    </div>
  );
}
