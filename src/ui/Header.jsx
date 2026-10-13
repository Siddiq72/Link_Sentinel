import React from 'react';
import { ShieldLockIcon } from './icons';

export default function Header({ onOpenSelfTest }) {
  return (
    <header className="w-full px-4 sm:px-6 pt-4 pb-3 flex flex-wrap items-center justify-between gap-3 border-b border-slate-800/80 bg-[#070d18]/90 backdrop-blur-md sticky top-0 z-50">
      {/* Left: Logo and Title Lockup */}
      <div className="flex items-center gap-2.5 sm:gap-3 min-w-0">
        <div className="w-9 h-9 sm:w-10 sm:h-10 rounded-xl bg-surface-container flex items-center justify-center text-primary-container border border-cyan-500/20 shadow-[0_0_16px_rgba(0,229,255,0.15)] shrink-0">
          <ShieldLockIcon className="w-5 h-5 sm:w-6 sm:h-6" />
        </div>
        <div className="flex flex-col min-w-0">
          <h1 className="text-base sm:text-lg font-bold tracking-wider text-slate-100 leading-tight">
            LINK SENTINEL
          </h1>
          <p className="text-[10px] sm:text-xs text-slate-400 leading-tight sm:leading-snug truncate">
            Explainable link &amp; QR risk screener
          </p>
        </div>
      </div>

      {/* Right: Actions / Badges Grouping */}
      <div className="flex items-center gap-2 shrink-0">
        {/* Self-Test Evidence Trigger Button */}
        <button
          type="button"
          onClick={onOpenSelfTest}
          className="text-[11px] sm:text-xs px-2.5 py-1 sm:px-3 sm:py-1.5 rounded-lg border border-emerald-500/30 text-emerald-400 hover:bg-emerald-500/10 whitespace-nowrap font-mono font-bold transition-all flex items-center gap-1.5 shadow-[0_0_12px_rgba(16,185,129,0.15)] cursor-pointer active:scale-95 shrink-0 focus:outline-none focus:ring-2 focus:ring-emerald-500/40"
          aria-label="Open Self-Test Evidence and Regression Dashboard"
        >
          <span aria-hidden="true">⚡</span>
          <span>Self-Test Evidence</span>
        </button>

        {/* Privacy Pill Badge */}
        <div className="flex items-center gap-1.5 sm:gap-2 px-2 sm:px-3 py-1 sm:py-1.5 rounded-full bg-emerald-950/40 border border-emerald-500/30 text-emerald-300 text-[10px] sm:text-xs font-medium shrink-0">
          <span className="w-1.5 h-1.5 sm:w-2 sm:h-2 rounded-full bg-emerald-400 animate-pulse" aria-hidden="true" />
          <span className="hidden md:inline">Zero network requests during analysis</span>
          <span className="hidden sm:inline md:hidden">Zero network</span>
          <span className="inline sm:hidden">Offline</span>
        </div>
      </div>
    </header>
  );
}

