import React from 'react';
import { ShieldLockIcon } from './icons';

export default function Header() {
  return (
    <header className="w-full border-b border-slate-800/80 bg-[#070d18]/90 backdrop-blur-md sticky top-0 z-50">
      <div className="max-w-[1280px] mx-auto px-4 sm:px-6 h-20 flex items-center justify-between gap-4">
        {/* Left: Logo & Title */}
        <div className="flex items-center gap-3.5">
          <div className="w-11 h-11 rounded-xl bg-surface-container flex items-center justify-center text-primary-container border border-cyan-500/20 shadow-[0_0_16px_rgba(0,229,255,0.15)] shrink-0">
            <ShieldLockIcon className="w-6 h-6" />
          </div>
          <div className="flex flex-col">
            <span className="text-base sm:text-lg font-extrabold uppercase tracking-wider text-primary">
              LINK SENTINEL
            </span>
            <span className="text-xs sm:text-sm text-on-surface-variant font-normal">
              Explainable link &amp; QR risk screener
            </span>
          </div>
        </div>

        {/* Right: Privacy Pill Badge */}
        <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-emerald-950/40 border border-emerald-500/30 text-emerald-300 text-xs sm:text-sm font-medium shrink-0">
          <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" aria-hidden="true"></span>
          <span className="hidden sm:inline">Zero network requests during analysis</span>
          <span className="inline sm:hidden">Zero network</span>
        </div>
      </div>
    </header>
  );
}
