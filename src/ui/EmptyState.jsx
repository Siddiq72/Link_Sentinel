import React from 'react';
import { EmptyShieldIcon } from './icons';

export default function EmptyState() {
  return (
    <div className="bg-[#0c1729] border border-cyan-500/20 shadow-2xl rounded-2xl p-8 sm:p-12 text-center flex flex-col items-center justify-center gap-5 min-h-[440px]">
      <div className="w-16 h-16 rounded-2xl bg-surface-container flex items-center justify-center text-primary-container shadow-[0_0_24px_rgba(0,229,255,0.2)] border border-cyan-500/30">
        <EmptyShieldIcon className="w-9 h-9" />
      </div>
      <div className="flex flex-col gap-2 max-w-md">
        <h2 className="text-xl sm:text-2xl font-bold text-on-surface">
          Awaiting Link or QR Input
        </h2>
        <p className="text-sm text-slate-400 leading-relaxed">
          Paste a link, upload a QR image, or try an example.
        </p>
      </div>

      {/* Three-row Severity Legend */}
      <div className="w-full max-w-md mt-2 flex flex-col gap-2 text-left">
        <div className="flex items-center gap-2.5 px-3 py-2 rounded-lg bg-emerald-950/40 border border-emerald-500/30 text-emerald-300 text-xs sm:text-sm">
          <span className="w-2.5 h-2.5 rounded-full bg-emerald-400 shrink-0" aria-hidden="true" />
          <span>Safe: no deception signals found (not a guarantee)</span>
        </div>
        <div className="flex items-center gap-2.5 px-3 py-2 rounded-lg bg-amber-950/40 border border-amber-500/30 text-amber-300 text-xs sm:text-sm">
          <span className="w-2.5 h-2.5 rounded-full bg-amber-400 shrink-0" aria-hidden="true" />
          <span>Review needed: can't be verified offline</span>
        </div>
        <div className="flex items-center gap-2.5 px-3 py-2 rounded-lg bg-red-950/40 border border-red-500/30 text-red-300 text-xs sm:text-sm">
          <span className="w-2.5 h-2.5 rounded-full bg-red-400 shrink-0" aria-hidden="true" />
          <span>Suspicious: clear structural deception</span>
        </div>
      </div>
    </div>
  );
}
