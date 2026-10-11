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
          Paste a URL in the inspector or click an example above to inspect its anatomy and routing traps.
        </p>
      </div>
    </div>
  );
}
