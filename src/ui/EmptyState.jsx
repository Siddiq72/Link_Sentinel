import React from 'react';
import { EmptyShieldIcon } from './icons';

export default function EmptyState() {
  return (
    <div className="bg-[#0c1729] border border-cyan-500/20 shadow-2xl rounded-2xl p-6 sm:p-10 text-center flex flex-col items-center justify-center gap-5 min-h-[440px] backdrop-blur-xl">
      {/* Tactical radar/shield graphic with pulse ring */}
      <div className="relative flex items-center justify-center my-1">
        <div className="absolute w-24 h-24 rounded-full ring-1 ring-cyan-500/20 bg-cyan-950/20 animate-pulse pointer-events-none" />
        <div className="absolute w-32 h-32 rounded-full border border-cyan-500/10 pointer-events-none" />
        <div className="w-16 h-16 rounded-2xl bg-slate-900/90 flex items-center justify-center text-cyan-400 shadow-[0_0_30px_rgba(6,182,212,0.25)] border border-cyan-500/40 relative z-10 transition-transform duration-300 hover:scale-105">
          <EmptyShieldIcon className="w-9 h-9" />
        </div>
      </div>

      {/* Header and status badge */}
      <div className="flex flex-col items-center gap-2 max-w-md">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-cyan-950/40 border border-cyan-500/30 text-[11px] font-mono font-semibold tracking-wider text-cyan-300 shadow-sm">
          <span className="w-2 h-2 rounded-full bg-emerald-400 animate-ping shrink-0" aria-hidden="true" />
          <span>HEURISTIC ENGINE ARMED // 0 NETWORK TELEMETRY</span>
        </div>
        <h2 className="text-xl sm:text-2xl font-bold text-on-surface tracking-tight mt-1">
          Awaiting Target Stream
        </h2>
        <p className="text-sm text-slate-400 leading-relaxed max-w-sm">
          Input a link or drop a QR code to initiate offline heuristic inspection.
        </p>
      </div>

      {/* Glassmorphic Verdict Legend Bars */}
      <div className="w-full max-w-md mt-2 flex flex-col gap-2.5 text-left">
        {/* Safe Status Tile */}
        <div className="flex items-start gap-3 p-3 rounded-xl bg-emerald-950/25 border border-emerald-500/20 text-emerald-200 text-xs sm:text-sm backdrop-blur-sm transition-all hover:border-emerald-500/40 hover:bg-emerald-950/35">
          <span className="w-2.5 h-2.5 rounded-full bg-emerald-400 shadow-[0_0_8px_rgba(52,211,153,0.6)] mt-1 shrink-0" aria-hidden="true" />
          <div className="flex flex-col min-w-0">
            <div className="flex items-center justify-between gap-2">
              <span className="font-bold text-emerald-300 font-sans tracking-wide">Safe</span>
              <span className="text-[10px] font-mono font-semibold uppercase text-emerald-400/80 px-1.5 py-0.5 rounded bg-emerald-950/60 border border-emerald-500/30">Cleared</span>
            </div>
            <span className="text-xs text-slate-400 mt-0.5 leading-relaxed">
              Canonical domain syntax, valid HTTPS protocol, zero homoglyphs or decoy routing detected.
            </span>
          </div>
        </div>

        {/* Review Needed Status Tile */}
        <div className="flex items-start gap-3 p-3 rounded-xl bg-amber-950/25 border border-amber-500/20 text-amber-200 text-xs sm:text-sm backdrop-blur-sm transition-all hover:border-amber-500/40 hover:bg-amber-950/35">
          <span className="w-2.5 h-2.5 rounded-full bg-amber-400 shadow-[0_0_8px_rgba(251,191,36,0.6)] mt-1 shrink-0" aria-hidden="true" />
          <div className="flex flex-col min-w-0">
            <div className="flex items-center justify-between gap-2">
              <span className="font-bold text-amber-300 font-sans tracking-wide">Review needed</span>
              <span className="text-[10px] font-mono font-semibold uppercase text-amber-400/80 px-1.5 py-0.5 rounded bg-amber-950/60 border border-amber-500/30">Inspection</span>
            </div>
            <span className="text-xs text-slate-400 mt-0.5 leading-relaxed">
              Shortened links concealing destination, private RFC 1918 subnets, or non-Latin scripts requiring caution.
            </span>
          </div>
        </div>

        {/* Suspicious Status Tile */}
        <div className="flex items-start gap-3 p-3 rounded-xl bg-red-950/25 border border-red-500/20 text-red-200 text-xs sm:text-sm backdrop-blur-sm transition-all hover:border-red-500/40 hover:bg-red-950/35">
          <span className="w-2.5 h-2.5 rounded-full bg-red-400 shadow-[0_0_8px_rgba(248,113,113,0.6)] mt-1 shrink-0 animate-pulse" aria-hidden="true" />
          <div className="flex flex-col min-w-0">
            <div className="flex items-center justify-between gap-2">
              <span className="font-bold text-red-300 font-sans tracking-wide">Suspicious</span>
              <span className="text-[10px] font-mono font-semibold uppercase text-red-400/80 px-1.5 py-0.5 rounded bg-red-950/60 border border-red-500/30">Threat</span>
            </div>
            <span className="text-xs text-slate-400 mt-0.5 leading-relaxed">
              Credential theft traps (@ injection), visual homoglyph spoofing, combosquatting brand lures, or direct IP hosts.
            </span>
          </div>
        </div>
      </div>
    </div>
  );
}
