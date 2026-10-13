import React, { useState } from 'react';

/**
 * Renders structured breakdown of UPI payment intent barcodes (upi://pay?...)
 * Explains untrusted claimed display names and pre-filled transaction amount risks.
 *
 * @param {object} props
 * @param {object} props.data - Extracted payment parameters { pa, pn, am, tn, cu }
 * @param {string[]} props.anomalies - Fired anomaly tags
 */
export default function UpiPayloadCard({ data = {}, anomalies = [] }) {
  const { pa = '', pn = '', am = '', tn = '', cu = 'INR' } = data;
  const [copied, setCopied] = useState(false);

  const handleCopyVpa = async () => {
    if (!pa) return;
    try {
      await navigator.clipboard.writeText(pa);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // Fallback if clipboard API is restricted
    }
  };

  const currencyDisplay = cu || 'INR';
  const hasPrefilledAmount = Boolean(am);

  return (
    <div
      className="bg-[#0c1729] border border-amber-500/30 shadow-2xl rounded-2xl p-5 sm:p-6 flex flex-col gap-5 backdrop-blur-xl"
      data-testid="upi-payload-card"
    >
      {/* Header */}
      <div className="flex items-center justify-between border-b border-slate-800 pb-3">
        <div className="flex items-center gap-2">
          <svg
            className="w-4 h-4 text-amber-400 shrink-0"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
            aria-hidden="true"
          >
            <rect x="2" y="5" width="20" height="14" rx="2" />
            <line x1="2" y1="10" x2="22" y2="10" />
          </svg>
          <span className="text-xs uppercase font-mono tracking-wider font-bold text-amber-300">
            UPI Payment Intent Breakdown
          </span>
        </div>
        <span className="text-xs font-mono text-slate-400">Mobile Intent</span>
      </div>

      {/* Prominent Prefilled Amount Callout (if present) */}
      {hasPrefilledAmount ? (
        <div className="p-4 rounded-xl bg-amber-950/60 border border-amber-500/50 flex flex-col sm:flex-row sm:items-center justify-between gap-3 shadow-inner">
          <div className="flex flex-col gap-1">
            <span className="text-[11px] font-mono uppercase tracking-wider text-amber-300 font-bold flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full bg-amber-400 animate-pulse" aria-hidden="true" />
              Prefilled Amount Locked
            </span>
            <div className="flex items-baseline gap-2">
              <span className="text-3xl sm:text-4xl font-black font-mono text-amber-200 tracking-tight">
                {currencyDisplay === 'INR' ? '₹' : `${currencyDisplay} `}
                {am}
              </span>
              <span className="text-xs font-mono text-amber-400/80 uppercase font-semibold">
                {currencyDisplay}
              </span>
            </div>
          </div>
          <span className="text-xs font-sans text-amber-200/90 max-w-xs leading-relaxed">
            Attackers frequently pre-fill specific debit amounts on counterfeit campus canteen posters.
          </span>
        </div>
      ) : (
        <div className="p-3.5 rounded-xl bg-slate-900/80 border border-slate-800 flex items-center justify-between gap-2">
          <span className="text-xs text-slate-400 font-sans">Transaction Amount:</span>
          <span className="text-xs font-mono font-semibold text-emerald-400">
            Dynamic (Payer enters amount in banking app)
          </span>
        </div>
      )}

      {/* Parameter Grid */}
      <div className="flex flex-col gap-3 font-sans">
        {/* Row 1: Payee VPA (pa) */}
        <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 flex flex-col gap-2">
          <div className="flex items-center justify-between gap-2">
            <span className="text-xs text-slate-400 font-medium">
              Payee Virtual Address (VPA):
            </span>
            <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase bg-cyan-950 border border-cyan-500/40 text-cyan-300 shrink-0">
              Account Identifier
            </span>
          </div>
          <div className="flex items-center justify-between gap-2 bg-slate-900/90 px-3 py-2 rounded-lg border border-slate-700/60 min-w-0">
            <span className="font-mono text-sm sm:text-base text-cyan-200 font-bold select-all break-all min-w-0">
              {pa || '<No payee address specified>'}
            </span>
            {pa && (
              <button
                type="button"
                onClick={handleCopyVpa}
                className="px-2.5 py-1 text-xs font-mono rounded bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white shrink-0 cursor-pointer transition-colors border border-slate-600/50 min-h-[32px]"
                aria-label="Copy Payee VPA to clipboard"
              >
                {copied ? 'Copied!' : 'Copy'}
              </button>
            )}
          </div>
        </div>

        {/* Row 2: Claimed Name (pn) */}
        <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 flex flex-col gap-1.5">
          <div className="flex items-center justify-between gap-2">
            <span className="text-xs text-slate-400 font-medium">
              Claimed Display Name (pn):
            </span>
            <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase bg-amber-950 border border-amber-500/50 text-amber-300 shrink-0">
              Untrusted Name
            </span>
          </div>
          <div className="bg-slate-900/90 px-3 py-2 rounded-lg border border-slate-700/60">
            <span className="font-sans text-sm sm:text-base font-semibold text-slate-100 select-all break-all">
              {pn || '<None specified>'}
            </span>
          </div>
          <span className="text-[11px] text-amber-300/80 leading-relaxed font-sans pt-0.5">
            ⚠️ Arbitrary text entered by the QR creator. The bank will only verify the payee VPA during payment authorization.
          </span>
        </div>

        {/* Row 3: Note (tn) - if present */}
        {tn && (
          <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 flex flex-col gap-1">
            <span className="text-xs text-slate-400 font-medium">
              Transaction Note (tn):
            </span>
            <div className="bg-slate-900/90 px-3 py-2 rounded-lg border border-slate-700/60">
              <span className="font-sans text-sm text-slate-200 select-all break-words">
                {tn}
              </span>
            </div>
          </div>
        )}
      </div>

      {/* Safety Notice Footer */}
      <div className="p-3 rounded-xl bg-slate-950/60 border border-slate-800/80 flex items-start gap-2.5 text-xs text-slate-400">
        <svg
          className="w-4 h-4 text-amber-400 shrink-0 mt-0.5"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth="2"
          strokeLinecap="round"
          strokeLinejoin="round"
          aria-hidden="true"
        >
          <circle cx="12" cy="12" r="10" />
          <line x1="12" y1="8" x2="12" y2="12" />
          <line x1="12" y1="16" x2="12.01" y2="16" />
        </svg>
        <span className="leading-relaxed">
          Before entering your MPIN, confirm that the recipient name displayed in your banking application matches the actual intended beneficiary.
        </span>
      </div>
    </div>
  );
}
