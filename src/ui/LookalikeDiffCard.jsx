import React from 'react';

/**
 * Visual diff component that highlights spoofed homoglyphs and lookalike characters
 * against authentic protected domains.
 *
 * @param {object} props
 * @param {object|null} props.diff - Lookalike diff object computed by engine.
 */
export default function LookalikeDiffCard({ diff }) {
  if (!diff || !diff.characters || !Array.isArray(diff.characters)) {
    return null;
  }

  const { genuineDomain, characters, punycode } = diff;

  // Extract unique confusables for the explainer rows
  const confusableList = [];
  const seenCodes = new Set();
  for (const item of characters) {
    if (item.isConfusable && item.metadata) {
      const key = item.metadata.codePoint || item.char;
      if (!seenCodes.has(key)) {
        seenCodes.add(key);
        confusableList.push(item);
      }
    }
  }

  return (
    <div
      className="bg-slate-900/80 border border-red-500/30 rounded-xl p-4 my-4 flex flex-col gap-4 shadow-xl backdrop-blur-md"
      data-testid="lookalike-diff-card"
    >
      {/* Header */}
      <div className="flex items-center gap-2">
        <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-[11px] font-bold font-mono tracking-wider uppercase bg-red-500/10 text-red-400 border border-red-500/30">
          <svg className="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
            <circle cx="12" cy="12" r="10" />
            <line x1="12" y1="8" x2="12" y2="12" />
            <line x1="12" y1="16" x2="12.01" y2="16" />
          </svg>
          LOOK-ALIKE CHARACTER COMPARISON
        </span>
      </div>

      {/* Visual Stacked Diff */}
      <div className="bg-slate-950/90 rounded-lg p-3.5 border border-slate-800 flex flex-col gap-2.5">
        {/* Row 1: Authentic Target */}
        <div className="flex flex-col sm:flex-row sm:items-center gap-1 sm:gap-3 text-xs sm:text-sm">
          <span className="text-slate-400 font-medium shrink-0 sm:w-28">Genuine target:</span>
          <span className="font-mono text-emerald-400 font-semibold break-all select-all">
            {genuineDomain}
          </span>
        </div>

        {/* Row 2: Analyzed Host */}
        <div className="flex flex-col sm:flex-row sm:items-center gap-1 sm:gap-3 text-xs sm:text-sm">
          <span className="text-slate-400 font-medium shrink-0 sm:w-28">Analyzed host:</span>
          <span className="font-mono text-slate-200 break-all select-all flex flex-wrap items-center gap-0.5">
            {characters.map((item, idx) => {
              if (item.isConfusable) {
                return (
                  <span
                    key={idx}
                    className="bg-red-500/20 text-red-300 ring-1 ring-red-500 px-1 py-0.5 rounded font-bold inline-block"
                    title={item.metadata?.name || 'Confusable character'}
                  >
                    {item.char}
                  </span>
                );
              }
              return (
                <span key={idx} className="text-slate-200">
                  {item.char}
                </span>
              );
            })}
          </span>
        </div>
      </div>

      {/* Character Explainer Rows */}
      {confusableList.length > 0 && (
        <div className="flex flex-col gap-2 pt-1 border-t border-slate-800/80">
          <span className="text-[11px] uppercase tracking-wider font-bold text-slate-400">
            Detected Confusable Glyphs:
          </span>
          <div className="flex flex-col gap-1.5">
            {confusableList.map((item, idx) => {
              const meta = item.metadata || {};
              const targetMatch = meta.latinMatch || '?';
              return (
                <div
                  key={idx}
                  className="text-xs sm:text-sm text-slate-200 break-all bg-slate-950/50 rounded p-2 border border-slate-800/60 flex items-start gap-2"
                >
                  <span className="bg-red-500/20 text-red-300 ring-1 ring-red-500 px-1.5 py-0.5 rounded font-mono font-bold shrink-0">
                    {item.char}
                  </span>
                  <span className="leading-relaxed">
                    <span className="font-mono text-slate-400">({meta.codePoint})</span>{' '}
                    <span className="font-semibold text-slate-100">{meta.name}</span>
                    {' '}— visually imitates Latin <span className="font-mono font-bold text-emerald-400">'{targetMatch}'</span>
                  </span>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Punycode Resolution Line */}
      {punycode && (
        <div className="text-xs text-slate-400 break-all pt-2 border-t border-slate-800 flex flex-wrap items-center gap-1">
          <span>Host as the browser resolves it:</span>
          <span className="font-mono text-slate-200 font-semibold select-all">
            {punycode}
          </span>
        </div>
      )}
    </div>
  );
}
