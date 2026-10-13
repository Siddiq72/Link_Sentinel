import React, { useState } from 'react';

/**
 * Renders cleanly formatted plain text payloads extracted from non-URL QR codes.
 *
 * @param {object} props
 * @param {object} props.data - Extracted text data { text }
 */
export default function TextPayloadCard({ data = {} }) {
  const { text = '' } = data;
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    if (!text) return;
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // Fallback
    }
  };

  const wordCount = text.trim() ? text.trim().split(/\s+/).length : 0;
  const charCount = text.length;

  return (
    <div
      className="bg-[#0c1729] border border-emerald-500/20 shadow-2xl rounded-2xl p-5 sm:p-6 flex flex-col gap-4 backdrop-blur-xl"
      data-testid="text-payload-card"
    >
      {/* Header */}
      <div className="flex items-center justify-between border-b border-slate-800 pb-3">
        <div className="flex items-center gap-2">
          <svg
            className="w-4 h-4 text-emerald-400 shrink-0"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
            aria-hidden="true"
          >
            <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
            <polyline points="14 2 14 8 20 8" />
            <line x1="16" y1="13" x2="8" y2="13" />
            <line x1="16" y1="17" x2="8" y2="17" />
            <polyline points="10 9 9 9 8 9" />
          </svg>
          <span className="text-xs uppercase font-mono tracking-wider font-bold text-emerald-300">
            Plain Text QR Payload
          </span>
        </div>
        <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase bg-emerald-950 border border-emerald-500/40 text-emerald-300">
          Non-Executable
        </span>
      </div>

      {/* Text Container */}
      <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 flex flex-col gap-3">
        <div className="bg-slate-900/90 p-4 rounded-lg border border-slate-700/60 max-h-72 overflow-y-auto">
          <p className="font-sans text-sm sm:text-base text-slate-100 leading-relaxed whitespace-pre-wrap select-all break-words">
            {text || '<Empty text string>'}
          </p>
        </div>

        {/* Footer with Metrics & Copy button */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pt-1">
          <div className="flex items-center gap-3 text-xs font-mono text-slate-400">
            <span>{charCount} characters</span>
            <span aria-hidden="true">•</span>
            <span>{wordCount} words</span>
          </div>

          <button
            type="button"
            onClick={handleCopy}
            className="min-h-[44px] px-3.5 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-mono font-semibold border border-slate-600/50 cursor-pointer transition-colors focus:outline-none focus:ring-2 focus:ring-emerald-500/40 flex items-center justify-center gap-1.5 self-start sm:self-auto"
            aria-label="Copy text content to clipboard"
          >
            <svg
              className="w-3.5 h-3.5 text-slate-400"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
              strokeLinecap="round"
              strokeLinejoin="round"
              aria-hidden="true"
            >
              <rect x="9" y="9" width="13" height="13" rx="2" ry="2" />
              <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" />
            </svg>
            {copied ? 'Copied to Clipboard!' : 'Copy Text'}
          </button>
        </div>
      </div>
    </div>
  );
}
