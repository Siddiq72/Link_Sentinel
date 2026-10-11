import React from 'react';
import { AlertTriangleIcon, AlertCircleIcon, QrIcon } from './icons';

export default function ErrorState({ errorType = 'link', message }) {
  const isQr = errorType === 'qr';

  return (
    <div className="flex flex-col gap-5">
      {/* Banner */}
      <div className="rounded-2xl p-5 bg-gradient-to-r from-red-950/80 to-amber-950/70 border-2 border-red-500/80 shadow-[0_0_32px_rgba(239,68,68,0.25)] flex items-center gap-4">
        <div className="w-12 h-12 rounded-xl bg-red-900/50 flex items-center justify-center text-red-400 shadow-[0_0_16px_rgba(239,68,68,0.3)] shrink-0 border border-red-500/40">
          <AlertTriangleIcon className="w-7 h-7" />
        </div>
        <div className="flex flex-col">
          <span className="text-xs uppercase font-mono tracking-wider text-red-400 font-bold">
            Input Error
          </span>
          <h2 className="text-xl sm:text-2xl font-extrabold text-red-300 tracking-tight">
            ANALYSIS INTERRUPTED
          </h2>
        </div>
      </div>

      {/* Error Details Card */}
      <div className="bg-[#0c1729] border border-red-500/30 rounded-2xl p-5 sm:p-6 flex flex-col gap-4 shadow-xl">
        {/* Link error item */}
        {(!isQr || errorType === 'both') && (
          <div className="flex items-start gap-3 p-4 rounded-xl bg-slate-950/70 border border-red-500/30 text-slate-200">
            <AlertCircleIcon className="w-5 h-5 text-red-400 shrink-0 mt-0.5" />
            <div className="flex flex-col gap-1">
              <span className="font-bold text-sm text-red-400">
                {message || 'Please enter a valid link.'}
              </span>
              <span className="text-xs text-slate-400">
                The provided string does not contain an inspectable protocol authority or domain structure.
              </span>
            </div>
          </div>
        )}

        {/* QR error item */}
        {(isQr || errorType === 'both') && (
          <div className="flex items-start gap-3 p-4 rounded-xl bg-slate-950/70 border border-amber-500/30 text-slate-200">
            <QrIcon className="w-5 h-5 text-amber-400 shrink-0 mt-0.5" />
            <div className="flex flex-col gap-1">
              <span className="font-bold text-sm text-amber-400">
                {message || 'No QR code found in this image.'}
              </span>
              <span className="text-xs text-slate-400">
                Zero matrix barcodes detected in buffer. Ensure good contrast and uncropped corner finder patterns.
              </span>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
