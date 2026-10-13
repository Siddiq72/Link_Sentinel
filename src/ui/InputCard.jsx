import React, { useRef, useState } from 'react';
import { LinkIcon, ClearIcon, SearchIcon, QrIcon, LockIcon, InfoIcon, SpinnerIcon } from './icons';
import ExampleChips from './ExampleChips';

const ACCEPTED_IMAGE_TYPES = ['.png', '.jpg', '.jpeg', '.webp'];

export default function InputCard({
  value,
  onChange,
  onAnalyze,
  onClear,
  onQrUpload,
  onSelectSample,
  isQrLoading = false
}) {
  const fileInputRef = useRef(null);
  const [isDragging, setIsDragging] = useState(false);

  const handleKeyDown = (e) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      onAnalyze();
    }
  };

  const isAcceptedImage = (file) => {
    if (!file) return false;
    const nameLower = file.name.toLowerCase();
    const hasValidExt = ACCEPTED_IMAGE_TYPES.some((ext) => nameLower.endsWith(ext));
    const hasValidMime = file.type === 'image/png' || file.type === 'image/jpeg' || file.type === 'image/webp';
    return hasValidExt || hasValidMime;
  };

  const handleFileChange = (e) => {
    if (isQrLoading) return;
    const file = e.target.files?.[0];
    if (file) {
      onQrUpload(file);
    }
    // Reset file input so the same file can be selected again
    e.target.value = '';
  };

  const handleDragOver = (e) => {
    e.preventDefault();
    if (!isQrLoading) {
      setIsDragging(true);
    }
  };

  const handleDragLeave = (e) => {
    e.preventDefault();
    setIsDragging(false);
  };

  const handleDrop = (e) => {
    e.preventDefault();
    setIsDragging(false);
    if (isQrLoading) return;
    const file = e.dataTransfer.files?.[0];
    if (file && isAcceptedImage(file)) {
      onQrUpload(file);
    }
  };

  return (
    <div className="bg-[#0c1729] border border-cyan-500/20 shadow-2xl rounded-2xl p-5 sm:p-6 flex flex-col gap-5 backdrop-blur-xl">
      {/* Header with Title and Clear Button */}
      <div className="flex items-center justify-between">
        <label
          htmlFor="url-input"
          className="text-sm font-bold text-on-surface uppercase tracking-wider flex items-center gap-2 cursor-pointer"
        >
          <LinkIcon className="w-4 h-4 text-primary-container" />
          Link Inspector Input
        </label>
        <button
          type="button"
          onClick={onClear}
          className="text-xs font-mono text-slate-300 hover:text-primary transition-colors flex items-center gap-1 min-h-[44px] px-2.5 rounded-lg border border-slate-700/50 hover:border-cyan-500/40 bg-slate-900/50 cursor-pointer focus:outline-none focus:ring-2 focus:ring-primary-container/30"
          aria-label="Clear input field"
        >
          <ClearIcon className="w-3.5 h-3.5" />
          Clear
        </button>
      </div>

      {/* URL Input Bar + Cyan Analyze Button */}
      <div className="flex flex-col sm:flex-row gap-2.5">
        <div className="relative flex-1">
          <input
            id="url-input"
            type="text"
            value={value}
            onChange={(e) => onChange(e.target.value)}
            onPaste={(e) => {
              e.preventDefault();
              const pasted = e.clipboardData?.getData('text') || '';
              onChange(pasted.trim());
            }}
            onKeyDown={handleKeyDown}
            placeholder="Paste a link to inspect"
            className="w-full min-h-[48px] bg-slate-900/90 text-on-surface font-mono text-sm px-4 rounded-xl border border-slate-700/60 focus:outline-none focus:border-primary-container focus:ring-2 focus:ring-primary-container/20 transition-all placeholder:text-slate-500"
            aria-label="URL to inspect"
          />
        </div>
        <button
          id="btn-analyze"
          type="button"
          onClick={onAnalyze}
          className="min-h-[48px] px-6 rounded-xl bg-primary-container text-on-primary-container font-extrabold text-sm uppercase tracking-wider shadow-[0_0_18px_rgba(0,229,255,0.25)] hover:shadow-[0_0_24px_rgba(0,229,255,0.4)] active:scale-[0.98] transition-all flex items-center justify-center gap-2 shrink-0 cursor-pointer focus:outline-none focus:ring-2 focus:ring-cyan-300"
        >
          <SearchIcon className="w-4 h-4" />
          ANALYZE
        </button>
      </div>

      {/* QR Image Upload Area */}
      <div
        onClick={() => !isQrLoading && fileInputRef.current?.click()}
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
        role="button"
        tabIndex={0}
        aria-busy={isQrLoading}
        onKeyDown={(e) => {
          if (!isQrLoading && (e.key === 'Enter' || e.key === ' ')) {
            e.preventDefault();
            fileInputRef.current?.click();
          }
        }}
        aria-label="Upload a QR image"
        className={`group border-2 border-dashed rounded-xl p-4 transition-all flex items-center gap-4 text-left min-h-[72px] focus:outline-none focus:ring-2 focus:ring-primary-container/40 ${
          isQrLoading
            ? 'border-cyan-500/60 bg-cyan-950/20 cursor-wait'
            : isDragging
            ? 'border-primary-container bg-slate-900/90 cursor-pointer'
            : 'border-slate-700 hover:border-primary-container/70 bg-slate-950/40 hover:bg-slate-900/60 cursor-pointer'
        }`}
      >
        <input
          ref={fileInputRef}
          type="file"
          accept=".png,.jpg,.jpeg,.webp,image/png,image/jpeg,image/webp"
          onChange={handleFileChange}
          disabled={isQrLoading}
          className="hidden"
          aria-hidden="true"
        />
        <div className="w-11 h-11 rounded-lg bg-surface-container flex items-center justify-center text-primary-container group-hover:scale-105 transition-transform shrink-0 border border-slate-700/50">
          {isQrLoading ? (
            <SpinnerIcon className="w-6 h-6 text-cyan-400" />
          ) : (
            <QrIcon className="w-6 h-6" />
          )}
        </div>
        <div className="flex flex-col min-w-0">
          <span className="text-sm font-bold text-on-surface group-hover:text-primary transition-colors flex items-center gap-2">
            {isQrLoading ? (
              <span className="text-cyan-300 font-mono">Decoding QR code...</span>
            ) : (
              'Upload a QR image'
            )}
          </span>
          <span className="text-xs text-on-surface-variant truncate">
            {isQrLoading
              ? 'Analyzing off-screen canvas matrix locally'
              : 'Drag & drop or browse .png, .jpg, .webp for client-side decode'}
          </span>
        </div>
      </div>

      {/* Privacy note with lock icon */}
      <div className="flex items-center gap-2.5 px-3.5 py-3 rounded-lg bg-slate-900/60 border border-slate-800 text-slate-300 text-sm">
        <LockIcon className="w-4 h-4 text-emerald-400 shrink-0" />
        <span>Your link is analyzed on this device and is never opened.</span>
      </div>

      {/* Example Chips */}
      <ExampleChips onSelectSample={onSelectSample} />

      {/* Authority Helper Note */}
      <div className="p-3.5 rounded-xl bg-slate-900/40 border border-slate-800 text-slate-300 text-sm flex items-start gap-2.5">
        <InfoIcon className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
        <p className="leading-relaxed">
          The real host is whatever comes after the last <span className="font-mono text-cyan-300 font-bold">@</span> in the link&apos;s authority. Link Sentinel highlights it for you.
        </p>
      </div>
    </div>
  );
}
