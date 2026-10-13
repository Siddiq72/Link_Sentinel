import React, { useState } from 'react';

/**
 * Renders structured breakdown of Wi-Fi MECARD barcode payloads (WIFI:...).
 * Provides SSID display, security protocol classification, and masked password with Show/Hide toggle.
 *
 * @param {object} props
 * @param {object} props.data - Extracted Wi-Fi configuration { ssid, security, password, hidden }
 * @param {string[]} props.anomalies - Fired anomaly tags
 */
export default function WifiPayloadCard({ data = {}, anomalies = [] }) {
  const { ssid = '', security = 'nopass', password = '', hidden = false } = data;
  const [showPassword, setShowPassword] = useState(false);
  const [copied, setCopied] = useState(false);

  const isOpenNetwork =
    !security || security.toLowerCase() === 'nopass' || security.toLowerCase() === 'none';

  const handleCopyPassword = async () => {
    if (!password) return;
    try {
      await navigator.clipboard.writeText(password);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // Fallback
    }
  };

  const getSecurityBadge = () => {
    if (isOpenNetwork) {
      return (
        <span className="px-2.5 py-1 rounded text-xs font-mono font-bold uppercase bg-amber-950 border border-amber-500/50 text-amber-300">
          Unencrypted (Open)
        </span>
      );
    }
    return (
      <span className="px-2.5 py-1 rounded text-xs font-mono font-bold uppercase bg-emerald-950 border border-emerald-500/40 text-emerald-300">
        {security.toUpperCase()} Secured
      </span>
    );
  };

  return (
    <div
      className="bg-[#0c1729] border border-cyan-500/20 shadow-2xl rounded-2xl p-5 sm:p-6 flex flex-col gap-5 backdrop-blur-xl"
      data-testid="wifi-payload-card"
    >
      {/* Header */}
      <div className="flex items-center justify-between border-b border-slate-800 pb-3">
        <div className="flex items-center gap-2">
          <svg
            className="w-4 h-4 text-cyan-400 shrink-0"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
            aria-hidden="true"
          >
            <path d="M5 12.55a11 11 0 0 1 14.08 0" />
            <path d="M1.42 9a16 16 0 0 1 21.16 0" />
            <path d="M8.53 16.11a6 6 0 0 1 6.95 0" />
            <line x1="12" y1="20" x2="12.01" y2="20" />
          </svg>
          <span className="text-xs uppercase font-mono tracking-wider font-bold text-cyan-300">
            Wi-Fi Network Configuration Breakdown
          </span>
        </div>
        <span className="text-xs font-mono text-slate-400">MECARD Format</span>
      </div>

      {/* Network Name (SSID) Callout */}
      <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 flex flex-col gap-2">
        <div className="flex items-center justify-between gap-2">
          <span className="text-xs text-slate-400 font-medium">Network Name (SSID):</span>
          {hidden && (
            <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase bg-purple-950 border border-purple-500/40 text-purple-300">
              Hidden Network
            </span>
          )}
        </div>
        <div className="bg-slate-900/90 px-3.5 py-2.5 rounded-lg border border-slate-700/60 flex items-center justify-between">
          <span className="font-mono text-base sm:text-lg text-emerald-300 font-bold select-all break-all">
            {ssid || '<Blank Network Name>'}
          </span>
        </div>
      </div>

      {/* Security Protocol & Password Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 font-sans">
        {/* Security Protocol */}
        <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 flex flex-col justify-between gap-2">
          <span className="text-xs text-slate-400 font-medium">Security Protocol:</span>
          <div>{getSecurityBadge()}</div>
        </div>

        {/* Network Visibility */}
        <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 flex flex-col justify-between gap-2">
          <span className="text-xs text-slate-400 font-medium">Broadcast Status:</span>
          <span className="text-xs font-mono font-semibold text-slate-200">
            {hidden ? 'Hidden SSID (Non-broadcast)' : 'Standard Public Broadcast'}
          </span>
        </div>
      </div>

      {/* Password Field */}
      <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 flex flex-col gap-2">
        <div className="flex items-center justify-between gap-2">
          <span className="text-xs text-slate-400 font-medium">Network Password / Pre-Shared Key:</span>
          {password && (
            <span className="text-[10px] font-mono text-slate-500">
              {password.length} characters
            </span>
          )}
        </div>

        <div className="bg-slate-900/90 px-3 py-2 rounded-lg border border-slate-700/60 flex items-center justify-between gap-2 min-w-0">
          <span className="font-mono text-sm sm:text-base text-slate-200 select-all break-all tracking-wider min-w-0">
            {isOpenNetwork
              ? '(No password required - Open Wi-Fi)'
              : showPassword
              ? password
              : '•'.repeat(Math.min(password.length || 8, 16))}
          </span>

          {!isOpenNetwork && password && (
            <div className="flex items-center gap-1.5 shrink-0">
              <button
                type="button"
                onClick={() => setShowPassword(!showPassword)}
                className="min-h-[44px] px-3 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-mono font-semibold border border-slate-600/50 cursor-pointer transition-colors focus:outline-none focus:ring-2 focus:ring-cyan-500/40"
                aria-label={showPassword ? 'Hide password' : 'Show password'}
              >
                {showPassword ? 'Hide' : 'Show'}
              </button>
              <button
                type="button"
                onClick={handleCopyPassword}
                className="min-h-[44px] px-3 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-mono font-semibold border border-slate-600/50 cursor-pointer transition-colors focus:outline-none focus:ring-2 focus:ring-cyan-500/40"
                aria-label="Copy password to clipboard"
              >
                {copied ? 'Copied!' : 'Copy'}
              </button>
            </div>
          )}
        </div>
      </div>

      {/* Security Advisory */}
      <div className="p-3 rounded-xl bg-slate-950/60 border border-slate-800/80 flex items-start gap-2.5 text-xs text-slate-400">
        <svg
          className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth="2"
          strokeLinecap="round"
          strokeLinejoin="round"
          aria-hidden="true"
        >
          <circle cx="12" cy="12" r="10" />
          <line x1="12" y1="12" x2="12" y2="16" />
          <line x1="12" y1="8" x2="12.01" y2="8" />
        </svg>
        <span className="leading-relaxed">
          {isOpenNetwork
            ? 'Open Wi-Fi warning: Connecting to unencrypted Wi-Fi allows other devices on the same radio frequency to intercept unencrypted transmissions.'
            : 'Always confirm that the SSID matches official university campus access points before connecting your device.'}
        </span>
      </div>
    </div>
  );
}
