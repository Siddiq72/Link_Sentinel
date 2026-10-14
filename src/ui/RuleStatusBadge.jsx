import React, { useState, useEffect } from 'react';
import { getRuleMetadata, syncRulesOnline } from '../engine/sync/ruleManager';

/**
 * Compact tactical rule status badge with manual sync trigger
 * and local offline status indicator.
 */
export default function RuleStatusBadge() {
  const [metadata, setMetadata] = useState(() => getRuleMetadata());
  const [isOnline, setIsOnline] = useState(() =>
    typeof navigator !== 'undefined' && 'onLine' in navigator ? navigator.onLine : true
  );
  const [isSyncing, setIsSyncing] = useState(false);
  const [notice, setNotice] = useState('');

  useEffect(() => {
    const handleUpdate = () => {
      setMetadata(getRuleMetadata());
    };

    const handleOnline = () => setIsOnline(true);
    const handleOffline = () => setIsOnline(false);

    if (typeof window !== 'undefined') {
      window.addEventListener('link-sentinel-rules-updated', handleUpdate);
      window.addEventListener('online', handleOnline);
      window.addEventListener('offline', handleOffline);
    }

    return () => {
      if (typeof window !== 'undefined') {
        window.removeEventListener('link-sentinel-rules-updated', handleUpdate);
        window.removeEventListener('online', handleOnline);
        window.removeEventListener('offline', handleOffline);
      }
    };
  }, []);

  const handleSync = async () => {
    if (isSyncing) return;
    setIsSyncing(true);
    setNotice('');

    try {
      const res = await syncRulesOnline();
      if (res.status === 'updated') {
        setMetadata(getRuleMetadata());
        setNotice('Rules up to date // Stored locally on-device');
      } else if (res.status === 'offline') {
        setNotice('Offline // Using cached rules');
      } else {
        setNotice('Rules up to date // Stored locally on-device');
      }
    } catch {
      setNotice('Sync failed // Using local fallback');
    } finally {
      setIsSyncing(false);
      setTimeout(() => {
        setNotice('');
      }, 3500);
    }
  };

  return (
    <div className="relative inline-flex items-center">
      <div className="flex items-center gap-1.5 sm:gap-2 px-2.5 py-1 rounded-lg bg-slate-900/80 border border-slate-700/60 hover:border-cyan-500/40 text-xs font-mono transition-all shadow-sm">
        {/* Pulsing indicator dot */}
        <span
          className={`w-1.5 h-1.5 rounded-full shrink-0 ${
            isOnline
              ? 'bg-cyan-400 shadow-[0_0_8px_rgba(6,182,212,0.8)]'
              : 'bg-amber-400 shadow-[0_0_8px_rgba(251,191,36,0.6)]'
          }`}
          aria-hidden="true"
        />

        {/* Tactical Rule Version Tag */}
        <div className="flex items-center gap-1 min-w-0">
          <span className="text-slate-400 font-bold hidden sm:inline">RULES:</span>
          <span className="text-cyan-300 font-bold">v{metadata.version}</span>
          <span className="text-[10px] text-slate-400 tracking-wider hidden md:inline">
            (OFFLINE READY)
          </span>
        </div>

        {/* Check Updates button when online */}
        {isOnline && (
          <button
            type="button"
            onClick={handleSync}
            disabled={isSyncing}
            className="ml-1 px-1.5 py-0.5 rounded bg-cyan-950/60 hover:bg-cyan-900/80 border border-cyan-500/40 hover:border-cyan-400 text-cyan-300 text-[10px] font-bold tracking-tight transition-all cursor-pointer disabled:opacity-50 disabled:cursor-wait focus:outline-none focus:ring-1 focus:ring-cyan-400 shrink-0"
            aria-label="Check for threat rule updates"
            title="Check online static threat manifest for updates"
          >
            {isSyncing ? 'Syncing...' : 'Check Updates'}
          </button>
        )}
      </div>

      {/* Floating Tactical Micro-copy Toast */}
      {notice && (
        <div
          role="status"
          aria-live="polite"
          className="absolute top-full right-0 mt-2 z-50 px-2.5 py-1 rounded-md bg-[#0a1829] border border-cyan-500/60 text-[10px] text-cyan-200 font-mono font-semibold shadow-[0_4px_16px_rgba(0,0,0,0.6)] whitespace-nowrap animate-fade-in flex items-center gap-1.5 backdrop-blur-md"
        >
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-ping shrink-0" />
          <span>{notice}</span>
        </div>
      )}
    </div>
  );
}
