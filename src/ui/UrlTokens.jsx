import React from 'react';
import { AnatomyIcon } from './icons';

const isIpv4 = (h) => {
  if (!h || typeof h !== 'string') return false;
  const parts = h.split('.');
  if (parts.length !== 4) return false;
  return parts.every((p) => /^\d+$/.test(p) && Number(p) >= 0 && Number(p) <= 255);
};

const isIpv6 = (h) => {
  if (!h || typeof h !== 'string') return false;
  if (h.startsWith('[') && h.endsWith(']')) return true;
  return h.includes(':') && /^[0-9a-fA-F:]+$/.test(h);
};

const isPrivateIp = (ip) => {
  if (!isIpv4(ip)) return ip === '[::1]' || ip === '::1';
  const [a, b] = ip.split('.').map(Number);
  if (a === 10) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 127) return true;
  if (a === 169 && b === 254) return true;
  return false;
};

export default function UrlTokens({ parts, anomalies = [], verdict }) {
  if (!parts) return null;

  const {
    protocol = '',
    userinfo = '',
    host = '',
    registrableDomain = '',
    port = '',
    path = '',
    query = ''
  } = parts;

  const isPrivateIpHost = anomalies.includes('private_ip_host') || isPrivateIp(host);
  const isPublicIpHost =
    (anomalies.includes('raw_ip_host') && !isPrivateIpHost) ||
    ((isIpv4(host) || isIpv6(host)) && !isPrivateIpHost);
  const isIpHost = isPrivateIpHost || isPublicIpHost;

  const isDecoyUserinfo = Boolean(userinfo) && (anomalies.includes('userinfo_decoy') || verdict === 'suspicious');
  const hasLookalike = anomalies.includes('homoglyph_cyrillic') || /[\u0400-\u04FF]/.test(host);
  const isShortener = anomalies.includes('url_shortener');

  // Render host characters with non-ASCII lookalike characters highlighted in red
  const renderHostText = (hostStr) => {
    if (!hostStr) return null;

    // Check if any character is non-ASCII
    const hasNonAscii = [...hostStr].some((char) => char.charCodeAt(0) > 127);
    if (!hasNonAscii) {
      return <span>{hostStr}</span>;
    }

    return (
      <span>
        {[...hostStr].map((char, index) => {
          if (char.charCodeAt(0) > 127) {
            return (
              <span
                key={index}
                className="text-red-400 bg-red-900/90 px-1 rounded inline-block animate-pulse"
                title={`Non-ASCII glyph: U+${char.charCodeAt(0).toString(16).toUpperCase().padStart(4, '0')}`}
              >
                {char}
              </span>
            );
          }
          return <span key={index} className="text-slate-200">{char}</span>;
        })}
      </span>
    );
  };

  // Host styling depending on verdict/anomalies
  let hostContainerClass = 'bg-slate-900 border border-slate-700 text-slate-300';
  let hostTagLabel = 'Host';
  let hostTagClass = 'text-slate-400';

  if (isPrivateIpHost) {
    hostContainerClass = 'bg-amber-950/70 border border-amber-400 text-amber-200 text-sm font-bold';
    hostTagLabel = 'PRIVATE IP HOST';
    hostTagClass = 'text-amber-400';
  } else if (isPublicIpHost) {
    hostContainerClass = 'bg-red-950/80 border-2 border-red-500 text-sm font-bold shadow-[0_0_16px_rgba(239,68,68,0.3)]';
    hostTagLabel = 'PUBLIC IP HOST';
    hostTagClass = 'text-red-400';
  } else if (hasLookalike) {
    hostContainerClass = 'bg-red-950/80 border-2 border-red-500 text-sm font-bold shadow-[0_0_16px_rgba(239,68,68,0.3)]';
    hostTagLabel = "CYRILLIC 'с' (U+0441)";
    hostTagClass = 'text-red-400';
  } else if (isShortener) {
    hostContainerClass = 'bg-amber-950/70 border border-amber-400 text-amber-200 text-sm font-bold';
    hostTagLabel = 'Redirection Host';
    hostTagClass = 'text-amber-400';
  } else {
    // Real Host receives green glowing outline
    hostContainerClass = 'bg-emerald-950/80 border-2 border-emerald-400 text-emerald-300 text-sm font-bold shadow-[0_0_20px_rgba(52,211,153,0.4)]';
    hostTagLabel = 'REAL HOST';
    hostTagClass = 'text-emerald-400';
  }

  // Registrable domain color
  const regDomainClass = hasLookalike
    ? 'text-red-400'
    : isShortener
    ? 'text-amber-300'
    : 'text-emerald-300';

  return (
    <div className="bg-[#0c1729] border border-cyan-500/20 shadow-2xl rounded-2xl p-5 sm:p-6 flex flex-col gap-4 backdrop-blur-xl">
      <div className="flex items-center justify-between border-b border-slate-800 pb-3">
        <span className="text-xs uppercase font-mono tracking-wider font-bold text-primary flex items-center gap-2">
          <AnatomyIcon className="w-4 h-4 text-primary-container" />
          URL Anatomy Breakdown
        </span>
        <span className="text-xs font-mono text-slate-400">Analyzed Link</span>
      </div>

      {/* Monospace non-clickable tokens with responsive wrapping */}
      <div className="bg-slate-950 p-3.5 sm:p-4 rounded-xl flex flex-wrap items-end gap-x-2 gap-y-3 font-mono border border-slate-800 max-w-full">
        {/* Protocol */}
        {protocol && (
          <div className="flex flex-col items-start gap-1 shrink-0">
            <span className="px-2.5 py-1.5 rounded-lg bg-slate-900 text-slate-300 text-xs sm:text-sm select-all">
              {protocol}
            </span>
            <span className="text-[10px] uppercase font-bold text-slate-500 px-1">
              Protocol
            </span>
          </div>
        )}

        {/* Userinfo token */}
        {userinfo && (
          <div className="flex flex-col items-start gap-1 max-w-full">
            <span
              className={`px-2.5 py-1.5 rounded-lg text-xs sm:text-sm font-bold select-all max-w-full break-all ${
                isDecoyUserinfo
                  ? 'bg-red-950/80 border-2 border-red-500 text-red-300 shadow-[0_0_14px_rgba(239,68,68,0.3)]'
                  : 'bg-slate-900 border border-slate-700 text-slate-300'
              }`}
            >
              {userinfo}
            </span>
            <span
              className={`text-[10px] uppercase font-bold px-1 ${
                isDecoyUserinfo ? 'text-red-400' : 'text-slate-500'
              }`}
            >
              {isDecoyUserinfo ? 'DECOY (Userinfo)' : 'Userinfo'}
            </span>
          </div>
        )}

        {/* Host token */}
        {host && (
          <div className="flex flex-col items-start gap-1 max-w-full">
            <span className={`px-2.5 sm:px-3 py-1.5 rounded-lg select-all max-w-full break-all ${hostContainerClass}`}>
              {renderHostText(host)}
            </span>
            <span className={`text-[10px] uppercase font-bold px-1 ${hostTagClass}`}>
              {hostTagLabel}
            </span>
          </div>
        )}

        {/* Port token */}
        {port && (
          <div className="flex flex-col items-start gap-1 shrink-0">
            <span className="px-2 py-1.5 rounded-lg bg-cyan-950/80 border border-cyan-500/60 text-cyan-300 text-xs sm:text-sm font-bold select-all">
              {port}
            </span>
            <span className="text-[10px] uppercase font-bold text-cyan-400 px-1">
              Port
            </span>
          </div>
        )}

        {/* Path token */}
        {path && (
          <div className="flex flex-col items-start gap-1 max-w-full">
            <span className="px-2.5 py-1.5 rounded-lg bg-slate-900 text-slate-300 text-xs sm:text-sm select-all max-w-full break-all">
              {path}
            </span>
            <span className="text-[10px] uppercase font-bold text-slate-500 px-1">
              Path
            </span>
          </div>
        )}

        {/* Query token */}
        {query && (
          <div className="flex flex-col items-start gap-1 max-w-full">
            <span className="px-2.5 py-1.5 rounded-lg bg-slate-900 border border-slate-700 text-slate-300 text-xs sm:text-sm select-all max-w-full break-all">
              {query}
            </span>
            <span className="text-[10px] uppercase font-bold text-slate-400 px-1">
              Query (?param)
            </span>
          </div>
        )}
      </div>

      {/* Registrable domain callout or Host type for IP */}
      {isIpHost ? (
        <div className="p-3.5 rounded-xl bg-slate-900/80 border border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-1.5">
          <span className="text-xs sm:text-sm text-slate-300 shrink-0">Host type:</span>
          <span className={`font-mono text-sm sm:text-base font-bold ${isPrivateIpHost ? 'text-amber-300' : 'text-red-400'} select-all break-all`}>
            {isPrivateIpHost ? 'private IP address' : 'public IP address'}
          </span>
        </div>
      ) : registrableDomain ? (
        <div className="p-3.5 rounded-xl bg-slate-900/80 border border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-1.5">
          <span className="text-xs sm:text-sm text-slate-300 shrink-0">Registrable domain:</span>
          <span className={`font-mono text-sm sm:text-base font-bold ${regDomainClass} select-all break-all`}>
            {registrableDomain}
          </span>
        </div>
      ) : null}
    </div>
  );
}
